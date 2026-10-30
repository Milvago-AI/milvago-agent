#!/usr/bin/env python3
"""Install the fixed system collector; never adopt a bridge-writable identity."""
import argparse,hashlib,json,os,pwd,secrets,stat,subprocess,sys
from pathlib import Path

UNITS=('milvago-discovery.service','milvago-discovery-enroll.service','milvago-discovery-enroll.timer')

def directory(path,mode=None):
 path=Path(path)
 if not path.is_absolute():raise ValueError('absolute installation directory required')
 if mode is not None and mode not in (0o700,0o755):raise ValueError('invalid installation directory mode')
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 try:
  for index,name in enumerate(path.parts[1:]):
   if name in ('','.','..'):raise ValueError('invalid installation directory')
   leaf=index==len(path.parts)-2
   created=False
   try:nextfd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
   except FileNotFoundError:
    if mode is None:raise
    os.mkdir(name,mode if leaf else 0o755,dir_fd=fd)
    created=True
    nextfd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
   os.close(fd);fd=nextfd
   info=os.fstat(fd)
   if info.st_uid!=0 or info.st_mode&0o022:raise ValueError('installation directory is not protected')
   # A restrictive caller umask must not break a newly created service path.
   # Existing administrator-owned permissions remain an explicit contract.
   if created:os.fchmod(fd,mode if leaf else 0o755)
  if mode is not None and stat.S_IMODE(os.fstat(fd).st_mode)!=mode:raise ValueError('unexpected installation directory mode')
  return fd
 except BaseException:os.close(fd);raise

def read(path,limit,private=False):
 parent=directory(path.parent)
 try:fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
 finally:os.close(parent)
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o022 or info.st_size>limit:raise ValueError('unsafe installation file')
  if private and info.st_mode&0o077:raise ValueError('installation file must be private')
  chunks=[];length=0
  while length<=limit:
   block=os.read(fd,min(65536,limit+1-length))
   if not block:break
   chunks.append(block);length+=len(block)
  result=b''.join(chunks)
  after=os.fstat(fd)
  if len(result)!=info.st_size or after.st_mtime_ns!=info.st_mtime_ns or after.st_size!=info.st_size or after.st_nlink!=1:raise ValueError('installation file changed')
  return result
 finally:os.close(fd)

def publish(path,data,mode=0o600):
 parent=directory(path.parent)
 name='discovery-'+secrets.token_hex(12)+'.new'
 try:
  fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode,dir_fd=parent)
  with os.fdopen(fd,'wb') as output:
   output.write(data);output.flush()
   # Publish the requested permissions independently of the caller's umask.
   os.fchmod(output.fileno(),mode);os.fsync(output.fileno())
  os.replace(name,path.name,src_dir_fd=parent,dst_dir_fd=parent);os.fsync(parent)
 finally:
  try:os.unlink(name,dir_fd=parent)
  except FileNotFoundError:pass
  os.close(parent)

def install(payload,provision,edition,uid,gid,portable=False,root=Path('/'),control=None):
 if os.geteuid()!=0 or edition not in ('community','commercial') or type(uid)is not int or type(gid)is not int or not 0<uid<2**32-1 or not 0<gid<2**32-1:raise ValueError('dedicated service account required')
 profile=read(provision,16384)
 value=json.loads(profile)
 config=root/'etc/milvago-discovery';state=root/'var/lib/milvago-discovery';target=root/'opt/milvago-discovery'
 generic=value=={}
 if generic:
  try:profile=read(config/'provision.json',16384,True);value=json.loads(profile)
  except FileNotFoundError:pass
 if value!={} and (value.get('edition')!=edition or value.get('platform')!='linux' or not isinstance(value.get('bootstrap_token'),str)):raise ValueError('organization provisioning required')
 binary=read(payload/'milvago-discovery-system',128*1024*1024)
 if binary[:6]!=b'\x7fELF\x02\x01' or binary[18:20]!=b'\x3e\x00':raise ValueError('invalid discovery executable')
 texts={unit:read(payload/unit,16384) for unit in UNITS}
 notices={name:read(payload/'licenses/discovery'/name,65536) for name in ('LICENSE','NOTICE-ENGINE','NOTICE-SOURCES')}
 if any(b'\r' in text for text in texts.values()):raise ValueError('invalid Linux unit line endings')
 for path,mode in [(config,0o700),(state,0o700),(target,0o755)]:os.close(directory(path,mode))
 installation=config/'installation.json'
 previous=None
 try:previous=json.loads(read(installation,4096,True))
 except FileNotFoundError:pass
 if previous is not None:
  old=json.loads(read(config/'provision.json',16384,True))
  if previous.get('edition')!=edition or old.get('server_url')!=value.get('server_url') or old.get('policy_public_key')!=value.get('policy_public_key'):raise ValueError('existing collector belongs to another organization; explicit reprovisioning required')
  if type(previous.get('enroll')) is not bool:raise ValueError('invalid existing discovery installation')
 home=root/('var/lib/milvago-browser' if edition=='community' else 'var/lib/milvago-commercial')
 # A legacy endpoint keeps its identity. An administrator can bind its UUID with
 # install-anchor; a writable legacy cache is never promoted into root's anchor.
 enroll=previous['enroll'] if previous is not None else not os.path.lexists(home/'state.bin')
 document=dict(version=1,edition=edition,agent_uid=uid,agent_gid=gid,enroll=enroll,portable=portable)
 if control:control('stop','milvago-discovery.service','milvago-discovery-enroll.timer','milvago-discovery-enroll.service')
 publish(target/'milvago-discovery-system',binary,0o755)
 os.close(directory(target/'licenses/discovery',0o755))
 for name,text in notices.items():publish(target/'licenses/discovery'/name,text,0o644)
 if value!={}:
  publish(config/'provision.json',profile)
  publish(installation,(json.dumps(document)+'\n').encode())
 units=root/'etc/systemd/system';os.close(directory(units,0o755))
 for name,text in texts.items():publish(units/name,text,0o644)
 service='milvago-commercial' if edition=='commercial' else ('milvago-browser' if portable else 'milvago-community')
 if value!={}:
  drop=units/(service+'.service.d');os.close(directory(drop,0o755))
  publish(drop/'discovery.conf',b'[Unit]\nWants=milvago-discovery-enroll.service\nAfter=milvago-discovery-enroll.service\n[Service]\nEnvironment=MILVAGO_DISCOVERY_MANAGED=1\n',0o644)
 assets=[target/'milvago-discovery-system',*[target/'licenses/discovery'/name for name in notices],*[units/name for name in UNITS]]
 if value!={}:assets.append(drop/'discovery.conf')
 owner=dict(version=1,edition=edition,files={str(path.relative_to(root)):hashlib.sha256(read(path,128*1024*1024)).hexdigest() for path in assets})
 publish(config/'owned-files.json',(json.dumps(owner)+'\n').encode())
 if control:
  control('daemon-reload')
  control('enable','--now','milvago-discovery-enroll.timer')
  control('start','--no-block','milvago-discovery-enroll.service')
 return document

def remove(edition,root=Path('/'),control=None):
 if os.geteuid()!=0 or edition not in ('community','commercial'):raise ValueError('root and a known edition required')
 config=root/'etc/milvago-discovery'
 try:owner=json.loads(read(config/'owned-files.json',16384,True))
 except FileNotFoundError:return []
 if owner.get('version')!=1 or owner.get('edition')!=edition or not isinstance(owner.get('files'),dict):raise ValueError('invalid discovery ownership record')
 allowed={'opt/milvago-discovery/milvago-discovery-system',*('opt/milvago-discovery/licenses/discovery/'+name for name in ('LICENSE','NOTICE-ENGINE','NOTICE-SOURCES')),*('etc/systemd/system/'+name for name in UNITS),*('etc/systemd/system/'+name+'.service.d/discovery.conf' for name in ('milvago-community','milvago-browser','milvago-commercial'))}
 if not set(owner['files']).issubset(allowed):raise ValueError('unexpected discovery ownership path')
 if control:control('disable','--now','milvago-discovery-enroll.timer','milvago-discovery.service');control('stop','milvago-discovery-enroll.service')
 retained=[]
 for name,digest in owner['files'].items():
  path=root/name
  try:
   body=read(path,128*1024*1024)
   if hashlib.sha256(body).hexdigest()!=digest:retained.append(name);continue
   parent=directory(path.parent)
   try:os.unlink(path.name,dir_fd=parent);os.fsync(parent)
   finally:os.close(parent)
  except FileNotFoundError:pass
  except (OSError,ValueError):retained.append(name)
 if control:control('daemon-reload')
 return retained

def main():
 if len(sys.argv)==3 and sys.argv[1]=='--remove':
  def stop(*arguments):subprocess.run(['/usr/bin/systemctl',*arguments],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=25)
  retained=remove(sys.argv[2],control=stop)
  if retained:print('Milvago: modified discovery files preserved during removal.',file=sys.stderr)
  return
 parser=argparse.ArgumentParser()
 parser.add_argument('provision',type=Path);parser.add_argument('edition',choices=('community','commercial'));parser.add_argument('--portable',action='store_true')
 args=parser.parse_args();account=pwd.getpwnam('milvago-agent')
 def control(*arguments):
  result=subprocess.run(['/usr/bin/systemctl',*arguments],stdin=subprocess.DEVNULL,capture_output=True,timeout=25)
  if result.returncode and arguments[0]!='stop':raise RuntimeError('discovery service configuration failed')
 install(Path(__file__).resolve().parent,args.provision,args.edition,account.pw_uid,account.pw_gid,args.portable,control=control)
if __name__=='__main__':main()
