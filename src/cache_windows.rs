//! Windows-only protected persistence for browser authorization.
use crate::Result;
use std::{ffi::c_void, fs::{self, File, OpenOptions}, io::Read, path::{Path, PathBuf}};
use std::os::windows::{fs::{OpenOptionsExt, MetadataExt}, io::AsRawHandle};
#[repr(C)] struct AceHeader { kind:u8, flags:u8, size:u16 }
#[repr(C)] struct Acl { revision:u8, reserved:u8, size:u16, count:u16, reserved2:u16 }
#[link(name="advapi32")]
unsafe extern "system" {
    fn GetSecurityInfo(handle:isize,kind:i32,information:u32,owner:*mut *mut c_void,group:*mut *mut c_void,dacl:*mut *mut c_void,sacl:*mut *mut c_void,descriptor:*mut *mut c_void)->u32;
    fn ConvertSidToStringSidW(sid:*mut c_void,out:*mut *mut u16)->i32;
    fn GetAce(acl:*const Acl,index:u32,ace:*mut *mut c_void)->i32;
    fn RegOpenKeyExW(key:isize,sub:*const u16,options:u32,access:u32,out:*mut isize)->i32;
    fn RegCreateKeyExW(key:isize,sub:*const u16,reserved:u32,class:*const u16,options:u32,access:u32,security:*const c_void,out:*mut isize,disposition:*mut u32)->i32;
    fn RegQueryValueExW(key:isize,name:*const u16,reserved:*mut u32,kind:*mut u32,data:*mut u8,len:*mut u32)->i32;
    fn RegSetValueExW(key:isize,name:*const u16,reserved:u32,kind:u32,data:*const u8,len:u32)->i32;
    fn RegCloseKey(key:isize)->i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(text:*const u16,revision:u32,out:*mut *mut c_void,size:*mut u32)->i32;
}
#[link(name="kernel32")]
unsafe extern "system" { fn LocalFree(memory:*mut c_void)->*mut c_void; fn GetTickCount64()->u64; }
struct Allocation(*mut c_void);
impl Drop for Allocation { fn drop(&mut self) { unsafe{LocalFree(self.0);} } }
fn wide(text:&str)->Vec<u16>{text.encode_utf16().chain(Some(0)).collect()}
fn privileged(sid:*const c_void,installer:bool)->Result<bool>{
    if sid.is_null(){return Err("cache SID absent".into())}
    let mut text=std::ptr::null_mut();
    if unsafe{ConvertSidToStringSidW(sid.cast_mut(),&mut text)}==0{return Err("cache SID unavailable".into())}
    let _memory=Allocation(text.cast());let mut len=0;
    while unsafe{*text.add(len)}!=0{len+=1;}
    let sid=String::from_utf16(unsafe{std::slice::from_raw_parts(text,len)})?;
    Ok(matches!(sid.as_str(),"S-1-5-18"|"S-1-5-32-544") || (installer && sid=="S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"))
}
fn verify(file:&File,private:bool,installer:bool)->Result<()>{
    if file.metadata()?.file_attributes()&0x400!=0{return Err("redirected cache path".into())}
    verify_security(file.as_raw_handle() as isize,1,private,installer)
}
fn verify_security(handle:isize,kind:i32,private:bool,installer:bool)->Result<()>{
    let(mut owner,mut dacl,mut descriptor)=(std::ptr::null_mut(),std::ptr::null_mut(),std::ptr::null_mut());
    let status=unsafe{GetSecurityInfo(handle,kind,5,&mut owner,std::ptr::null_mut(),&mut dacl,std::ptr::null_mut(),&mut descriptor)};
    let _memory=Allocation(descriptor);
    if status!=0||dacl.is_null()||!privileged(owner,installer)?{return Err("cache ownership or ACL rejected".into())}
    let acl=dacl as *const Acl;
    for index in 0..unsafe{(*acl).count} as u32{
        let mut ace=std::ptr::null_mut();
        if unsafe{GetAce(acl,index,&mut ace)}==0{return Err("cache ACL unavailable".into())}
        let header=unsafe{&*(ace as *const AceHeader)};
        if header.kind==1||header.flags&8!=0{continue}
        if header.kind!=0||header.size<12{return Err("unsupported cache ACL".into())}
        let mask=unsafe{*((ace as *const u8).add(4) as *const u32)};
        let dangerous=if private {0xffff_ffff} else {0x10000000|0x40000000|0x000d0156};
        if mask&dangerous!=0&&!privileged(unsafe{(ace as *const u8).add(8).cast()},installer)?{return Err("cache ACL permits untrusted access".into())}
    }
    Ok(())
}
pub struct Directory { path:PathBuf, _handle:File, private:bool, installer:bool }
fn legacy_snapshot(name:&str)->bool {
    name.strip_prefix("state.").and_then(|n|n.strip_suffix(".tmp"))
        .is_some_and(|id|uuid::Uuid::parse_str(id).is_ok_and(|value|value.to_string()==id))
}
impl Directory {
    pub fn open(path:&Path,private:bool)->Result<Self>{Self::open_mode(path,private,false)}
    /// Only fixed installed browser/runtime/MSI paths may trust Windows servicing.
    /// Authorization keys and journals deliberately never use this exception.
    pub fn installed(path:&Path)->Result<Self>{Self::open_mode(path,false,true)}
    fn open_mode(path:&Path,private:bool,installer:bool)->Result<Self>{
        for part in path.ancestors(){let metadata=fs::symlink_metadata(part)?;if metadata.file_attributes()&0x400!=0{return Err("redirected cache ancestor".into())}}
        let handle=OpenOptions::new().access_mode(0x20080).share_mode(1)
            .custom_flags(0x02000000|0x00200000).open(path)?;
        verify(&handle,private,installer)?;
        Ok(Self{path:path.to_path_buf(),_handle:handle,private,installer})
    }
    pub fn hold_file(&self,name:&std::ffi::OsStr)->Result<File>{
        if Path::new(name).components().count()!=1{return Err("invalid protected leaf".into())}
        let file=OpenOptions::new().access_mode(0x80020000).share_mode(1).custom_flags(0x00200000).open(self.path.join(name))?;
        verify(&file,self.private,self.installer)?;if !file.metadata()?.is_file(){return Err("protected leaf is not a file".into())}Ok(file)
    }
    pub fn contains(&self,name:&str)->Result<bool>{Ok(self.path.join(name).try_exists()?)}
    pub fn read(&self,name:&str,limit:u64)->Result<Vec<u8>>{
        if !matches!(name,"anchor.json"|"state.bin"|"pending.bin"|"custody.json"|"release.json")&&!legacy_snapshot(name){return Err("invalid cache file".into())}
        let file=OpenOptions::new().access_mode(0x80020000).share_mode(1).custom_flags(0x00200000).open(self.path.join(name))?;
        verify(&file,self.private,self.installer)?;
        if !file.metadata()?.is_file()||file.metadata()?.len()>limit{return Err("cache file exceeds limit".into())}
        let mut bytes=Vec::new();file.take(limit+1).read_to_end(&mut bytes)?;
        if bytes.len() as u64>limit{return Err("cache file exceeds limit".into())}Ok(bytes)
    }
    pub fn write(&self,name:&str,bytes:&[u8])->Result<()>{
        if !matches!(name,"anchor.json"|"state.bin"|"pending.bin"|"custody.json"|"release.json"){return Err("invalid cache file".into())}
        let path=self.path.join(name);
        if path.exists(){self.read(name,12*1024*1024)?;}
        crate::atomic_private(&path,bytes)?;
        if self.read(name,12*1024*1024)?!=bytes{return Err("cache durable readback failed".into())}Ok(())
    }
    pub(crate) fn legacy_snapshots(&self)->Result<Vec<String>>{
        if !self.private{return Err("cache recovery requires private directory".into())}
        let mut names=Vec::new();
        for entry in fs::read_dir(&self.path)? {
            let entry=entry?;let name=entry.file_name();
            if let Some(name)=name.to_str().filter(|name|legacy_snapshot(name)) {
                if names.len()>=64{return Err("too many cache recovery candidates".into())}
                names.push(name.to_owned());
            }
        }
        names.sort();Ok(names)
    }
    /// Interoperates with the MSI FileStream byte-zero lock. A transaction sets
    /// its marker before snapshots and removes it only after restoration becomes
    /// impossible; custody cannot move into a rollbackable agent state meanwhile.
    pub fn delivery_guard(&self,edition:&str)->Result<File>{
        if !self.private{return Err("delivery guard requires private directory".into())}
        let guard=OpenOptions::new().read(true).write(true).create(true).truncate(false).share_mode(3)
            .custom_flags(0x00200000).open(self.path.join("custody.lock"))?;
        verify(&guard,true,false)?;fs2::FileExt::try_lock_exclusive(&guard)?;
        if self.path.join("custody.json").try_exists()? {
            let marker:serde_json::Value=serde_json::from_slice(&self.read("custody.json",4096)?)?;
            if marker["edition"]!=edition||marker["active"]!=true{return Err("delivery barrier invalid".into())}
            return Err("MSI state may still be restored".into());
        }
        Ok(guard)
    }
    pub fn lock(&self)->Result<File>{
        let file=OpenOptions::new().read(true).write(true).create(true).truncate(false).custom_flags(0x00200000).open(self.path.join("authority.lock"))?;
        verify(&file,true,false)?;fs2::FileExt::try_lock_exclusive(&file)?;Ok(file)
    }
}
pub fn root(edition:&str)->Result<PathBuf>{
    if !matches!(edition,"community"|"commercial"){return Err("invalid cache edition".into())}
    // SCM receives its environment from the machine, not a browser request.
    Ok(PathBuf::from(std::env::var_os("ProgramData").ok_or("machine data root absent")?).join("MilvagoAuthorization").join(edition))
}
pub fn tick()->u64{unsafe{GetTickCount64()}}
struct Registry(isize);
impl Drop for Registry{fn drop(&mut self){unsafe{RegCloseKey(self.0);}}}
fn registry(edition:&str)->Result<Registry>{
    if !matches!(edition,"community"|"commercial"){return Err("invalid cache edition".into())}
    let path=wide(&format!("SOFTWARE\\MilvagoAuthorization\\{edition}"));let mut handle=0;
    let code=unsafe{RegOpenKeyExW(0x80000002u32 as i32 as isize,path.as_ptr(),0,0x20019|0x20006|0x100,&mut handle)};
    if code!=0{return Err("cache registry provisioning unavailable".into())}
    let key=Registry(handle);verify_security(handle,4,true,false)?;Ok(key)
}
/// Persistent initialization marker prevents a repair from recreating deleted
/// authority files. This registry tree is outside MSI snapshot/restore scope.
pub fn initialized(edition:&str,set:bool)->Result<bool>{
    let root=registry(edition)?;let name=wide("Initialized");let(mut len,mut kind,mut value)=(4u32,0u32,0u32);
    let code=unsafe{RegQueryValueExW(root.0,name.as_ptr(),std::ptr::null_mut(),&mut kind,(&mut value as *mut u32).cast(),&mut len)};
    if code==0{return if kind==4&&len==4&&value==1{Ok(true)}else{Err("cache initialization marker corrupt".into())}}
    if code!=2{return Err("cache initialization marker unavailable".into())}
    if set {let value=1u32;if unsafe{RegSetValueExW(root.0,name.as_ptr(),0,4,(&value as *const u32).cast(),4)}!=0{return Err("cache initialization marker write failed".into())}}
    Ok(false)
}
#[repr(C)]struct SecurityAttributes{length:u32,descriptor:*mut c_void,inherit:i32}
pub fn boot(edition:&str,create:bool)->Result<String>{
    let root=registry(edition)?;let name=wide("Boot");let mut handle=0;
    let code=unsafe{RegOpenKeyExW(root.0,name.as_ptr(),0,0x20019,&mut handle)};
    let mut created=false;
    if code==2&&create{
        let mut descriptor=std::ptr::null_mut();let acl=wide("D:P(A;;KA;;;SY)(A;;KA;;;BA)");
        if unsafe{ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.as_ptr(),1,&mut descriptor,std::ptr::null_mut())}==0{return Err("boot ACL unavailable".into())}
        let _memory=Allocation(descriptor);let sa=SecurityAttributes{length:std::mem::size_of::<SecurityAttributes>() as u32,descriptor,inherit:0};let mut disposition=0;
        let code=unsafe{RegCreateKeyExW(root.0,name.as_ptr(),0,std::ptr::null(),1,0x20019|0x20006,(&sa as *const SecurityAttributes).cast(),&mut handle,&mut disposition)};
        if code!=0||disposition!=1{return Err("boot marker creation refused".into())}created=true;
    }else if code!=0{return Err("boot authorization absent".into())}
    let key=Registry(handle);verify_security(handle,4,true,false)?;let name=wide("Identity");
    if created{let text=wide(&uuid::Uuid::new_v4().to_string());if unsafe{RegSetValueExW(key.0,name.as_ptr(),0,1,text.as_ptr().cast(),(text.len()*2) as u32)}!=0{return Err("boot marker write failed".into())}}
    let(mut kind,mut len)=(0u32,74u32);let mut value=[0u16;37];
    if unsafe{RegQueryValueExW(key.0,name.as_ptr(),std::ptr::null_mut(),&mut kind,value.as_mut_ptr().cast(),&mut len)}!=0||kind!=1||len!=74||value[36]!=0{return Err("boot marker corrupt".into())}
    let id=String::from_utf16(&value[..36])?;uuid::Uuid::parse_str(&id)?;Ok(id)
}

#[derive(serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Epoch {
    installation:String,generation:u64,cache_hash:String,policy_revision:u64,catalog_revision:u64,
    boot:String,deadline:Option<u64>,armed:bool,last_tick:u64,queue_hash:String,
}
#[link(name="advapi32")]
unsafe extern "system" { fn RegFlushKey(key:isize)->i32; }
pub fn save_epoch(journal:&crate::browser_cache::Journal,queue_hash:String)->Result<()> {
    let epoch=Epoch{installation:journal.pin.installation.clone(),generation:journal.generation,cache_hash:journal.cache_hash.clone(),
        policy_revision:journal.policy_revision,catalog_revision:journal.catalog_revision,boot:journal.boot.clone(),deadline:journal.deadline,
        armed:journal.armed,last_tick:journal.last_tick,queue_hash};
    let bytes=serde_json::to_vec(&epoch)?;if bytes.len()>2048{return Err("authorization journal exceeds limit".into())}
    let root=registry(&journal.pin.edition)?;let name=wide("Epoch");
    if unsafe{RegSetValueExW(root.0,name.as_ptr(),0,3,bytes.as_ptr(),bytes.len() as u32)}!=0
        ||unsafe{RegFlushKey(root.0)}!=0{return Err("authorization journal persistence failed".into())}Ok(())
}
pub(crate) fn read_epoch(edition:&str)->Result<Epoch> {
    let root=registry(edition)?;let name=wide("Epoch");let mut bytes=vec![0u8;2048];let(mut kind,mut len)=(0,2048);
    if unsafe{RegQueryValueExW(root.0,name.as_ptr(),std::ptr::null_mut(),&mut kind,bytes.as_mut_ptr(),&mut len)}!=0
        ||kind!=3||len>2048{return Err("authorization journal missing or corrupt".into())}
    Ok(serde_json::from_slice(&bytes[..len as usize])?)
}
impl Epoch {
    pub(crate) fn apply(&self,journal:&mut crate::browser_cache::Journal,queue_hash:&str)->Result<()> {
    let epoch=self;
    if epoch.queue_hash!=queue_hash||epoch.installation!=journal.pin.installation||epoch.generation!=journal.generation||epoch.cache_hash!=journal.cache_hash
        ||epoch.policy_revision!=journal.policy_revision||epoch.catalog_revision!=journal.catalog_revision {
        return Err("cache no longer matches authorization journal".into());
    }
    journal.boot=epoch.boot.clone();journal.deadline=epoch.deadline;journal.armed=epoch.armed;journal.last_tick=epoch.last_tick;Ok(())
    }
}

#[cfg(test)]
mod recovery_path_tests {
    use super::legacy_snapshot;
    #[test]
    fn only_exact_legacy_snapshot_leaves_are_candidates() {
        let id=uuid::Uuid::new_v4().to_string();
        assert!(legacy_snapshot(&format!("state.{id}.tmp")));
        for name in [format!("../state.{id}.tmp"),format!("state.{id}.tmp/child"),
            format!("state.{id}.tmp:stream"),format!("state.{id}.tmp.bak"),
            format!("pending.{id}.tmp"),format!("state.{}.tmp",id.to_uppercase()),
            "state.invalid.tmp".into(),"state.bin".into()] {
            assert!(!legacy_snapshot(&name));
        }
    }
}
