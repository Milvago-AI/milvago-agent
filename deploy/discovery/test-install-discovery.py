"""Fixed-path installer recipes executed only inside the isolated Linux fixture."""
import importlib.util,json,os,stat,tempfile,unittest
from pathlib import Path

spec=importlib.util.spec_from_file_location('discovery_installer',Path(__file__).with_name('install-discovery.py'))
installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)

class InstallerTests(unittest.TestCase):
 def setUp(self):
  self.case=tempfile.TemporaryDirectory(prefix='discovery-install-',dir=os.environ.get('MILVAGO_DISCOVERY_TEST_SCRATCH','/run'))
  self.base=Path(self.case.name);self.root=self.base/'root';self.root.mkdir()
  self.payload=self.base/'payload';self.payload.mkdir()
  data=bytearray(64);data[:6]=b'\x7fELF\x02\x01';data[18:20]=b'\x3e\x00'
  (self.payload/'milvago-discovery-system').write_bytes(data)
  os.chmod(self.payload/'milvago-discovery-system',0o755)
  for name in installer.UNITS:
   (self.payload/name).write_bytes(Path(__file__).with_name(name).read_bytes())
  notices=self.payload/'licenses/discovery';notices.mkdir(parents=True)
  for name in ('LICENSE','NOTICE-ENGINE','NOTICE-SOURCES'):(notices/name).write_text('Fixture license notice\n')
  self.profile=self.base/'provision.json'
  self.profile.write_text(json.dumps(dict(edition='community',platform='linux',bootstrap_token='fixture',server_url='https://server.example.test',policy_public_key='fixture-key')))
  os.chmod(self.profile,0o600)
  self.controls=[]
 def tearDown(self):self.case.cleanup()
 def install(self):
  return installer.install(self.payload,self.profile,'community',1000,1000,root=self.root,control=lambda *args:self.controls.append(args))
 def test_fresh_install_is_protected_and_bridge_keeps_empty_capabilities(self):
  document=self.install();self.assertTrue(document['enroll'])
  for name in ('installation.json','provision.json'):
   self.assertEqual(stat.S_IMODE((self.root/'etc/milvago-discovery'/name).stat().st_mode),0o600)
  drop=(self.root/'etc/systemd/system/milvago-community.service.d/discovery.conf').read_text()
  self.assertIn('MILVAGO_DISCOVERY_MANAGED=1',drop);self.assertNotIn('CapabilityBoundingSet',drop)
  self.assertIn(('enable','--now','milvago-discovery-enroll.timer'),self.controls)
  unit=(self.root/'etc/systemd/system/milvago-discovery.service').read_text()
  self.assertIn('CAP_NET_RAW',unit);self.assertNotIn('CAP_SETUID',unit)
  self.assertTrue((self.root/'opt/milvago-discovery/licenses/discovery/NOTICE-SOURCES').is_file())
 def test_existing_endpoint_is_not_silently_reenrolled_and_generic_upgrade_keeps_binding(self):
  home=self.root/'var/lib/milvago-browser';home.mkdir(parents=True)
  (home/'state.bin').write_bytes(b'legacy ciphertext')
  document=self.install();self.assertFalse(document['enroll'])
  self.profile.write_text('{}')
  self.assertFalse(self.install()['enroll'])
  self.assertEqual((home/'state.bin').read_bytes(),b'legacy ciphertext')
 def test_restrictive_umask_keeps_new_directory_contracts(self):
  previous=os.umask(0o077)
  try:self.install()
  finally:os.umask(previous)
  for name in ('opt','opt/milvago-discovery','opt/milvago-discovery/licenses','etc','etc/systemd','etc/systemd/system'):
   self.assertEqual(stat.S_IMODE((self.root/name).stat().st_mode),0o755)
  for name in ('etc/milvago-discovery','var/lib/milvago-discovery'):
   self.assertEqual(stat.S_IMODE((self.root/name).stat().st_mode),0o700)
  for name in ('opt/milvago-discovery/milvago-discovery-system',):
   self.assertEqual(stat.S_IMODE((self.root/name).stat().st_mode),0o755)
  for name in ('etc/systemd/system/milvago-discovery.service','opt/milvago-discovery/licenses/discovery/LICENSE'):
   self.assertEqual(stat.S_IMODE((self.root/name).stat().st_mode),0o644)
 def test_existing_private_directory_is_not_widened(self):
  target=self.root/'opt/milvago-discovery';target.mkdir(parents=True);os.chmod(target,0o700)
  with self.assertRaises(ValueError):self.install()
  self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o700)
  self.assertFalse(self.controls)
 def test_generic_unconfigured_payload_does_not_grant_root_enrollment(self):
  self.profile.write_text('{}');self.install()
  self.assertFalse((self.root/'etc/milvago-discovery/installation.json').exists())
  self.assertFalse((self.root/'etc/systemd/system/milvago-community.service.d/discovery.conf').exists())
 def test_atomic_publication_replaces_links_without_touching_their_target(self):
  target=self.base/'administrator-file';target.write_bytes(b'preserved')
  destination=self.base/'published';destination.symlink_to(target)
  previous=os.umask(0o077)
  try:installer.publish(destination,b'new asset',0o755)
  finally:os.umask(previous)
  self.assertFalse(destination.is_symlink())
  self.assertEqual(destination.read_bytes(),b'new asset')
  self.assertEqual(stat.S_IMODE(destination.stat().st_mode),0o755)
  self.assertEqual(target.read_bytes(),b'preserved')
  destination.unlink();os.link(target,destination)
  with self.assertRaises(ValueError):installer.read(destination,1024)
  installer.publish(destination,b'private asset')
  self.assertEqual(stat.S_IMODE(destination.stat().st_mode),0o600)
  self.assertEqual(target.read_bytes(),b'preserved')
  self.assertFalse(list(self.base.glob('discovery-*.new')))
 def test_foreign_profile_is_rejected_before_stopping_current_services(self):
  self.install();self.controls.clear()
  value=json.loads(self.profile.read_text());value['server_url']='https://other.example.test';self.profile.write_text(json.dumps(value))
  with self.assertRaises(ValueError):self.install()
  self.assertFalse(self.controls)
 def test_removal_deletes_only_owned_unchanged_assets_and_preserves_identity(self):
  self.install()
  modified=self.root/'etc/systemd/system/milvago-discovery.service';modified.write_text('administrator change\n')
  retained=installer.remove('community',root=self.root)
  self.assertIn('etc/systemd/system/milvago-discovery.service',retained)
  self.assertTrue(modified.exists())
  self.assertFalse((self.root/'opt/milvago-discovery/milvago-discovery-system').exists())
  self.assertTrue((self.root/'etc/milvago-discovery/provision.json').exists())
 def test_malicious_removal_record_cannot_select_other_paths(self):
  self.install()
  record=self.root/'etc/milvago-discovery/owned-files.json'
  value=json.loads(record.read_text());value['files']['../../outside']='bad';record.write_text(json.dumps(value))
  self.controls.clear()
  with self.assertRaises(ValueError):installer.remove('community',root=self.root,control=lambda *args:self.controls.append(args))
  self.assertFalse(self.controls)
 def test_links_writable_directories_and_invalid_binary_are_rejected(self):
  target=self.base/'elsewhere';target.write_text('unchanged')
  self.profile.unlink();self.profile.symlink_to(target)
  with self.assertRaises(OSError):self.install()
  self.profile.unlink();self.profile.write_text('{}');os.chmod(self.profile,0o600)
  (self.payload/'milvago-discovery-system').write_bytes(b'image/png')
  with self.assertRaises(ValueError):self.install()
  bad=self.base/'writable';bad.mkdir();os.chmod(bad,0o777)
  with self.assertRaises(ValueError):installer.directory(bad)
  self.assertEqual(target.read_text(),'unchanged')

if __name__=='__main__':unittest.main()
