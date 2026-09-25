//! Kernel identities for the privileged cache and update channels.
use crate::Result;
use std::{ffi::c_void,path::PathBuf};
#[link(name="kernel32")]
unsafe extern "system" {
    fn OpenProcess(access:u32,inherit:i32,pid:u32)->isize;
    fn CloseHandle(handle:isize)->i32;
    fn QueryFullProcessImageNameW(process:isize,flags:u32,path:*mut u16,size:*mut u32)->i32;
    fn GetStdHandle(kind:u32)->isize;
    fn GetNamedPipeServerProcessId(pipe:isize,pid:*mut u32)->i32;
}
#[link(name="advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process:isize,access:u32,token:*mut isize)->i32;
    fn GetTokenInformation(token:isize,kind:i32,information:*mut c_void,length:u32,returned:*mut u32)->i32;
    fn LookupAccountNameW(system:*const u16,name:*const u16,sid:*mut c_void,sid_len:*mut u32,domain:*mut u16,domain_len:*mut u32,use_kind:*mut u32)->i32;
    fn ConvertSidToStringSidW(sid:*mut c_void,text:*mut *mut u16)->i32;
    fn EqualSid(a:*const c_void,b:*const c_void)->i32;
}
#[link(name="kernel32")]
unsafe extern "system"{fn LocalFree(memory:*mut c_void)->*mut c_void;}
struct Handle(isize);impl Drop for Handle{fn drop(&mut self){unsafe{CloseHandle(self.0);}}}
fn image(pid:u32)->Result<PathBuf>{
    let handle=Handle(unsafe{OpenProcess(0x1000,0,pid)});if handle.0==0{return Err("peer unavailable".into())}
    let mut name=vec![0u16;32768];let mut len=name.len() as u32;
    if unsafe{QueryFullProcessImageNameW(handle.0,0,name.as_mut_ptr(),&mut len)}==0{return Err("peer image unavailable".into())}
    Ok(PathBuf::from(String::from_utf16(&name[..len as usize])?))
}
fn program_roots()->Vec<PathBuf>{["ProgramW6432","ProgramFiles","ProgramFiles(x86)"].into_iter()
    .filter_map(std::env::var_os).map(PathBuf::from).collect()}
fn same_path(a:&std::path::Path,b:&std::path::Path)->bool{
    a.as_os_str().to_string_lossy().replace('/', "\\")
        .eq_ignore_ascii_case(&b.as_os_str().to_string_lossy().replace('/', "\\"))
}
fn browser(pid:u32)->Result<()> {
    let executable=image(pid)?;
    if !program_roots().iter().any(|root|["Google/Chrome/Application/chrome.exe","Microsoft/Edge/Application/msedge.exe","Mozilla Firefox/firefox.exe"]
        .iter().any(|tail|same_path(&executable,&root.join(tail)))){return Err("managed browser image refused".into())}
    // Holding the directory prevents rename/reparse substitution. The installed
    // browser image itself must also be administrator-owned and non-writable.
    let directory=crate::cache_windows::Directory::installed(executable.parent().ok_or("browser directory absent")?)?;
    let _image=directory.hold_file(executable.file_name().ok_or("browser image absent")?)?;
    drop(directory);Ok(())
}
/// Browser-created Native Messaging pipes are the evidence, not parent PID or
/// origin arguments (both can be forged by a launcher). This executable exposes
/// no alternate CLI that accepts cache requests without this check.
pub fn browser_session()->Result<()> {
    let mut input=0;let mut output=0;
    if unsafe{GetNamedPipeServerProcessId(GetStdHandle(-10i32 as u32),&mut input)}==0
        ||unsafe{GetNamedPipeServerProcessId(GetStdHandle(-11i32 as u32),&mut output)}==0
        ||input==0||input!=output{return Err("native messaging pipe origin refused".into())}
    browser(input)
}
/// Hygiene, not authentication: the image of a process the user owns proves nothing
/// against that user, who can start the relay suspended or inject into it, and the
/// pid may be recycled between the pipe and the process lookup. The CacheBrowser
/// channel is therefore reachable by every signed-in user, and is built for it: the
/// identity comes from the impersonation token, `caller.system` is never true for a
/// user, and each account has its own share of the queue and of its receipt ring.
pub fn relay(pid:u32,edition:&str)->Result<()> {
    if !matches!(edition,"community"|"commercial"){return Err("invalid relay edition".into())}
    let executable=image(pid)?;let folder=if edition=="commercial"{"Commercial"}else{"Browser"};
    let version=executable.parent().and_then(|p|p.file_name()).and_then(|p|p.to_str()).ok_or("relay version absent")?;
    let pieces:Vec<_>=version.split('.').collect();
    if pieces.len()!=3||pieces.iter().any(|p|p.is_empty()||p.len()>5||!p.bytes().all(|b|b.is_ascii_digit())){return Err("relay version invalid".into())}
    if !program_roots().iter().any(|root|same_path(&executable,&root.join("Milvago").join(folder).join("runtime").join(version).join("milvago-relay.exe"))){return Err("relay image refused".into())}
    let directory=crate::cache_windows::Directory::installed(executable.parent().ok_or("relay directory absent")?)?;
    let _image=directory.hold_file(executable.file_name().ok_or("relay image absent")?)?;
    drop(directory);Ok(())
}
fn sid(edition:&str)->Result<Vec<u8>>{
    named_sid(match edition{"community"=>"Milvago Agent Logger Community","commercial"=>"Milvago Agent Logger",_=>return Err("invalid service edition".into())})
}
/// SID of `NT SERVICE\<service>`, as text.
pub fn named_service_sid(service:&str)->Result<String>{sid_text(named_sid(service)?)}
fn named_sid(service:&str)->Result<Vec<u8>>{
    let name:Vec<_>=format!("NT SERVICE\\{service}").encode_utf16().chain(Some(0)).collect();let(mut len,mut domain_len,mut kind)=(0,0,0);
    unsafe{LookupAccountNameW(std::ptr::null(),name.as_ptr(),std::ptr::null_mut(),&mut len,std::ptr::null_mut(),&mut domain_len,&mut kind);}
    if len==0||len>4096||domain_len>4096{return Err("service SID unavailable".into())}
    let mut sid=vec![0u8;len as usize];let mut domain=vec![0u16;domain_len as usize];
    if unsafe{LookupAccountNameW(std::ptr::null(),name.as_ptr(),sid.as_mut_ptr().cast(),&mut len,domain.as_mut_ptr(),&mut domain_len,&mut kind)}==0{return Err("service SID unavailable".into())}Ok(sid)
}
pub fn service_sid(edition:&str)->Result<String>{sid_text(sid(edition)?)}
fn sid_text(mut sid:Vec<u8>)->Result<String>{
    let mut text=std::ptr::null_mut();if unsafe{ConvertSidToStringSidW(sid.as_mut_ptr().cast(),&mut text)}==0{return Err("service SID conversion failed".into())}
    let mut len=0;while unsafe{*text.add(len)}!=0{len+=1;}
    let result=String::from_utf16(unsafe{std::slice::from_raw_parts(text,len)});unsafe{LocalFree(text.cast());}Ok(result?)
}
#[repr(C)]struct SidAndAttributes{sid:*mut c_void,attributes:u32}
#[repr(C)]struct Groups{count:u32,groups:[SidAndAttributes;1]}
pub fn agent(pid:u32,edition:&str)->Result<()> {
    let wanted=sid(edition)?;let process=Handle(unsafe{OpenProcess(0x1000,0,pid)});if process.0==0{return Err("service peer absent".into())}
    let mut token=0;if unsafe{OpenProcessToken(process.0,8,&mut token)}==0{return Err("service token absent".into())}let token=Handle(token);
    let mut size=0;unsafe{GetTokenInformation(token.0,2,std::ptr::null_mut(),0,&mut size);}
    if size==0||size>65536{return Err("service token rejected".into())}
    let mut bytes=vec![0u64;(size as usize+7)/8];if unsafe{GetTokenInformation(token.0,2,bytes.as_mut_ptr().cast(),size,&mut size)}==0{return Err("service token unavailable".into())}
    let groups=bytes.as_ptr() as *const Groups;let count=unsafe{(*groups).count} as usize;
    let offset=std::mem::offset_of!(Groups,groups);
    if offset+count*std::mem::size_of::<SidAndAttributes>()>size as usize{return Err("service groups invalid".into())}
    let list=unsafe{std::slice::from_raw_parts((bytes.as_ptr() as *const u8).add(offset) as *const SidAndAttributes,count)};
    if !list.iter().any(|group|group.attributes&4!=0&&group.attributes&16==0&&unsafe{EqualSid(group.sid,wanted.as_ptr().cast())}!=0){return Err("agent service identity refused".into())}Ok(())
}


#[cfg(test)]
mod path_tests {
    use super::same_path;
    use std::path::Path;

    #[test]
    fn browser_path_accepts_windows_separator_and_case_variants() {
        let root=Path::new(r"C:\Program Files");
        let image=root.join("Google").join("Chrome").join("Application").join("chrome.exe");
        assert!(same_path(&image,&root.join("Google/Chrome/Application/chrome.exe")));
        assert!(same_path(&image,Path::new(r"c:\program files\google\chrome\application\CHROME.EXE")));
        assert!(same_path(Path::new(r"C:\Program Files\Mozilla Firefox\firefox.exe"),
            &root.join("Mozilla Firefox/firefox.exe")));
    }

    #[test]
    fn normalization_does_not_expand_trusted_paths() {
        let browser=Path::new(r"C:\Program Files\Google\Chrome\Application\chrome.exe");
        for refused in [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe.evil",
            r"C:\Program Files\Google\Chrome\Application\other.exe",
            r"C:\Program Files\Google\Chrome\ApplicationExtra\chrome.exe",
            r"C:\Program Files\Google\Chrome\Application\..\Application\chrome.exe",
        ] { assert!(!same_path(browser,Path::new(refused)),"refused path accepted"); }
        assert!(!same_path(
            Path::new(r"C:\Program Files\Milvago\Browser\runtime\0.5.12\milvago-relay.exe"),
            Path::new(r"C:\Program Files\Milvago\Browser\runtime\0.5.13\milvago-relay.exe")));
        assert!(!same_path(
            Path::new(r"C:\Program Files\Milvago\Browser\runtime\0.5.13\milvago-relay.exe"),
            Path::new(r"C:\Program Files\Milvago\Commercial\runtime\0.5.13\milvago-relay.exe")));
    }
}
