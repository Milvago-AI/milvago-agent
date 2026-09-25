//! Versioned native-messaging relay. It never owns machine credentials.
use milvago_browser_agent::{Result,frame,write_frame};
use serde_json::{Value,json};
use std::{io,time::{Duration,Instant}};
#[cfg(windows)]
fn cache_request(edition:&str,request:&Value)->Result<Value>{
    use milvago_browser_agent::{cache_service,ipc,update};
    if request["protocol"]!=2||request["op"]!="browser_request"{return Err("browser broker operation refused".into())}
    update::wake_applier(edition)?;
    let until=Instant::now()+Duration::from_secs(5);
    loop{
        match ipc::exchange_timeout(&cache_service::channel(edition),ipc::Access::CacheBrowser,request,Duration::from_secs(4)){
            Ok(value)=>return Ok(value),Err(error)if Instant::now()>=until=>return Err(error),
            Err(_)=>std::thread::sleep(Duration::from_millis(100)),
        }
    }
}
fn run()->Result<()> {
    let args:Vec<_>=std::env::args().skip(1).collect();
    if args.as_slice()==["--capabilities"] {println!("{}",milvago_browser_agent::browser_broker::capabilities());return Ok(())}
    if !milvago_browser_agent::native::browser_caller(&args){return Err("browser origin refused".into())}
    #[cfg(windows)]
    milvago_browser_agent::cache_peer::browser_session()?;
    let edition=milvago_browser_agent::extension_update::EDITION;
    let channel=if edition=="commercial"{"commercial"}else{"browser"};
    let mut input=io::stdin().lock();let mut output=io::stdout().lock();
    while let Some(request)=frame(&mut input)? {
        let op=request["op"].as_str().unwrap_or("");
        let answer=if op=="browser_request"||op.starts_with("cache_") {
            #[cfg(windows)]
            {cache_request(edition,&request)}
            #[cfg(not(windows))]
            {Err("browser autonomy requires Windows".into())}
        } else {milvago_browser_agent::ipc::exchange_timeout(channel,milvago_browser_agent::ipc::Access::Browser,&request,Duration::from_secs(5))};
        write_frame(&mut output,&answer.unwrap_or_else(|_|json!({"ok":false,"error":"agent_unavailable"})))?;
    }
    Ok(())
}
fn main(){if run().is_err(){std::process::exit(1)}}
