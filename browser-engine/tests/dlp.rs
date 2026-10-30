use milvago_browser_engine::{InspectionInput,inspect_with_context};
use serde_json::json;
use std::collections::BTreeMap;

fn request(native:bool)->InspectionInput {
    InspectionInput{scope:"browser".into(),provider:"chatgpt.com".into(),text:"Tomate person@example.test".into(),upload:false,service:json!({"id":"chatgpt","mode":"observe","enabled":true}),config:json!({
        "protection":{"keywords":["Tomate"],"exact":"block"},"privacy":{"enabled":true,"types":["email"]},"classification":{"browser":["email"],"coding":["email"]},
        "dlp_legacy_disabled":true,"dlp_fingerprint":"a".repeat(64),"dlp_context":{"device_id":"signed-device"},
        "dlp":{"schema_version":1,"domain":"endpoint","inspection":true,"native_inspection":native,"journal":true,"detectors":[],"rules":[{
            "id":"replace","revision":1,"name":"Tomate to Carotte","priority":1,"mode":"active","condition":{"op":"contains","field":"prompt","value":"Tomate","ignore_case":false,"whole_word":false},
            "scope":{"op":"all","children":[{"op":"eq","field":"channel","value":"native"},{"op":"eq","field":"tool","value":"codex"},{"op":"eq","field":"provider","value":"chatgpt"},{"op":"eq","field":"device_id","value":"signed-device"}]},
            "consequence":{"action":"replace","value":"Tomate","replacement":"Carotte","ignore_case":false,"whole_word":false},"review":false,"message":""
        }]}
    })}
}
fn facts()->BTreeMap<String,String>{BTreeMap::from([("channel".into(),"native".into()),("tool".into(),"codex".into()),("device_id".into(),"forged-device".into())])}

#[test]
fn native_inspection_is_independent_of_retention_and_classification_scope() {
    let input=request(false);
    let result=inspect_with_context(&input,facts()).unwrap();
    assert_eq!(result.text,input.text);assert!(result.labels.is_empty());assert!(result.dlp.is_empty());
    let input=request(true);
    let result=inspect_with_context(&input,facts()).unwrap();
    assert_eq!(result.action,"observe");assert_eq!(result.text,"Carotte person@example.test");
    assert_eq!(result.dlp.len(),1);assert_eq!(result.dlp[0].rule_name,"Tomate to Carotte");
}

#[test]
fn no_analysis_still_honors_service_blocks_and_input_limits() {
    let mut input=request(false);input.service["mode"]=json!("block");
    assert_eq!(inspect_with_context(&input,facts()).unwrap().action,"block");
    input.text="x".repeat(32769);
    assert!(inspect_with_context(&input,facts()).is_err());
}

#[test]
fn migrated_builtin_masking_preserves_legacy_results_on_supported_text() {
    let categories=["email","phone","iban","card","ssn_us","social_id","ip"];
    let samples=["plain synthetic text","contact person@example.test now","phone +33 6 12 34 56 78","4111 1111 1111 1111","4111 1111 1111 1112","address 192.0.2.1","not-an-address 999.999.999.999","synthetic 123-45-6789","fullwidth ４１１１１１１１１１１１１１１１","unicode pｅrson@example.test","invisible per\u{200b}son@example.test","person@example.test person@example.test","embedded [EMAIL] person@example.test"];
    for category in categories {
        for text in samples {
            let legacy=InspectionInput{scope:"browser".into(),provider:"chatgpt.com".into(),text:text.into(),upload:false,service:json!({"id":"chatgpt","mode":"observe","enabled":true}),config:json!({"protection":{},"privacy":{"enabled":true,"review":false,"types":[category],"custom_rules":[]},"classification":{"browser":[],"coding":[]}})};
            let before=inspect_with_context(&legacy,BTreeMap::new()).unwrap();
            let mut migrated=legacy.clone();
            migrated.config["dlp_legacy_disabled"]=json!(true);migrated.config["dlp_fingerprint"]=json!("a".repeat(64));
            migrated.config["dlp"]=json!({"schema_version":1,"domain":"endpoint","inspection":true,"native_inspection":false,"journal":true,"detectors":[{"id":"legacy","name":"Legacy","definition":{"kind":"builtin","category":category}}],"rules":[{"id":"mask","revision":1,"name":"Legacy mask","mode":"active","priority":100,"condition":{"op":"matches","field":"prompt","detector":"legacy","minimum":1},"scope":{"op":"true"},"consequence":{"action":"mask","detector":"legacy","label":category.to_uppercase()},"review":false,"message":""}]});
            let after=inspect_with_context(&migrated,BTreeMap::new()).unwrap();
            assert_eq!(after.text,before.text,"category={category} text={text}");
            assert_eq!(after.action,before.action,"category={category} text={text}");
        }
    }
}

#[test]
fn browser_warning_returns_confirmation_without_rewriting_and_without_journaling(){
 for journal in [false,true]{
 let mut data=request(false);data.config["dlp"]["journal"]=json!(journal);
 data.config["dlp"]["rules"][0]["consequence"]=json!({"action":"warn"});
 data.config["dlp"]["rules"][0]["message"]=json!("Confirm this submission.");
 data.config["dlp"]["rules"][0]["scope"]=json!({"op":"eq","field":"channel","value":"browser"});
 let result=inspect_with_context(&data,BTreeMap::from([("channel".into(),"browser".into()),("tool".into(),"chrome".into())])).unwrap();
 assert_eq!(result.action,"review");assert!(result.confirmation);assert_eq!(result.text,data.text);assert_eq!(result.reason,"Confirm this submission.");assert_eq!(result.dlp.len(),if journal{1}else{0});
 }
}
