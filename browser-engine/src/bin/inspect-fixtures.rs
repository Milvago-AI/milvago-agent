use milvago_browser_engine::{inspect, InspectionInput};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{fs, process};

#[derive(Deserialize)]
struct Fixture {
    name: String,
    editions: Vec<String>,
    input: InspectionInput,
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| process::exit(2));
    let edition = std::env::args().nth(2).unwrap_or_else(|| process::exit(2));
    let bytes = fs::read(path).unwrap_or_else(|_| process::exit(2));
    let fixtures: Vec<Fixture> = serde_json::from_slice(&bytes).unwrap_or_else(|_| process::exit(2));
    let output: Vec<Value> = fixtures.into_iter()
        .filter(|fixture| fixture.editions.iter().any(|value| value == &edition))
        .map(|mut fixture| { if fixture.input.text == "__OVER_LIMIT__" { fixture.input.text = "x".repeat(milvago_browser_engine::TEXT_LIMIT + 1); } match inspect(&fixture.input) {
            Ok(result) => json!({"name": fixture.name, "result": result}),
            Err(error) => json!({"name": fixture.name, "error": error}),
        }})
        .collect();
    print!("{}", serde_json::to_string(&output).unwrap());
}
