fn main() {
    let bytes = std::fs::read(std::env::args().nth(1).unwrap()).unwrap();
    match voboost_contract::agent_catalog::AgentCatalog::parse(&bytes) {
        Ok(c) => println!(
            "OK\n{}",
            String::from_utf8_lossy(&c.canonical_bytes().unwrap())
        ),
        Err(e) => {
            println!("ERR {e}");
            let c: voboost_contract::agent_catalog::AgentCatalog =
                serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
            println!("{}", String::from_utf8_lossy(&c.canonical_bytes().unwrap()));
        }
    }
}
