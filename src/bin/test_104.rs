use snmp2::{SyncSession, Oid};
use snmp2::v3::{Security, Auth, AuthProtocol, Cipher};
use std::time::Duration;

fn main() {
    let agent_addr = "192.168.1.104:161";
    let security = Security::new("root".as_bytes(), "12345678".as_bytes())
        .with_auth_protocol(AuthProtocol::Md5)
        .with_auth(Auth::AuthPriv { 
            cipher: Cipher::Des, 
            privacy_password: "12345678".as_bytes().to_vec() 
        });

    println!("Testing Native Library connectivity to {}...", agent_addr);
    match SyncSession::new_v3(agent_addr, Some(Duration::from_secs(5)), 5, security) {
        Ok(mut session) => {
            let oid = Oid::from(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap();
            match session.get(&oid) {
                Ok(resp) => println!("✅ SUCCESS: {:?}", resp),
                Err(e) => println!("❌ GET FAILED: {:?}", e),
            }
        }
        Err(e) => println!("❌ CONNECTION FAILED: {:?}", e),
    }
}
