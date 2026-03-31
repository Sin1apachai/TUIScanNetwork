use tui_scan_network::{ups, SecurityLevel};
use snmp2::v3::{AuthProtocol, Cipher};

#[tokio::main]
async fn main() {
    let addr = "192.168.1.103:161";
    let user = "root";
    let pass = "12345678";
    let priv_pass = "12345678";
    let proto = AuthProtocol::Md5;
    let cipher = Cipher::Des;
    let level = SecurityLevel::AuthPriv;

    println!("========================================");
    println!("SNMP V3 TESTER: {}", addr);
    println!("User: {}, Auth: MD5, Priv: DES", user);
    println!("========================================");
    
    match ups::identify_ups_v3(addr, user, pass, priv_pass, proto, cipher, level).await {
        Ok(Some(dev)) => {
            println!("✅ SUCCESS! Found UPS Device:");
            println!("   Vendor: {:?}", dev.vendor);
            println!("   Model:  {}", dev.model);
        }
        Ok(None) => {
            println!("⚠️  Connected, but device identification failed.");
        }
        Err(e) => {
            println!("❌ FAILED with error: {:?}", e);
        }
    }

    println!("\nWaiting 2 seconds before metrics test...");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    println!("Attempting to read Battery Capacity (.1.3.6.1.2.1.33.1.2.4.0)...");
    let mut security = snmp2::v3::Security::new(user.as_bytes(), pass.as_bytes()).with_auth_protocol(proto);
    security = match level {
        SecurityLevel::NoAuth => security,
        SecurityLevel::AuthNoPriv => security.with_auth(snmp2::v3::Auth::AuthNoPriv),
        SecurityLevel::AuthPriv => security.with_auth(snmp2::v3::Auth::AuthPriv { cipher, privacy_password: priv_pass.as_bytes().to_vec() }),
    };

    match snmp2::SyncSession::new_v3(addr, Some(std::time::Duration::from_secs(5)), 5, security) {
        Ok(mut session) => {
            let oid = snmp2::Oid::from(&[1, 3, 6, 1, 2, 1, 33, 1, 2, 4, 0]).unwrap();
            match session.get(&oid) {
                Ok(resp) => {
                    if let Some(vb) = resp.varbinds.into_iter().next() {
                        println!("✅ BATTERY CAPACITY: {:?}", vb.1);
                    } else {
                        println!("⚠️ No varbinds in response");
                    }
                }
                Err(e) => {
                    println!("❌ GET OID FAILED: {:?}", e);
                }
            }
        }
        Err(e) => {
            println!("❌ SESSION CREATION FAILED: {:?}", e);
        }
    }
}
