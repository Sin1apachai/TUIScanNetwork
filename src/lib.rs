pub mod ups;
pub mod device;

use snmp2::v3::{AuthProtocol, Cipher};

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum SecurityLevel { NoAuth, AuthNoPriv, AuthPriv }

#[derive(PartialEq, Clone, Debug)]
pub enum EditMode {
    None,
    Input(String, usize),
    ManualAdd,
}

pub struct Config {
    pub snmp_port: u16,
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub v3_user: String,
    pub v3_auth_pass: String,
    pub v3_priv_pass: String,
    pub v3_auth_protocol: AuthProtocol,
    pub v3_cipher: Cipher,
    pub v3_level: SecurityLevel,
    pub community: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            snmp_port: 161,
            timeout_ms: 5000,
            concurrency: 60,
            v3_user: String::new(),
            v3_auth_pass: String::new(),
            v3_priv_pass: String::new(),
            v3_auth_protocol: AuthProtocol::Md5,
            v3_cipher: Cipher::Des,
            v3_level: SecurityLevel::AuthPriv,
            community: "public".to_string(),
        }
    }
}
