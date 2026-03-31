fn main() {
    let oids = [
        (".1.3.6.1.2.1.33.1.2.4.0", "Battery Charge (%)"),
        (".1.3.6.1.2.1.1.1.0", "Description"),
    ];
    let full_output = ".1.3.6.1.2.1.33.1.2.4.0 = INTEGER: 100\n.1.3.6.1.2.1.1.1.0 = STRING: Network Management Card for UPS";

    for line in full_output.lines() {
        if let Some((oid_part, val_raw)) = line.split_once(" = ") {
            let val = if let Some((_type, actual)) = val_raw.split_once(": ") { actual } else { val_raw }.trim();
            println!("Parsing OID Part: '{}', Value: '{}'", oid_part, val);
            if let Some((oid_str, label)) = oids.iter().find(|(o, _)| oid_part.contains(&**o)) {
                println!("✅ MATCH: label='{}', val='{}'", label, val);
            } else {
                println!("❌ NO MATCH for '{}'", oid_part);
            }
        }
    }
}
