#![allow(missing_docs)]

mod vector_cases;

use std::fs;
use std::path::Path;

use serde_json::Value;

#[test]
fn published_vectors_match() -> Result<(), Box<dyn std::error::Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("test-vectors/v1");
    let update = std::env::var_os("UPDATE_VECTORS").is_some();
    for case in vector_cases::all()? {
        let path = root.join(format!("{}.json", case.name));
        let rendered = format!("{}\n", serde_json::to_string_pretty(&case.value)?);
        if update {
            fs::write(&path, &rendered)?;
        }
        let published: Value = serde_json::from_str(&fs::read_to_string(&path)?)?;
        assert_eq!(published, case.value, "{}", case.name);
    }
    Ok(())
}
