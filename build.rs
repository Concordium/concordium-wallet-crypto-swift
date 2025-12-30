use concordium_base::*;

fn main() {
    let out_dir = std::env::var_os("OUT_DIR").unwrap();
    let dest_path = std::path::Path::new(&out_dir).join("table_bytes.bin");

    let global = id::types::GlobalContext::<concordium_base::id::constants::ArCurve>::generate(
        String::from("genesis_string"),
    );
    let m = 1 << 16;
    let table = elgamal::BabyStepGiantStep::new(global.encryption_in_exponent_generator(), m);
    std::fs::write(dest_path, common::to_bytes(&table)).expect("Could not write table to file.");
    let udl_file_path = "./src/lib.udl";
    uniffi::generate_scaffolding(udl_file_path).unwrap();

    // TODO: this is workaround for `clippy::empty_line_after_doc_comments` that turns warnings into erros in 1.91.
    // The generated scafoling has lots of empty lines, especially after the doc comments "///".
    // Updating to the newer version of `uniffi`` should fix the issue, but would require addresing the breaking changes.
    let path = std::path::Path::new(&out_dir).join("lib.uniffi.rs");
    let contents = std::fs::read_to_string(&path).unwrap();

    let fixed = contents
        .lines()
        .filter(|line| line.trim() != "")
        .collect::<Vec<_>>()
        .join("\n");

    std::fs::write(&path, fixed).unwrap();
}
