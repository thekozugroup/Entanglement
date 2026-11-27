use std::{env,fs,path::PathBuf};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args=env::args_os().skip(1).map(PathBuf::from);
    let core=fs::read(args.next().unwrap())?;
    let adapter=fs::read(args.next().unwrap())?;
    let output=args.next().unwrap();
    let bytes=wit_component::ComponentEncoder::default().module(&core)?
        .adapter("wasi_snapshot_preview1",&adapter)?.validate(true).encode()?;
    fs::write(output,bytes)?;
    Ok(())
}
