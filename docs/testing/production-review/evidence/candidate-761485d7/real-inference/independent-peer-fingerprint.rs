use std::io::{self, Read};
fn main() {let mut s=String::new();io::stdin().read_to_string(&mut s).unwrap();let s=s.trim();assert!(s.len()==64);let b=(0..32).map(|i|u8::from_str_radix(&s[2*i..2*i+2],16).unwrap()).collect::<Vec<_>>();for byte in &blake3::hash(&b).as_bytes()[..16]{print!("{byte:02x}")}println!();}
