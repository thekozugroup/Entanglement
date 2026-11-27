use std::time::{SystemTime, UNIX_EPOCH};

fn now_ns() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
}

fn verify_xorshift_sequence(mut x: u32, rounds: usize, expected: u32) {
    let begin = now_ns();
    for _ in 0..rounds {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
    }
    assert_eq!(x, expected);
    println!("seeded_guest_interval {} {}", begin, now_ns());
}

#[test]
fn a_long() { verify_xorshift_sequence(4919, 170000000, 1380937680); }

#[test]
fn b_short() { verify_xorshift_sequence(4920, 95000, 1354091051); }

#[test]
fn c_long() { verify_xorshift_sequence(4921, 170000000, 4073116447); }

#[test]
fn d_short() { verify_xorshift_sequence(4922, 90000, 3711156642); }

#[test]
fn e_medium() { verify_xorshift_sequence(4923, 15000000, 3858101986); }

#[test]
fn f_short() { verify_xorshift_sequence(4924, 91000, 2941234534); }

#[test]
fn g_medium() { verify_xorshift_sequence(4925, 15000000, 1589110650); }

#[test]
fn h_short() { verify_xorshift_sequence(4926, 99000, 231209851); }
