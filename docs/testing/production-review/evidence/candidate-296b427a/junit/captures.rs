//! Controlled fixture for preserving large real harness captures in JUnit XML.
fn exercise(name: &str) {
    let sample = "<record> λ & pass\u{1}\n".repeat(2048);
    println!("{name}: {sample}");
    assert_eq!(sample.lines().count(), 2048);
}
macro_rules! cases {
    ($($case:ident),*) => { $(#[test] fn $case() {exercise(stringify!($case));})* };
}
cases!(
    capture_00, capture_01, capture_02, capture_03, capture_04, capture_05, capture_06, capture_07,
    capture_08, capture_09, capture_10, capture_11, capture_12, capture_13, capture_14, capture_15,
    capture_16, capture_17, capture_18, capture_19, capture_20, capture_21, capture_22, capture_23,
    capture_24, capture_25, capture_26, capture_27, capture_28, capture_29, capture_30, capture_31,
    capture_32, capture_33, capture_34, capture_35, capture_36, capture_37, capture_38, capture_39,
    capture_40, capture_41, capture_42, capture_43, capture_44, capture_45, capture_46, capture_47
);
