#[test]
fn intentionally_fails_on_first_attempt() {
    let attempt: u8 = std::env::var("ENTANGLE_LIBTEST_ATTEMPT")
        .expect("libtest invocation provides the attempt number")
        .parse()
        .expect("attempt number is an integer");
    assert!(attempt > 1, "intentional first-attempt failure");
}

#[test]
#[ignore = "exercises explicit selection and exhausted retries"]
fn intentionally_fails_on_every_attempt() {
    panic!("intentional failure on every attempt");
}
