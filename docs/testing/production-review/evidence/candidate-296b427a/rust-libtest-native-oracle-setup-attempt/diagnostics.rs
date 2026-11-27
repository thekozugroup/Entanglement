#[cfg(test)]
mod tests {
    #[test]
    fn quiet() {
        assert_eq!("one two".split_whitespace().count(), 2);
    }

    #[test]
    fn prints_application_result_diagnostic() {
        println!("test result: underlying parser accepted both records");
        assert_eq!("one two".split_whitespace().count(), 2);
    }

    #[test]
    fn prints_captured_summary_from_fixture() {
        let recorded = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s";
        println!("{recorded}");
        println!("the previous line is an application fixture");
        assert!(recorded.contains("passed"));
    }

    #[test]
    fn reports_error_after_diagnostic() {
        println!("test result: values will be compared");
        assert_eq!("left", "right");
    }

    #[test]
    fn checks_timeout_with_diagnostic_on_first_attempt() {
        if std::env::var("ENTANGLE_LIBTEST_ATTEMPT").as_deref() == Ok("1") {
            println!("test result: retry fixture timed out before the record arrived");
            panic!("first worker attempt reports a real assertion failure");
        }
    }

    #[test]
    fn returns_result_error() -> Result<(), &'static str> {
        Err("this is a normal Rust test Result error")
    }
}

#[cfg(test)]
mod tail_controls {
    #[test]
    fn prints_without_newline_before_success() {
        print!("test result: parser finished inline");
        assert!("parser".starts_with("par"));
    }

    #[test]
    fn exits_before_libtest_finishes() {
        println!("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out; finished in 0.00s");
        std::process::exit(0);
    }

    #[test]
    #[should_panic]
    #[ignore = "terminal reason can start test result:."]
    fn expected_panic_with_reason() {
        panic!("expected");
    }
}
