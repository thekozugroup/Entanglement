#[test]
fn runs_past_worker_deadline() {
    loop {
        std::hint::black_box(());
    }
}
