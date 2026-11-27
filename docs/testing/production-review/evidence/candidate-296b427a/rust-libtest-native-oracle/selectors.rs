mod alpha {
    #[test] fn first() {}
    #[test] fn second() {}
    #[ignore] #[test] fn muted() {}
}

mod alphabet {
    #[test] fn first() {}
}

mod beta {
    #[test] fn first() {}
    #[test] fn second() {}
    #[ignore] #[test] fn muted() {}
}

#[test] fn unrelated() {}
