//! Shamir `split` and `combine` wipe every heap buffer that held the secret
//! before freeing it, so the release key does not linger in freed memory
//! (and from there in swap or a core dump) after a key ceremony.
//!
//! A scanning global allocator zero-initialises every allocation, so every
//! byte it later reads is initialised, and, while armed, checks each block
//! being freed (including the old block of a reallocation) for the secret.
//! The test wipes its own copies, so a hit is a copy that `split` or `combine`
//! freed without wiping. One test per binary: the allocator is process-wide.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};

use entangle_signing::shamir;

/// 32 bytes that occur nowhere else in the process's heap.
const SECRET: [u8; 32] = [
    0xd4, 0x1f, 0x8c, 0x02, 0x77, 0xb9, 0x3e, 0xa5, 0x61, 0x0d, 0xf2, 0x9b, 0x48, 0xc6, 0x13, 0x7e,
    0xe9, 0x25, 0x5a, 0xb0, 0x8f, 0x36, 0xcd, 0x04, 0x71, 0x9e, 0x2b, 0xd8, 0x63, 0x1a, 0xf7, 0x40,
];

static ARMED: AtomicBool = AtomicBool::new(false);
static UNWIPED: AtomicUsize = AtomicUsize::new(0);

struct Scanner;

// SAFETY: every method delegates to `System` with the caller's arguments, so
// `Scanner` upholds `GlobalAlloc`'s contract exactly as `System` does.
unsafe impl GlobalAlloc for Scanner {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged; `alloc_zeroed` has `alloc`'s contract.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(SeqCst) && layout.size() >= SECRET.len() {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes returned
            // by `alloc` above (zero-initialised there), not yet freed, and
            // its owner has given it up, so nothing else accesses it now.
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if block.windows(SECRET.len()).any(|w| w == SECRET) {
                UNWIPED.fetch_add(1, SeqCst);
            }
        }
        // SAFETY: forwarded unchanged.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Scanner = Scanner;

/// The test's own wipe, so its copies never count.
fn wipe(v: &mut Vec<u8>) {
    let cap = v.capacity();
    v.resize(cap, 0);
    v.fill(0);
    std::hint::black_box(v.as_slice());
}

#[test]
fn split_and_combine_wipe_their_copies_of_the_secret() {
    let mut secret = Vec::with_capacity(SECRET.len());
    secret.extend_from_slice(&SECRET);

    ARMED.store(true, SeqCst);
    let shares = shamir::split(&secret, 2, 3).unwrap();
    let mut got = shamir::combine(&shares[..2]).unwrap();
    let matches = got == secret;
    // A failed reconstruction (a wrong share) holds the secret too.
    let other = shamir::split(&secret, 2, 3).unwrap();
    let mixed_ok = shamir::combine(&[shares[0].clone(), other[1].clone()]).is_err();
    wipe(&mut got);
    wipe(&mut secret);
    drop((got, secret, shares, other));
    ARMED.store(false, SeqCst);

    assert!(matches, "combine must reconstruct the secret");
    assert!(mixed_ok);
    assert_eq!(
        UNWIPED.load(SeqCst),
        0,
        "split/combine freed heap blocks still holding the secret"
    );
}
