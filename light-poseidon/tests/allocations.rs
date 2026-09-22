//! Asserts that hashing performs no heap allocation.
//!
//! This crate is compiled natively into the validator and `solana_poseidon`
//! builds a fresh hasher on every `sol_poseidon` call, so both construction and
//! hashing sit on the syscall hot path. Allocation-freedom is a property worth
//! pinning: a future change that reintroduces a `Vec` would otherwise pass
//! unnoticed.
//!
//! The file holds a single test on purpose. The counter is global, so parallel
//! tests in the same binary would race on it.

use ark_bn254::Fr;
use ark_ff::Zero;
use light_poseidon::{Poseidon, PoseidonBytesHasher, PoseidonHasher, MAX_X5_LEN};
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

// Counts allocating calls and forwards everything to the system allocator.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        System.alloc_zeroed(layout)
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn count_allocations<F: FnOnce()>(f: F) -> usize {
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    f();
    ALLOCATIONS.load(Ordering::Relaxed) - before
}

#[test]
fn hashing_allocates_nothing() {
    // Everything the measurement needs is built up front, so only the hashing
    // itself is counted.
    let field_inputs: Vec<Vec<Fr>> = (1..MAX_X5_LEN).map(|n| vec![Fr::zero(); n]).collect();
    let byte_storage: Vec<Vec<[u8; 32]>> = (1..MAX_X5_LEN).map(|n| vec![[1u8; 32]; n]).collect();
    let byte_inputs: Vec<Vec<&[u8]>> = byte_storage
        .iter()
        .map(|inputs| inputs.iter().map(|b| b.as_slice()).collect())
        .collect();

    // Warm up: the first call through a code path can pull in lazily
    // initialised machinery that is not part of steady-state hashing.
    if let (Some(inputs), Some(bytes)) = (field_inputs.first(), byte_inputs.first()) {
        let mut hasher = Poseidon::<Fr>::new_circom(1).expect("hasher");
        let _ = hasher.hash(inputs);
        let _ = hasher.hash_bytes_be(bytes);
        let _ = hasher.hash_bytes_le(bytes);
    }

    for (index, nr_inputs) in (1..MAX_X5_LEN).enumerate() {
        let inputs = field_inputs.get(index).expect("field inputs");
        let bytes = byte_inputs.get(index).expect("byte inputs");

        let allocations = count_allocations(|| {
            let mut hasher = Poseidon::<Fr>::new_circom(nr_inputs).expect("hasher");
            black_box(hasher.hash(inputs).expect("hash"));
        });
        assert_eq!(
            allocations, 0,
            "new_circom({nr_inputs}) + hash allocated {allocations} times"
        );

        let allocations = count_allocations(|| {
            let mut hasher = Poseidon::<Fr>::new_circom(nr_inputs).expect("hasher");
            black_box(hasher.hash_bytes_be(bytes).expect("hash_bytes_be"));
        });
        assert_eq!(
            allocations, 0,
            "new_circom({nr_inputs}) + hash_bytes_be allocated {allocations} times"
        );

        let allocations = count_allocations(|| {
            let mut hasher = Poseidon::<Fr>::new_circom(nr_inputs).expect("hasher");
            black_box(hasher.hash_bytes_le(bytes).expect("hash_bytes_le"));
        });
        assert_eq!(
            allocations, 0,
            "new_circom({nr_inputs}) + hash_bytes_le allocated {allocations} times"
        );

        // A reused hasher must stay allocation-free across repeated calls.
        let allocations = count_allocations(|| {
            let mut hasher = Poseidon::<Fr>::new_circom(nr_inputs).expect("hasher");
            for _ in 0..4 {
                black_box(hasher.hash(inputs).expect("hash"));
            }
        });
        assert_eq!(
            allocations,
            0,
            "repeated hashing at width {} allocated {allocations} times",
            nr_inputs + 1
        );
    }
}
