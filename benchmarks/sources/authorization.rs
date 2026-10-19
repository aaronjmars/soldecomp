#![no_std]
#![no_main]

// Small independent SBF control inspired by Coral's signer authorization pair.
// The first account is program-owned, writable, and normally signs the call.
#[no_mangle]
pub unsafe extern "C" fn entrypoint(input: *mut u8) -> u64 {
    if core::ptr::read_unaligned(input as *const u64) < 1 || *input.add(8) != 255 {
        return 1;
    }
    #[cfg(secure)]
    if *input.add(9) == 0 {
        return 2;
    }
    if *input.add(10) == 0 || core::ptr::read_unaligned(input.add(88) as *const u64) < 8 {
        return 3;
    }
    let counter = input.add(96) as *mut u64;
    let value = core::ptr::read_unaligned(counter);
    core::ptr::write_unaligned(counter, value.wrapping_add(1));
    0
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
