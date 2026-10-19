#![no_std]
#![no_main]

// Small independent SBF control for a missing type-discriminator check. The
// first account is program-owned and carries an 8-byte type tag at the start
// of its data (account-0 data begins at input offset 96 in the aligned loader
// layout). The secure variant requires the tag to match the expected value,
// as an Anchor account discriminator would; the insecure variant uses the
// account without checking its type.
#[no_mangle]
pub unsafe extern "C" fn entrypoint(input: *mut u8) -> u64 {
    if core::ptr::read_unaligned(input as *const u64) < 1 {
        return 1;
    }
    let data_len = core::ptr::read_unaligned(input.add(88) as *const u64);
    if data_len < 8 {
        return 2;
    }
    #[cfg(secure)]
    {
        let discriminator = core::ptr::read_unaligned(input.add(96) as *const u64);
        if discriminator != 0x0102_0304_0506_0708 {
            return 3;
        }
    }
    0
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
