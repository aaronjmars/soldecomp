#![no_std]
#![no_main]

// Small independent SBF control for a missing owner check. The first account is
// read-only. In the aligned loader input the account-0 owner is 32 bytes at
// offset 48. The secure variant requires it to be the System program (all zero
// bytes); the insecure variant uses the account without checking its owner.
#[no_mangle]
pub unsafe extern "C" fn entrypoint(input: *mut u8) -> u64 {
    if core::ptr::read_unaligned(input as *const u64) < 1 {
        return 1;
    }
    #[cfg(secure)]
    {
        let owner = input.add(48);
        let mut index = 0;
        while index < 32 {
            if *owner.add(index) != 0 {
                return 2;
            }
            index += 1;
        }
    }
    0
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
