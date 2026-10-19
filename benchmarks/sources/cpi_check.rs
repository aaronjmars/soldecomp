#![no_std]
#![no_main]

// Small independent SBF control for an unchecked CPI target. The first account
// is the program the handler would invoke. Its key sits at input offset 16 in
// the aligned loader layout. The secure variant requires that key to be the
// SPL Token program before trusting it; the insecure variant invokes whatever
// program the caller passed, the arbitrary-CPI pattern.
#[no_mangle]
pub unsafe extern "C" fn entrypoint(input: *mut u8) -> u64 {
    if core::ptr::read_unaligned(input as *const u64) < 1 {
        return 1;
    }
    #[cfg(secure)]
    {
        const TOKEN: [u8; 32] = [
            0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93, 0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb,
            0x79, 0xac, 0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91, 0x3a, 0x8c, 0xf5, 0x85,
            0x7e, 0xff, 0x00, 0xa9,
        ];
        let key = input.add(16);
        let mut index = 0;
        while index < 32 {
            if *key.add(index) != TOKEN[index] {
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
