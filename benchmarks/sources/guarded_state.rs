#![no_std]
#![no_main]

// Small SBF controls for stale price, minimum output, and borrowing limits.
// State fields: output, oracle timestamp, collateral, debt (four u64 values).
const DATA_INCREASE: usize = 10_240;

unsafe fn read_u64(ptr: *mut u8, offset: usize) -> u64 {
    core::ptr::read_unaligned(ptr.add(offset) as *const u64)
}

unsafe fn next_account(start: usize, data_len: usize) -> usize {
    (start + 88 + data_len + DATA_INCREASE + 8 + 7) & !7
}

#[no_mangle]
pub unsafe extern "C" fn entrypoint(input: *mut u8) -> u64 {
    let count = read_u64(input, 0);
    if count < 1 || *input.add(8) != 255 || *input.add(10) == 0 {
        return 1;
    }
    let data_len = read_u64(input, 88) as usize;
    if data_len < 32 {
        return 2;
    }
    let state = input.add(96);
    let mut offset = next_account(8, data_len);
    let clock_data = if count > 1 {
        if *input.add(offset) != 255 || read_u64(input, offset + 80) < 40 {
            return 3;
        }
        let clock = input.add(offset + 88);
        offset = next_account(offset, read_u64(input, offset + 80) as usize);
        Some(clock)
    } else {
        None
    };
    if read_u64(input, offset) < 1 {
        return 4;
    }
    let instruction = input.add(offset + 8);
    let operation = *instruction;
    let argument = if read_u64(input, offset) >= 9 {
        read_u64(instruction, 1)
    } else {
        0
    };
    let field = |index: usize| read_u64(state, index * 8);
    match operation {
        1 => {
            #[cfg(secure)]
            if argument > 5 {
                return 5;
            }
            core::ptr::write_unaligned(state as *mut u64, field(0).wrapping_add(5));
        }
        2 => {
            let new_debt = field(3).wrapping_add(argument);
            #[cfg(secure)]
            if new_debt.saturating_mul(2) > field(2) {
                return 6;
            }
            core::ptr::write_unaligned(state.add(24) as *mut u64, new_debt);
        }
        3 => {
            let Some(clock) = clock_data else { return 7 };
            let _now = core::ptr::read_unaligned(clock.add(32) as *const i64);
            #[cfg(secure)]
            if _now.saturating_sub(field(1) as i64) > 60 {
                return 8;
            }
            core::ptr::write_unaligned(state as *mut u64, field(0).wrapping_add(1));
        }
        _ => return 9,
    }
    0
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
