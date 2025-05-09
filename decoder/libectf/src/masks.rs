use alloc::vec::Vec;

/// Mask widths that are used to encode packets and generate subscription keys. More mask widths
/// means encoded packets are larger and subscriptions are smaller, and less mask widths means vice
/// versa.
pub const MASKS: &[u8] = &[0, 3, 6, 9, 12, 15, 18, 21, 24, 27, 30, 33, 36, 39, 42, 45, 48, 51, 54, 57, 60];

/// Turn a range of timestamps into a list of bitranges `(start_timestamp, mask_idx)`
pub(crate) fn characterize_range(mut a: u64, b: u64) -> Vec<(u64, u8)> {
    let mut res = Vec::new();

    let mut mask_idx = 0;

    while a <= b {
        if mask_idx < MASKS.len() - 1 {
            let next_block_span = (1 << MASKS[mask_idx + 1]) - 1;
            if a & next_block_span == 0 && a | next_block_span <= b {
                mask_idx += 1;
                continue;
            } 
        }
        let block_span = (1 << MASKS[mask_idx]) - 1;
        res.push((a, mask_idx as u8));
        a = (a | block_span).wrapping_add(1);
        if a == 0 {  // Overflow
            return res;
        }
        mask_idx = 0;
    }

    res
}
