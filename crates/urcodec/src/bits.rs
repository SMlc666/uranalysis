pub fn bits(word: u32, lo: u8, hi: u8) -> u32 {
    debug_assert!(lo <= hi);
    debug_assert!(hi < 32);
    let width = u32::from(hi - lo + 1);
    let mask = if width == 32 {
        u32::MAX
    } else {
        (1u32 << width) - 1
    };
    (word >> lo) & mask
}

pub fn sign_extend(value: u32, width: u8) -> i64 {
    debug_assert!((1..=32).contains(&width));
    let shift = 64 - width;
    ((i64::from(value)) << shift) >> shift
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_inclusive_bit_ranges() {
        assert_eq!(bits(0b1101_0110, 1, 3), 0b011);
        assert_eq!(bits(0b1101_0110, 4, 7), 0b1101);
    }

    #[test]
    fn sign_extends_values() {
        assert_eq!(sign_extend(0b0111, 4), 7);
        assert_eq!(sign_extend(0b1000, 4), -8);
        assert_eq!(sign_extend(0b1111, 4), -1);
    }
}
