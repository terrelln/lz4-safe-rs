use core::intrinsics::likely;

pub const COPY_LITERALS_OVER_LENGTH: usize = 32;
pub const COPY_MATCH_OVER_LENGTH: usize = 32;

#[derive(Clone, Copy)]
pub struct Stripe(pub usize);
#[derive(Clone, Copy)]
pub struct Idx(pub usize);
#[derive(Clone, Copy)]
pub struct Offset(pub usize);
#[derive(Clone, Copy)]
pub struct Len(pub usize);

/// Functions called in `Fast` mode are allowed to over-copy according to their docs.
/// Generally limited by the `Stripe`.
/// But, when called in `End` mode they are limited to copy only `Len`.
pub enum CopyMode {
    Fast,
    End,
}

/// Copies `stripe` bytes from `src` to `dst`.
/// This copy is intended to have a constant `stripe` and inlined.
/// E.g. a 16-byte stripe inlines to two `movups` calls + bounds checks on x86-64.
///
/// # Panics
/// Panics if `src.len()` or `dst.len()` is less than `stripe.0`.
#[inline(always)]
pub fn copy_stripe(dst: &mut [u8], src: &[u8], stripe: Stripe) {
    debug_assert!(src.len() >= stripe.0);
    debug_assert!(dst.len() >= stripe.0);
    let dst_stripe = &mut dst[..stripe.0];
    let src_stripe = &src[..stripe.0];
    dst_stripe.copy_from_slice(src_stripe);
}

fn striped_copy_len(len: Len, stripe: Stripe) -> usize {
    let num_stripes = len.0 / stripe.0;
    let num_stripes = if len.0 % stripe.0 > 0 {
        num_stripes + 1
    } else if len.0 > 0 {
        num_stripes
    } else {
        1
    };
    num_stripes * stripe.0
}

/// Copies `src` to `dst` in stripes of size `stripe`, which should be constant.
/// In `Fast` mode it will copy the first multiple of `stripe` bytes at least as large as `len`,
/// but will always copy at least `stripe` bytes. See [striped_copy_len](striped_copy_len).
/// In `End` mode it will copy exactly `len` bytes.
///
/// # Panics
/// Panics if either `src` or `dst` isn't large enough.
#[inline(always)]
pub fn striped_copy(dst: &mut [u8], src: &[u8], len: Len, stripe: Stripe, mode: CopyMode) {
    match mode {
        CopyMode::Fast => {
            debug_assert!(src.len() >= striped_copy_len(len, stripe));
            debug_assert!(dst.len() >= striped_copy_len(len, stripe));
            let mut idx = 0;
            loop {
                let dst_stripe = &mut dst[idx..idx + stripe.0];
                let src_stripe = &src[idx..idx + stripe.0];
                dst_stripe.copy_from_slice(src_stripe);
                idx += stripe.0;
                if idx >= len.0 {
                    break;
                }
            }
        }
        CopyMode::End => dst[..len.0].copy_from_slice(&src[..len.0]),
    }
}

/// Copies `buf[idx-offset..idx-offset+stripe]` to `buf[idx..idx+stripe]`.
/// Requires that the two ranges don't overlap `buf` is large enough.
///
/// # Panics
/// Panics if `offset < stripe`, or of `offset > idx`, or if `idx + stripe > buf.len()`.
#[inline(always)]
pub fn copy_stripe_within(buf: &mut [u8], idx: Idx, offset: Offset, stripe: Stripe) {
    debug_assert!(offset.0 <= idx.0);
    debug_assert!(offset.0 >= stripe.0);
    debug_assert!(idx.0 + stripe.0 <= buf.len());
    let (src, dst) = buf.split_at_mut(idx.0);
    copy_stripe(dst, &src[idx.0 - offset.0..], stripe);
}

/// Copies `buf[idx-offset..idx-offset+len]` to `buf[idx..idx+len]`.
/// In `Fast` mode it will copy the first multiple of `stripe` bytes at least as large as `len`,
/// but will always copy at least `stripe` bytes. See [striped_copy_len](striped_copy_len).
/// In `End` mode it will copy exactly `len` bytes.
/// Requires that `0 < offset <= 16`.
///
/// # Panics
/// Panics if `buf` isn't large enough, or if `offset > idx`, or if `offset > 16`.
/// May panic if `offset == 0`, or may set output to an undefined value.
#[inline(always)]
fn short_duplicating_copy(buf: &mut [u8], mut idx: Idx, offset: Offset, len: Len, mode: CopyMode) {
    debug_assert!(offset.0 > 0);
    debug_assert!(offset.0 < 16);
    debug_assert!(offset.0 <= idx.0);
    debug_assert!(idx.0 + len.0 <= buf.len());
    let mut pattern = [0u8; 16];
    let pattern_len = match offset.0 {
        0 => {
            // Invalid, but just memset to 0
            pattern.fill(0);
            16
        }
        1 => {
            pattern.fill(buf[idx.0 - 1]);
            16
        }
        2 => {
            pattern[0..2].copy_from_slice(&buf[idx.0 - 2..idx.0]);
            pattern.copy_within(0..2, 2);
            pattern.copy_within(0..4, 4);
            pattern.copy_within(0..8, 8);
            16
        }
        4 => {
            pattern[0..4].copy_from_slice(&buf[idx.0 - 4..idx.0]);
            pattern.copy_within(0..4, 4);
            pattern.copy_within(0..8, 8);
            16
        }
        8 => {
            pattern[0..8].copy_from_slice(&buf[idx.0 - 8..idx.0]);
            pattern.copy_within(0..8, 8);
            16
        }
        off => {
            pattern[0..off].copy_from_slice(&buf[idx.0 - off..idx.0]);
            let mut pattern_length = off;
            // TODO: SIMD pattern code
            while pattern_length <= 8 {
                pattern.copy_within(0..pattern_length, pattern_length);
                pattern_length *= 2;
            }
            pattern_length
        }
    };
    let end = idx.0 + len.0;
    debug_assert!(pattern_len <= 16);
    match mode {
        CopyMode::Fast => {
            debug_assert!(idx.0 + striped_copy_len(len, Stripe(16)) <= buf.len());
            loop {
                copy_stripe(&mut buf[idx.0..idx.0 + 16], &pattern, Stripe(16));
                idx.0 += pattern_len;
                if idx.0 >= end {
                    return;
                }
            }
        }
        CopyMode::End => {
            while idx.0 + 16 <= end {
                copy_stripe(&mut buf[idx.0..idx.0 + 16], &pattern, Stripe(16));
                idx.0 += pattern_len;
            }
            if idx.0 + pattern_len <= end {
                copy_stripe(
                    &mut buf[idx.0..idx.0 + pattern_len],
                    &pattern,
                    Stripe(pattern_len),
                );
                idx.0 += pattern_len;
            }
            for i in 0..(end - idx.0) {
                buf[idx.0 + i] = pattern[i];
            }
        }
    }
}

/// Copies `buf[idx-offset..idx-offset+len]` to `buf[idx..idx+len]`.
/// In `Fast` mode it will copy the first multiple of `stripe` bytes at least as large as `len`,
/// but will always copy at least `stripe` bytes. See [striped_copy_len](striped_copy_len).
/// In `End` mode it will copy exactly `len` bytes.
/// Requires that `0 < offset <= idx`.
///
/// # Panics
/// Panics if `buf` isn't large enough, or if `offset > idx`.
/// May panic if `offset == 0`, or may set output to an undefined value.
#[inline(always)]
pub fn duplicating_copy(buf: &mut [u8], mut idx: Idx, offset: Offset, len: Len, mode: CopyMode) {
    debug_assert!(offset.0 <= idx.0);
    debug_assert!(idx.0 + len.0 <= buf.len());

    const COPY_STRIPE: usize = 16;
    let end = idx.0 + len.0;
    if likely(offset.0 >= COPY_STRIPE) {
        match mode {
            CopyMode::Fast => loop {
                copy_stripe_within(buf, idx, offset, Stripe(COPY_STRIPE));
                idx.0 += COPY_STRIPE;
                if idx.0 >= end {
                    break;
                }
            },
            CopyMode::End => {
                while idx.0 + COPY_STRIPE <= end {
                    copy_stripe_within(buf, idx, offset, Stripe(COPY_STRIPE));
                    idx.0 += COPY_STRIPE;
                }
                for idx in idx.0..end {
                    buf[idx] = buf[idx - offset.0];
                }
            }
        }
    } else {
        short_duplicating_copy(buf, idx, offset, len, mode);
    }
}

// #[cfg(test)]
// mod tests {
//     extern crate test;
//     use test::Bencher;
//     use super::*;

//     #[test]

// }