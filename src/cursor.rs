use core::intrinsics::{likely, unlikely};

use super::copy::*;
use super::{Error, Result};

pub const COPY_LITERALS_OVER_LENGTH: usize = 32;
pub const COPY_MATCH_OVER_LENGTH: usize = 32;

pub struct InputCursor<'a> {
    src: &'a [u8],
}

impl InputCursor<'_> {
    pub fn new(src: &[u8]) -> InputCursor {
        InputCursor { src }
    }

    #[inline(always)]
    pub fn advance(&mut self, len: usize) {
        debug_assert!(len <= self.src.len());
        self.src = &self.src[len..];
    }

    #[inline(always)]
    pub fn has(&self, len: usize) -> bool {
        likely(len <= self.src.len())
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        unlikely(self.src.is_empty())
    }

    #[inline(always)]
    pub fn read_u8(&mut self) -> u8 {
        debug_assert!(self.has(1));
        let byte = self.src[0];
        self.advance(1);
        byte
    }

    #[inline(always)]
    pub fn read_u16_le(&mut self) -> u16 {
        debug_assert!(self.has(2));
        let bytes = &self.src[..2];
        let value = u16::from_le_bytes([bytes[0], bytes[1]]);
        self.advance(2);
        value
    }

    #[inline(always)]
    fn read_varint_long(&mut self, mut value: usize) -> Result<usize> {
        loop {
            if self.is_empty() {
                return Err(Error::Truncation);
            }
            let next = self.read_u8() as usize;
            value += next;
            if next != 255 {
                break;
            }
        }
        return Ok(value);
    }

    #[inline(always)]
    pub fn read_varint(&mut self, token: usize, fast: bool) -> Result<usize> {
        let mut value = token;

        if fast {
            let next = self.read_u8() as usize;
            value += next;
            if next != 255 {
                return Ok(value);
            }
        }
        return self.read_varint_long(value);
    }

    #[inline(always)]
    pub fn slice(&self, len: Option<usize>) -> &[u8] {
        match len {
            Some(len) => {
                debug_assert!(self.has(len));
                &self.src[..len]
            }
            None => &self.src,
        }
    }
}

pub struct OutputCursor<'a> {
    dst: &'a mut [u8],
    idx: usize,
}

#[inline(always)]
fn copy_mode(fast: bool) -> CopyMode {
    if fast {
        CopyMode::Fast
    } else {
        CopyMode::End
    }
}

impl OutputCursor<'_> {
    pub fn new(dst: &mut [u8]) -> OutputCursor {
        OutputCursor { dst, idx: 0 }
    }

    #[inline(always)]
    pub fn validate_offset(&self, offset: usize) -> Result<()> {
        if likely(offset <= self.idx) {
            Ok(())
        } else {
            Err(Error::OffsetTooLarge)
        }
    }

    #[inline(always)]
    pub fn has(&self, bytes: usize) -> bool {
        likely(self.idx + bytes <= self.dst.len())
    }

    #[inline(always)]
    pub fn advance(&mut self, len: usize) {
        debug_assert!(self.has(len));
        self.idx += len;
        debug_assert!(self.idx <= self.dst.len());
    }

    #[inline(always)]
    pub fn copy_short_literals(&mut self, src: &mut InputCursor, literal_length: usize) {
        debug_assert!(literal_length <= 32);
        debug_assert!(self.has(32));
        debug_assert!(src.has(32));
        copy_stripe(self.slice(16), src.slice(Some(16)), Stripe(16));
        src.advance(literal_length);
        self.advance(literal_length);
    }

    #[inline(always)]
    pub fn copy_literals(&mut self, src: &mut InputCursor, literal_length: usize, fast: bool) {
        if fast && likely(literal_length <= 32) {
            copy_stripe(&mut self.dst[self.idx..], src.slice(None), Stripe(32));
        } else {
            striped_copy(
                &mut self.dst[self.idx..],
                src.slice(None),
                Len(literal_length),
                Stripe(32),
                copy_mode(fast),
            );
        }
        src.advance(literal_length);
        self.advance(literal_length);
    }

    #[inline(always)]
    pub fn copy_match(&mut self, offset: usize, match_length: usize, fast: bool) {
        debug_assert!(self.validate_offset(offset).is_ok());
        duplicating_copy(
            self.dst,
            Idx(self.idx),
            Offset(offset),
            Len(match_length),
            copy_mode(fast),
        );
        self.advance(match_length);
    }

    #[inline(always)]
    pub fn slice(&mut self, len: usize) -> &mut [u8] {
        debug_assert!(self.has(len));
        &mut self.dst[self.idx..self.idx + len]
    }

    #[inline(always)]
    pub fn copy_short_match(&mut self, offset: usize, match_length: usize) {
        debug_assert!(match_length <= 18);
        copy_stripe_within(self.dst, Idx(self.idx), Offset(offset), Stripe(18));
        self.advance(match_length);
    }

    pub fn written(&self) -> usize {
        self.idx
    }
}
