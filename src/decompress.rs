use std::intrinsics::{likely, unlikely};
use std::marker::PhantomData;

#[derive(PartialEq, Eq, Debug)]
pub enum Lz4Error {
    VarintCorrupted,
    LiteralLengthTooLong,
    OffsetCutShort,
    OffsetTooLarge,
    MatchLengthTooLong,
}

type Lz4Result<T> = Result<T, Lz4Error>;

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum Lz4SequenceState {
    SequenceStart,
    TokenRead,
    LiteralLengthRead,
    LiteralsCopied,
    OffsetRead,
    MatchLengthRead,
    End,
}

struct Lz4Fast;
struct Lz4End;

trait Lz4Mode {
    fn is_fast() -> bool;
}

impl Lz4Mode for Lz4Fast {
    #[inline(always)]
    fn is_fast() -> bool {
        true
    }
}

impl Lz4Mode for Lz4End {
    #[inline(always)]
    fn is_fast() -> bool {
        false
    }
}

#[derive(Debug)]
struct Lz4Sequence<Mode: Lz4Mode> {
    literal_length: usize,
    match_length: usize,
    offset: usize,
    state: Lz4SequenceState,
    _mode: PhantomData<Mode>,
}

impl<Mode: Lz4Mode> Lz4Sequence<Mode> {
    fn new() -> Self {
        Lz4Sequence {
            literal_length: 0,
            match_length: 0,
            offset: 0,
            state: Lz4SequenceState::SequenceStart,
            _mode: PhantomData {},
        }
    }

    #[inline(always)]
    fn to_end(&self, state: Lz4SequenceState) -> Lz4Sequence<Lz4End> {
        Lz4Sequence {
            literal_length: self.literal_length,
            match_length: self.match_length,
            offset: self.offset,
            state,
            _mode: PhantomData {},
        }
    }

    #[inline(always)]
    fn is_fast(&self) -> bool {
        Mode::is_fast()
    }

    #[inline(always)]
    fn check_state(&self, state: Lz4SequenceState) {
        if !self.is_fast() {
            assert_eq!(self.state, state);
        }
    }

    #[inline(always)]
    fn set_state(&mut self, state: Lz4SequenceState) {
        if !self.is_fast() {
            self.state = state;
        }
    }

    // fn set_fast(&mut self) {
    //     self.is_fast() = true;
    // }

    // fn set_slow(&mut self) {
    //     self.is_fast() = false;
    // }
}

const MIN_MATCH: usize = 4;
const LITERAL_TOKEN_MAX: usize = 15;
const MATCH_TOKEN_MAX: usize = LITERAL_TOKEN_MAX + MIN_MATCH;

const TOKEN_BYTES: usize = 1;
const SHORT_LITERAL_LENGTH_BYTES: usize = 0;
const SHORT_LITERAL_BYTES: usize = 16;
const OFFSET_BYTES: usize = 2;
const SHORT_MATCH_LENGTH_BYTES: usize = 0;
const SHORT_MATCH_BYTES: usize = 18;
const COPY_OVER_LENGTH: usize = 16;

const HALF_FAST_LOOP_LEN: usize = 32;
const FAST_LOOP_LEN: usize = 2 * HALF_FAST_LOOP_LEN;

struct InputCursor<'a> {
    src: &'a [u8],
}

impl InputCursor<'_> {
    fn new(src: &[u8]) -> InputCursor {
        InputCursor { src }
    }

    #[inline(always)]
    fn advance(&mut self, len: usize) {
        self.src = &self.src[len..];
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.src.len()
    }

    #[inline(always)]
    fn has(&self, len: usize) -> bool {
        likely(len <= self.len())
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        unlikely(self.src.is_empty())
    }

    #[inline(always)]
    fn read_u8(&mut self) -> u8 {
        let byte = self.src[0];
        self.advance(1);
        byte
    }

    #[inline(always)]
    fn read_u16_le(&mut self) -> u16 {
        let bytes = &self.src[..2];
        let value = u16::from_le_bytes([bytes[0], bytes[1]]);
        self.advance(2);
        value
    }

    #[inline(always)]
    fn peek_u32_le(&self) -> u32 {
        let bytes = &self.src[..4];
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    // When fast we know that we have at least
    #[inline(always)]
    fn read_varint(&mut self, token: usize, fast: bool) -> Lz4Result<usize> {
        let mut value = token;
        if false && fast {
            let value4 = self.peek_u32_le();
            if likely(value4 != 0xFFFFFFFF) {
                let ones = (value4.trailing_ones() >> 3) as usize;
                value += 255 * ones;
                value += self.src[ones] as usize;
                self.advance(ones + 1);
                return Ok(value);
            }
            value += 255 * 4;
            self.advance(4);
        }
        if fast {
            let next = self.read_u8() as usize;
            value += next;
            if next != 255 {
                return Ok(value);
            }
        }
        loop {
            if self.is_empty() {
                return Err(Lz4Error::VarintCorrupted);
            }
            let next = self.read_u8() as usize;
            value += next;
            if next != 255 {
                return Ok(value);
            }
        }
    }

    #[inline(always)]
    fn slice(&self, len: usize) -> &[u8] {
        &self.src[..len]
    }
}

struct OutputCursor<'a> {
    dst: &'a mut [u8],
    idx: usize,
}

#[inline(always)]
fn copy(dst: &mut OutputCursor, src: &mut InputCursor, len: usize) {
    let dst_slice = &mut dst.dst[dst.idx..dst.idx + len];
    let src_slice = src.slice(len);
    dst_slice.copy_from_slice(src_slice);
}

struct From(usize);
struct To(usize);
struct Stripe(usize);
struct Idx(usize);
struct Offset(usize);
struct Len(usize);

#[inline(always)]
fn copy_stripe(dst: &mut [u8], src: &[u8], stripe: Stripe) {
    let dst_stripe = &mut dst[..stripe.0];
    let src_stripe = &src[..stripe.0];
    dst_stripe.copy_from_slice(src_stripe);
}

#[inline(always)]
fn striped_copy(dst: &mut [u8], src: &[u8], len: Len, stripe: Stripe, fast: bool) {
    let mut idx = 0;
    if fast {
        loop {
            let dst_stripe = &mut dst[idx..idx + stripe.0];
            let src_stripe = &src[idx..idx + stripe.0];
            dst_stripe.copy_from_slice(src_stripe);
            idx += stripe.0;
            if idx >= len.0 {
                break;
            }
        }
    } else {
        dst[..len.0].copy_from_slice(&src[..len.0]);
    }
}

#[inline(always)]
fn copy_stripe_within(buf: &mut [u8], from: From, to: To, stripe: Stripe) {
    // assert!(from.0 + stripe.0 <= to.0);
    let (src, dst) = buf.split_at_mut(to.0);
    copy_stripe(dst, &src[from.0..], stripe);
}

#[inline(always)]
fn short_duplicating_copy(buf: &mut [u8], mut idx: Idx, offset: Offset, len: Len, fast: bool) {
    let mut pattern = [0u8; 16];
    let pattern_len = match offset.0 {
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
    if fast {
        loop {
            copy_stripe(&mut buf[idx.0..idx.0+16], &pattern, Stripe(16));
            idx.0 += pattern_len;
            if idx.0 >= end {
                return;
            }
        }
    } else {
        while idx.0 + 16 <= end {
            copy_stripe(&mut buf[idx.0..idx.0+16], &pattern, Stripe(16));
            idx.0 += pattern_len;
        }
        if idx.0 + pattern_len <= end {
            copy_stripe(&mut buf[idx.0..idx.0+pattern_len], &pattern, Stripe(pattern_len));
            idx.0 += pattern_len;
        }
        for i in 0..(end - idx.0) {
            buf[idx.0 + i] = pattern[i];
        }
    }
}

#[inline(always)]
fn duplicating_copy(buf: &mut [u8], mut idx: Idx, offset: Offset, len: Len, fast: bool) {
    const COPY_STRIPE: usize = 16;
    let end = idx.0 + len.0;
    if likely(offset.0 >= COPY_STRIPE) {
        if fast {
            loop {
                copy_stripe_within(buf, From(idx.0 - offset.0), To(idx.0), Stripe(COPY_STRIPE));
                idx.0 += COPY_STRIPE;
                if idx.0 >= end {
                    break;
                }
            }
            return;
        } else {
            while idx.0 + COPY_STRIPE <= end {
                copy_stripe_within(buf, From(idx.0 - offset.0), To(idx.0), Stripe(COPY_STRIPE));
                idx.0 += COPY_STRIPE;
            }
            for idx in idx.0..end {
                buf[idx] = buf[idx - offset.0];
            }
        }
    } else {
        // for idx in idx.0..end {
        //     buf[idx] = buf[idx - offset.0];
        // }
        short_duplicating_copy(buf, idx, offset, len, fast);
    }
}

impl OutputCursor<'_> {
    fn new(dst: &mut [u8]) -> OutputCursor {
        OutputCursor { dst, idx: 0 }
    }

    #[inline(always)]
    fn validate_offset(&self, offset: usize) -> Lz4Result<()> {
        if likely(offset <= self.idx) {
            Ok(())
        } else {
            Err(Lz4Error::OffsetTooLarge)
        }
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.dst.len() - self.idx
    }

    #[inline(always)]
    fn has(&self, bytes: usize) -> bool {
        likely(self.idx + bytes <= self.dst.len())
        // bytes <= self.len()
    }

    #[inline(always)]
    fn advance(&mut self, len: usize) {
        self.idx += len;
        // assert!(self.idx <= self.dst.len());
    }

    #[inline(always)]
    fn copy_literals(&mut self, src: &mut InputCursor, literal_length: usize, fast: bool) {
        if fast && likely(literal_length <= 32) {
            let dst_slice = &mut self.dst[self.idx..self.idx + 32];
            dst_slice.copy_from_slice(src.slice(32));
        } else {
            striped_copy(
                &mut self.dst[self.idx..],
                src.src,
                Len(literal_length),
                Stripe(16),
                fast,
            );
        }
        self.advance(literal_length);
        src.advance(literal_length);
    }

    #[inline(always)]
    fn copy_match_prefix(&mut self, offset: usize, prefix_length: usize)  {
        if likely(offset >= prefix_length) {
            copy_stripe_within(self.dst, From(self.idx - offset), To(self.idx), Stripe(prefix_length));
        // } else {
        //     duplicating_copy(self.dst, Idx(self.idx), Offset(offset), Len(prefix_length), true);
        }
    }

    #[inline(always)]
    fn copy_match(&mut self, offset: usize, match_length: usize, fast: bool) {
        // TODO: Optimize
        if fast {
            // if fast && likely(offset >= 18 && match_length <= 18) {
            //     copy_stripe_within(self.dst, From(self.idx - offset), To(self.idx), Stripe(18));
            // } else {
                duplicating_copy(
                    self.dst,
                    Idx(self.idx),
                    Offset(offset),
                    Len(match_length),
                    true,
                );
            // }
        } else {
            duplicating_copy(
                self.dst,
                Idx(self.idx),
                Offset(offset),
                Len(match_length),
                false,
            );
        }
        // if fast && offset >= 18 && match_length <= 18 {
        //     copy_stripe_within(self.dst, From(self.idx - offset), To(self.idx), Stripe(18));
        // } else {
        // let midx = self.idx - offset;
        // let mslice = midx..midx+match_length;
        // self.dst.copy_within(mslice, self.idx);
        // let _ = fast;
        // for i in 0..match_length {
        //     self.dst[self.idx + i] = self.dst[self.idx + i - offset];
        // }
        // }
        // let _ = fast;
        // for i in 0..match_length {
        //     self.dst[self.idx + i] = self.dst[self.idx + i - offset];
        // }
        self.advance(match_length);
    }

    #[inline(always)]
    fn slice(&mut self, len: usize) -> &mut [u8] {
        &mut self.dst[self.idx..self.idx+len]
    }
}

#[derive(PartialEq, Eq)]
enum Lz4Status {
    Fast,
    End,
}

impl<Mode: Lz4Mode> Lz4Sequence<Mode> {
    #[inline(always)]
    fn read_token(&mut self, src: &mut InputCursor) {
        self.check_state(Lz4SequenceState::SequenceStart);
        // No bounds check because if we were out of bytes we would be in the
        // end state.
        let token = src.read_u8();
        let literal_token = (token >> 4) as usize;
        let match_token = ((token & 0xF) as usize) + MIN_MATCH;

        self.set_state(Lz4SequenceState::TokenRead);
        self.literal_length = literal_token;
        self.match_length = match_token;
    }

    #[inline(always)]
    fn read_literal_length(
        &mut self,
        out: &mut OutputCursor,
        src: &mut InputCursor,
    ) -> Lz4Result<Lz4Status> {
        self.check_state(Lz4SequenceState::TokenRead);
        if self.literal_length != LITERAL_TOKEN_MAX {
            if self.is_fast() {
                // Output doesn't need to be checked - it is checked in read_match_length.
                // We need enough input to get back to this check: literal length + offset
                // + next token + next short literal length.
                copy_stripe(out.slice(16), src.slice(16), Stripe(16));
                src.advance(self.literal_length);
                out.advance(self.literal_length);
                self.set_state(Lz4SequenceState::LiteralsCopied);
                let status = if src.has(FAST_LOOP_LEN) {
                    Lz4Status::Fast
                } else {
                    Lz4Status::End
                };
                return Ok(status);
            }
        } else {
            self.literal_length = src.read_varint(self.literal_length, self.is_fast())?;
        }

        let has = |len| out.has(len) && src.has(len);

        // Need space for the over-copy
        let over_length = self.literal_length + HALF_FAST_LOOP_LEN;
        if self.is_fast() && has(over_length) {
            out.copy_literals(src, self.literal_length, true);
            self.set_state(Lz4SequenceState::LiteralsCopied);
            Ok(Lz4Status::Fast)
        } else {
            if has(self.literal_length) {
                out.copy_literals(src, self.literal_length, false);
                self.set_state(Lz4SequenceState::LiteralsCopied);
                Ok(Lz4Status::End)
            } else {
                Err(Lz4Error::LiteralLengthTooLong)
            }
        }
    }

    #[inline(always)]
    fn copy_literals(&mut self, out: &mut OutputCursor, src: &mut InputCursor) {
        self.check_state(Lz4SequenceState::LiteralLengthRead);
        // Literal length already validated
        out.copy_literals(src, self.literal_length, self.is_fast());
        self.set_state(Lz4SequenceState::LiteralsCopied);
    }

    #[inline(always)]
    fn read_offset(&mut self, out: &OutputCursor, src: &mut InputCursor) -> Lz4Result<()> {
        self.check_state(Lz4SequenceState::LiteralsCopied);
        if !self.is_fast() {
            if src.is_empty() {
                self.set_state(Lz4SequenceState::End);
                return Ok(());
            }
            if !src.has(2) {
                return Err(Lz4Error::OffsetCutShort);
            }
        }
        let offset = src.read_u16_le() as usize;

        out.validate_offset(offset)?;

        self.set_state(Lz4SequenceState::OffsetRead);
        self.offset = offset;
        Ok(())
    }

    #[inline(always)]
    fn read_match_length(
        &mut self,
        out: &mut OutputCursor,
        src: &mut InputCursor,
    ) -> Lz4Result<Lz4Status> {
        self.check_state(Lz4SequenceState::OffsetRead);
        if self.match_length != MATCH_TOKEN_MAX {
            if self.is_fast() {
                if likely(self.offset >= 18) {
                    copy_stripe_within(out.dst, From(out.idx - self.offset), To(out.idx), Stripe(18));
                    out.advance(self.match_length);
                } else {
                    out.copy_match(self.offset, self.match_length, true);
                }
                self.set_state(Lz4SequenceState::SequenceStart);
                let seq = if out.has(FAST_LOOP_LEN) {
                    Lz4Status::Fast
                } else {
                    Lz4Status::End
                };
                return Ok(seq);
            }
        } else {
            self.match_length = src.read_varint(self.match_length, self.is_fast())?;
        };

        if self.is_fast() && out.has(self.match_length + FAST_LOOP_LEN) {
            out.copy_match(self.offset, self.match_length, true);
            self.set_state(Lz4SequenceState::SequenceStart);
            Ok(Lz4Status::Fast)
        } else if out.has(self.match_length) {
            out.copy_match(self.offset, self.match_length, false);
            self.set_state(Lz4SequenceState::SequenceStart);
            Ok(Lz4Status::End)
        } else {
            Err(Lz4Error::MatchLengthTooLong)
        }
    }

    #[inline(always)]
    fn copy_match(&mut self, out: &mut OutputCursor) {
        self.check_state(Lz4SequenceState::MatchLengthRead);
        out.copy_match(self.offset, self.match_length, self.is_fast());
        self.set_state(Lz4SequenceState::SequenceStart);
    }
}

impl Lz4Sequence<Lz4End> {
    fn next(&mut self, out: &mut OutputCursor, src: &mut InputCursor) -> Lz4Result<()> {
        match self.state {
            Lz4SequenceState::SequenceStart => Ok(self.read_token(src)),
            Lz4SequenceState::TokenRead => {
                self.read_literal_length(out, src)?;
                Ok(())
            }
            Lz4SequenceState::LiteralLengthRead => Ok(self.copy_literals(out, src)),
            Lz4SequenceState::LiteralsCopied => self.read_offset(out, src),
            Lz4SequenceState::OffsetRead => {
                self.read_match_length(out, src)?;
                Ok(())
            }
            Lz4SequenceState::MatchLengthRead => Ok(self.copy_match(out)),
            Lz4SequenceState::End => panic!("Logic error!"),
        }
    }
}

type EndLz4Sequence = Lz4Sequence<Lz4End>;
type FastLz4Sequence = Lz4Sequence<Lz4Fast>;

pub fn decompress(dst: &mut [u8], src: &[u8]) -> Lz4Result<usize> {
    let mut end_seq = EndLz4Sequence::new();
    let mut out = OutputCursor::new(dst);
    let mut input = InputCursor::new(src);
    // Fast loop

    // TODO: We shouldn't need this top of loop check.
    // Outer if then loop. Each condition will check cyclically
    if input.has(FAST_LOOP_LEN) && out.has(FAST_LOOP_LEN) {
        loop {
            // Initial state
            let mut fast_seq = FastLz4Sequence::new();

            fast_seq.read_token(&mut input);

            let status = fast_seq.read_literal_length(&mut out, &mut input)?;
            if status == Lz4Status::End {
                end_seq = fast_seq.to_end(Lz4SequenceState::LiteralsCopied);
                break;
            }

            // fast_seq.copy_literals(&mut out, &mut input);

            fast_seq.read_offset(&out, &mut input)?;

            let status = fast_seq.read_match_length(&mut out, &mut input)?;
            // fast_seq.copy_match_prefix(&mut out);
            if status == Lz4Status::End {
                end_seq = fast_seq.to_end(Lz4SequenceState::SequenceStart);
                break;
            }

            // fast_seq.copy_match(&mut out);
        }
    }
    // End loop
    while !matches!(end_seq.state, Lz4SequenceState::End) {
        end_seq.next(&mut out, &mut input)?;
    }

    Ok(out.idx)
}
