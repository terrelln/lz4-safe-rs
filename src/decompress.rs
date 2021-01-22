// TODO: short offsets

#[derive(PartialEq, Eq, Debug)]
pub enum Lz4Error {
    VarintCorrupted,
    LiteralLengthTooLong,
    OffsetCutShort,
    OffsetTooLarge,
    MatchLengthTooLong,
}

type Lz4Result<T> = Result<T, Lz4Error>;

#[derive(PartialEq, Eq, Debug)]
enum Lz4SequenceState {
    SequenceStart,
    TokenRead,
    LiteralLengthRead,
    LiteralsCopied,
    OffsetRead,
    MatchLengthRead,
    End,
}

#[derive(Debug)]
struct Lz4Sequence {
    literal_length: usize,
    match_length: usize,
    offset: usize,
    state: Lz4SequenceState,
    fast: bool,
}

impl Lz4Sequence {
    fn new(fast: bool) -> Lz4Sequence {
        Lz4Sequence {
            literal_length: 0,
            match_length: 0,
            offset: 0,
            state: Lz4SequenceState::SequenceStart,
            fast,
        }
    }

    fn is_fast(&self) -> bool {
        self.fast
    }

    // fn set_fast(&mut self) {
    //     self.fast = true;
    // }

    // fn set_slow(&mut self) {
    //     self.fast = false;
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

const MATCH_LENGTH_READ_REMAINING: usize = SHORT_MATCH_BYTES;
const OFFSET_READ_REMAINING: usize = MATCH_LENGTH_READ_REMAINING + SHORT_MATCH_LENGTH_BYTES;
const LITERALS_COPID_REMAINING: usize = OFFSET_READ_REMAINING + OFFSET_BYTES;
const LITERAL_LENGTH_READ_REMAINING: usize = LITERALS_COPID_REMAINING + SHORT_LITERAL_BYTES;
const TOKEN_READ_REMAINING: usize = LITERAL_LENGTH_READ_REMAINING + SHORT_LITERAL_LENGTH_BYTES;
const SEQUENCE_START_REMAINING: usize = TOKEN_READ_REMAINING + TOKEN_BYTES;

struct InputCursor<'a> {
    src: &'a [u8],
    idx: usize,
}

impl InputCursor<'_> {
    fn new(src: &[u8]) -> InputCursor {
        InputCursor { src, idx: 0 }
    }

    fn advance(&mut self, len: usize) {
        self.idx += len;
        // assert!(self.idx <= self.src.len());
    }

    fn len(&self) -> usize { self.src.len() - self.idx }

    fn is_empty(&self) -> bool { self.idx == self.src.len() }

    fn read_u8(&mut self) -> u8 {
        let byte = self.src[self.idx];
        self.idx += 1;
        byte
    }

    fn read_u16_le(&mut self) -> u16 {
        let byte0 = self.src[self.idx] as u16;
        let byte1 = self.src[self.idx+1] as u16;
        self.idx += 2;
        byte0 | (byte1 << 8)
    }

    fn read_varint(&mut self, token: usize) -> Lz4Result<usize> {
        let mut value = token;
        loop {
            if self.is_empty() {
                return Lz4Result::Err(Lz4Error::VarintCorrupted);
            }
            let next = self.read_u8() as usize;
            value += next;
            if next < 255 {
                break;
            }
        }
        Lz4Result::Ok(value)
    }
}

struct OutputCursor<'a> {
    dst: &'a mut [u8],
    idx: usize,
}

#[inline(always)]
fn copy(dst: &mut OutputCursor, src: &mut InputCursor, len: usize) {
    let dst_slice = &mut dst.dst[dst.idx..dst.idx+len];
    let src_slice = &src.src[src.idx..src.idx+len];
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

fn striped_copy(dst: &mut [u8], src: &[u8], len: Len, stripe: Stripe, fast: bool) {
    let mut idx = 0;
    if fast {
        loop {
            let dst_stripe = &mut dst[idx..idx+stripe.0];
            let src_stripe = &src[idx..idx+stripe.0];
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
    // let (src, dst) = buf.split_at_mut(to.0);
    // copy_stripe(dst, &src[from.0..], stripe);
    let from_slice = from.0..from.0+stripe.0;
    buf.copy_within(from_slice, to.0);
}

#[inline(always)]
fn duplicating_copy(buf: &mut [u8], mut idx: Idx, offset: Offset, len: Len, fast: bool) {
    const COPY_STRIPE: usize = 16;
    let end = idx.0 + len.0;
    if offset.0 >= COPY_STRIPE {
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
            while idx.0 + COPY_STRIPE < end {
                copy_stripe_within(buf, From(idx.0 - offset.0), To(idx.0), Stripe(COPY_STRIPE));
                idx.0 += COPY_STRIPE;
            }
            // for idx in idx.0..end {
            //     buf[idx] = buf[idx - offset.0];
            // }
        }
    }
    // TODO: Optimize short offsets
    for idx in idx.0..end {
        buf[idx] = buf[idx - offset.0];
    }
}

impl OutputCursor<'_> {
    fn new(dst: &mut [u8]) -> OutputCursor {
        OutputCursor { dst, idx: 0 }
    }

    #[inline(always)]
    fn validate_offset(&self, offset: usize) -> Lz4Result<()> {
        if offset <= self.idx {
            Lz4Result::Ok(())
        } else {
            Lz4Result::Err(Lz4Error::OffsetTooLarge)
        }
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.dst.len() - self.idx
    }

    #[inline(always)]
    fn has(&self, bytes: usize) -> bool {
        self.idx + bytes <= self.dst.len()
    }

    #[inline(always)]
    fn advance(&mut self, len: usize) {
        self.idx += len;
        // assert!(self.idx <= self.dst.len());
    }

    #[inline(always)]
    fn copy_literals(&mut self, src: &mut InputCursor, literal_length: usize, fast: bool) {
        if fast && literal_length <= 32 {
            let dst_slice = &mut self.dst[self.idx..self.idx + 32];
            let src_slice = &src.src[src.idx..src.idx + 32];
            dst_slice.copy_from_slice(src_slice);
        } else {
            striped_copy(&mut self.dst[self.idx..], &src.src[src.idx..], Len(literal_length), Stripe(16), fast);
        }
        // if fast {
        //     // striped_over_copy(dst: &mut [u8], src: &[u8], len: Len, stripe: Stripe, fast: bool)
        //     // if literal_length <= 16 {
        //     //     copy(self, src, 16);
        //     // }
        // } else {

        // }
        // if fast && literal_length <= 16 {
        //     // copy_stripe(&mut self.dst[self.idx..self.idx+16], &src.src[src.idx..src.idx+16], Stripe(16))
        // } else {
        //     copy(self, src, literal_length);
        // }
        self.advance(literal_length);
        src.advance(literal_length);
    }

    #[inline(always)]
    fn copy_match(&mut self, offset: usize, match_length: usize, fast: bool) {
        // TODO: Optimize
        if fast {
            if fast && offset >= 18 && match_length <= 18 {
                copy_stripe_within(self.dst, From(self.idx - offset), To(self.idx), Stripe(18));
            } else {
                duplicating_copy(self.dst, Idx(self.idx), Offset(offset), Len(match_length), true);
            }
        } else {
            duplicating_copy(self.dst, Idx(self.idx), Offset(offset), Len(match_length), false);
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
}

impl Lz4Sequence {
    #[inline(always)]
    fn read_token(&mut self, src: &mut InputCursor) -> Lz4Result<()> {
        assert_eq!(self.state, Lz4SequenceState::SequenceStart);
        // No bounds check because if we were out of bytes we would be in the
        // end state.
        let token = src.read_u8();
        let literal_token = (token >> 4) as usize;
        let match_token = ((token & 0xF) as usize) + MIN_MATCH;

        self.state = Lz4SequenceState::TokenRead;
        self.literal_length = literal_token;
        self.match_length = match_token;

        Lz4Result::Ok(())
    }

    #[inline(always)]
    fn read_literal_length(&mut self, out: &OutputCursor, src: &mut InputCursor) -> Lz4Result<()> {
        assert_eq!(self.state, Lz4SequenceState::TokenRead);
        if self.literal_length != LITERAL_TOKEN_MAX {
            if self.fast {
                self.state = Lz4SequenceState::LiteralLengthRead;
                return Lz4Result::Ok(());
            }
        } else {
            self.literal_length = src.read_varint(self.literal_length)?;
        }

        let has = |len| out.has(len) && len <= src.len();

        let over_length = self.literal_length + LITERALS_COPID_REMAINING;
        if self.fast && has(over_length) {
            self.state = Lz4SequenceState::LiteralLengthRead;
            Lz4Result::Ok(())
        } else {
            self.fast = false;
            if has(self.literal_length) {
                self.state = Lz4SequenceState::LiteralLengthRead;
                Lz4Result::Ok(())
            } else {
                Lz4Result::Err(Lz4Error::LiteralLengthTooLong)
            }
        }
    }

    #[inline(always)]
    fn copy_literals(&mut self, out: &mut OutputCursor, src: &mut InputCursor) -> Lz4Result<()> {
        assert_eq!(self.state, Lz4SequenceState::LiteralLengthRead);
        // Literal length already validated
        out.copy_literals(src, self.literal_length, self.fast);
        self.state = Lz4SequenceState::LiteralsCopied;
        Lz4Result::Ok(())
    }

    #[inline(always)]
    fn read_offset(&mut self, out: &OutputCursor, src: &mut InputCursor) -> Lz4Result<()> {
        assert_eq!(self.state, Lz4SequenceState::LiteralsCopied);
        if !self.fast {
            if src.is_empty() {
                self.state = Lz4SequenceState::End;
                return Lz4Result::Ok(());
            }
            if src.len() < 2 {
                return Lz4Result::Err(Lz4Error::OffsetCutShort);
            }
        }
        let offset = src.read_u16_le() as usize;

        out.validate_offset(offset)?;

        self.state = Lz4SequenceState::OffsetRead;
        self.offset = offset;
        Lz4Result::Ok(())
    }

    #[inline(always)]
    fn read_match_length(&mut self, out: &OutputCursor, src: &mut InputCursor) -> Lz4Result<()> {
        assert_eq!(self.state, Lz4SequenceState::OffsetRead);
        if self.match_length != MATCH_TOKEN_MAX {
            if self.fast {
                // No need for validation
                self.state = Lz4SequenceState::MatchLengthRead;
                return Lz4Result::Ok(());
            }
        } else {
            self.match_length = src.read_varint(self.match_length)?;
        };

        if self.fast && out.has(self.match_length + COPY_OVER_LENGTH) {
            self.state = Lz4SequenceState::MatchLengthRead;
            Lz4Result::Ok(())
        } else if out.has(self.match_length) {
            self.state = Lz4SequenceState::MatchLengthRead;
            self.fast = false;
            Lz4Result::Ok(())
        } else {
            Lz4Result::Err(Lz4Error::MatchLengthTooLong)
        }
    }

    #[inline(always)]
    fn copy_match(&mut self, out: &mut OutputCursor) -> Lz4Result<()> {
        assert_eq!(self.state, Lz4SequenceState::MatchLengthRead);
        out.copy_match(self.offset, self.match_length, self.fast);
        self.state = Lz4SequenceState::SequenceStart;
        Lz4Result::Ok(())
        // TODO: Do we want to not require the end of block condition?
    }

    fn next(&mut self, out: &mut OutputCursor, src: &mut InputCursor) -> Lz4Result<()> {
        match self.state {
            Lz4SequenceState::SequenceStart => self.read_token(src),
            Lz4SequenceState::TokenRead => self.read_literal_length(out, src),
            Lz4SequenceState::LiteralLengthRead => self.copy_literals(out, src),
            Lz4SequenceState::LiteralsCopied => self.read_offset(out, src),
            Lz4SequenceState::OffsetRead => self.read_match_length(out, src),
            Lz4SequenceState::MatchLengthRead => self.copy_match(out),
            Lz4SequenceState::End => panic!("Logic error!"),
        }
    }
}

pub fn decompress(dst: &mut [u8], src: &[u8]) -> Lz4Result<usize> {
    let mut seq = Lz4Sequence::new(false);
    let mut out = OutputCursor::new(dst);
    let mut input = InputCursor::new(src);
    // Fast loop

    // TODO: We shouldn't need this top of loop check.
    // Outer if then loop. Each condition will check cyclically
    while input.len() >= SEQUENCE_START_REMAINING && out.has(SEQUENCE_START_REMAINING) {
        // Initial state
        seq = Lz4Sequence::new(true);
        assert!(seq.is_fast());

        seq.read_token(&mut input)?;
        assert!(seq.is_fast());

        seq.read_literal_length(&out, &mut input)?;
        if !seq.is_fast() {
            break;
        }

        seq.copy_literals(&mut out, &mut input)?;
        assert!(seq.is_fast());

        seq.read_offset(&out, &mut input)?;
        assert!(seq.is_fast());

        seq.read_match_length(&out, &mut input)?;
        if !seq.is_fast() {
            break;
        }

        seq.copy_match(&mut out)?;
        assert!(seq.is_fast());
    }
    // End loop
    seq.fast = false;
    while !matches!(seq.state, Lz4SequenceState::End) {
        seq.next(&mut out, &mut input)?;
    }

    Lz4Result::Ok(out.idx)
}

#[cfg(test)]
mod tests {
    use super::*;
}
