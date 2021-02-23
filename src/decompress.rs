use super::cursor::{InputCursor, OutputCursor, COPY_LITERALS_OVER_LENGTH, COPY_MATCH_OVER_LENGTH};
use super::{Error, Result};

use core::intrinsics::likely;
use core::marker::PhantomData;

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum Lz4SequenceState {
    SequenceStart,
    TokenRead,
    LiteralsCopied,
    OffsetRead,
    End,
}

struct Lz4Fast;
struct Lz4End;

trait Lz4Mode {
    const IS_FAST: bool;
}

impl Lz4Mode for Lz4Fast {
    const IS_FAST: bool = true;
}

impl Lz4Mode for Lz4End {
    const IS_FAST: bool = false;
}

#[derive(Debug)]
struct Lz4Sequence<Mode: Lz4Mode> {
    literal_length: usize,
    match_length: usize,
    offset: usize,
    state: Lz4SequenceState,
    _mode: PhantomData<Mode>,
}

const MIN_MATCH: usize = 4;
const LITERAL_TOKEN_MAX: usize = 15;
const MATCH_TOKEN_MAX: usize = LITERAL_TOKEN_MAX + MIN_MATCH;

const TOKEN_BYTES: usize = 1;
const SHORT_LITERAL_BYTES: usize = COPY_LITERALS_OVER_LENGTH;
const OFFSET_BYTES: usize = 2;
const SHORT_MATCH_BYTES: usize = COPY_MATCH_OVER_LENGTH;

const FAST_LOOP_LEN: usize = 64;

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

    const USE_STATE: bool = !Mode::IS_FAST || cfg!(debug_assertions);

    #[cfg(debug_assertions)]
    fn check_state_conditions(&self, out: Option<&OutputCursor>, src: &InputCursor) {
        match self.state {
            Lz4SequenceState::SequenceStart => {
                if Mode::IS_FAST {
                    debug_assert!(src.has(TOKEN_BYTES + SHORT_LITERAL_BYTES));
                }
            }
            Lz4SequenceState::TokenRead => {
                let out = out.unwrap();
                debug_assert!(self.literal_length <= LITERAL_TOKEN_MAX);
                debug_assert!(self.match_length <= MATCH_TOKEN_MAX);
                if Mode::IS_FAST {
                    debug_assert!(out.has(SHORT_MATCH_BYTES + SHORT_LITERAL_BYTES));
                    debug_assert!(src.has(SHORT_LITERAL_BYTES));
                }
            }
            Lz4SequenceState::LiteralsCopied => {
                let out = out.unwrap();
                debug_assert!(self.match_length <= MATCH_TOKEN_MAX);
                if Mode::IS_FAST {
                    debug_assert!(out.has(SHORT_MATCH_BYTES));
                    debug_assert!(src.has(OFFSET_BYTES + TOKEN_BYTES + SHORT_LITERAL_BYTES));
                }
            }
            Lz4SequenceState::OffsetRead => {
                let out = out.unwrap();
                debug_assert!(self.match_length <= MATCH_TOKEN_MAX);
                debug_assert!(out.validate_offset(self.offset).is_ok());
                if Mode::IS_FAST {
                    debug_assert!(out.has(SHORT_MATCH_BYTES));
                    debug_assert!(src.has(TOKEN_BYTES + SHORT_LITERAL_BYTES));
                }
            }
            Lz4SequenceState::End => {
                debug_assert!(!Mode::IS_FAST);
                debug_assert!(src.is_empty());
            }
        }
    }

    #[cfg(not(debug_assertions))]
    #[inline(always)]
    fn check_state_conditions(&self, _out: Option<&OutputCursor>, _src: &InputCursor) {}

    #[inline(always)]
    fn check_state(&self, state: Lz4SequenceState, out: Option<&OutputCursor>, src: &InputCursor) {
        if Self::USE_STATE {
            debug_assert_eq!(self.state, state);
        }
        self.check_state_conditions(out, src);
    }

    #[inline(always)]
    fn set_state(&mut self, state: Lz4SequenceState) {
        if Self::USE_STATE {
            self.state = state;
        }
    }
}

#[derive(PartialEq, Eq)]
enum Lz4Status {
    Fast,
    End,
}

impl<Mode: Lz4Mode> Lz4Sequence<Mode> {
    #[inline(always)]
    fn read_token(&mut self, src: &mut InputCursor) -> Result<()> {
        self.check_state(Lz4SequenceState::SequenceStart, None, src);
        if !Mode::IS_FAST && src.is_empty() {
            return Err(Error::Truncation);
        }
        // No bounds check because if we were out of bytes we would be in the
        // end state.
        let token = src.read_u8();
        let literal_token = (token >> 4) as usize;
        let match_token = ((token & 0xF) as usize) + MIN_MATCH;

        self.set_state(Lz4SequenceState::TokenRead);
        self.literal_length = literal_token;
        self.match_length = match_token;
        Ok(())
    }

    #[inline(always)]
    fn read_literal_length(
        &mut self,
        out: &mut OutputCursor,
        src: &mut InputCursor,
    ) -> Result<Lz4Status> {
        self.check_state(Lz4SequenceState::TokenRead, Some(out), src);
        if self.literal_length != LITERAL_TOKEN_MAX {
            if Mode::IS_FAST {
                // Output doesn't need to be checked - it is checked in read_match_length.
                // We need enough input to get back to this check: literal length + offset
                // + next token + next short literal length.
                out.copy_short_literals(src, self.literal_length);
                self.set_state(Lz4SequenceState::LiteralsCopied);
                let status = if src.has(FAST_LOOP_LEN) {
                    Lz4Status::Fast
                } else {
                    Lz4Status::End
                };
                return Ok(status);
            }
        } else {
            self.literal_length = src.read_varint(self.literal_length, Mode::IS_FAST)?;
        }

        let has = |len| out.has(len) && src.has(len);

        // Need space for the over-copy
        let over_length = self.literal_length + FAST_LOOP_LEN;
        if Mode::IS_FAST && has(over_length) {
            out.copy_literals(src, self.literal_length, true);
            self.set_state(Lz4SequenceState::LiteralsCopied);
            Ok(Lz4Status::Fast)
        } else {
            if has(self.literal_length) {
                out.copy_literals(src, self.literal_length, false);
                self.set_state(Lz4SequenceState::LiteralsCopied);
                Ok(Lz4Status::End)
            } else {
                if !src.has(self.literal_length) {
                    Err(Error::Truncation)
                } else {
                    debug_assert!(!out.has(self.literal_length));
                    Err(Error::OutputTooSmall)
                }
            }
        }
    }

    #[inline(always)]
    fn read_offset(&mut self, out: &OutputCursor, src: &mut InputCursor) -> Result<()> {
        self.check_state(Lz4SequenceState::LiteralsCopied, Some(out), src);
        if !Mode::IS_FAST {
            if src.is_empty() {
                self.set_state(Lz4SequenceState::End);
                return Ok(());
            }
            if !src.has(2) {
                return Err(Error::Truncation);
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
    ) -> Result<Lz4Status> {
        self.check_state(Lz4SequenceState::OffsetRead, Some(out), src);
        if self.match_length != MATCH_TOKEN_MAX {
            if Mode::IS_FAST {
                if likely(self.offset >= 18) {
                    out.copy_short_match(self.offset, self.match_length);
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
            self.match_length = src.read_varint(self.match_length, Mode::IS_FAST)?;
        };

        if Mode::IS_FAST && out.has(self.match_length + FAST_LOOP_LEN) {
            out.copy_match(self.offset, self.match_length, true);
            self.set_state(Lz4SequenceState::SequenceStart);
            if src.has(FAST_LOOP_LEN) {
                Ok(Lz4Status::Fast)
            } else {
                Ok(Lz4Status::End)
            }
        } else if out.has(self.match_length) {
            out.copy_match(self.offset, self.match_length, false);
            self.set_state(Lz4SequenceState::SequenceStart);
            Ok(Lz4Status::End)
        } else {
            Err(Error::OutputTooSmall)
        }
    }
}

impl Lz4Sequence<Lz4End> {
    fn next(&mut self, out: &mut OutputCursor, src: &mut InputCursor) -> Result<()> {
        match self.state {
            Lz4SequenceState::SequenceStart => self.read_token(src),
            Lz4SequenceState::TokenRead => self.read_literal_length(out, src).map(|_| ()),
            Lz4SequenceState::LiteralsCopied => self.read_offset(out, src),
            Lz4SequenceState::OffsetRead => self.read_match_length(out, src).map(|_| ()),
            Lz4SequenceState::End => panic!("Logic error!"),
        }
    }
}

type EndLz4Sequence = Lz4Sequence<Lz4End>;
type FastLz4Sequence = Lz4Sequence<Lz4Fast>;

pub fn decompress(dst: &mut [u8], src: &[u8]) -> Result<usize> {
    let mut end_seq = EndLz4Sequence::new();
    let mut out = OutputCursor::new(dst);
    let mut input = InputCursor::new(src);

    // Fast loop
    if input.has(FAST_LOOP_LEN) && out.has(FAST_LOOP_LEN) {
        loop {
            // Initial state
            let mut fast_seq = FastLz4Sequence::new();

            fast_seq.read_token(&mut input)?;

            let status = fast_seq.read_literal_length(&mut out, &mut input)?;
            if status == Lz4Status::End {
                end_seq = fast_seq.to_end(Lz4SequenceState::LiteralsCopied);
                break;
            }

            fast_seq.read_offset(&out, &mut input)?;

            let status = fast_seq.read_match_length(&mut out, &mut input)?;
            if status == Lz4Status::End {
                end_seq = fast_seq.to_end(Lz4SequenceState::SequenceStart);
                break;
            }
        }
    }
    // End loop
    while !matches!(end_seq.state, Lz4SequenceState::End) {
        end_seq.next(&mut out, &mut input)?;
    }

    Ok(out.written())
}
