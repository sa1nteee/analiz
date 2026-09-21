//! A bounds-checked cursor over untrusted bytes.
//!
//! Every byte handed to the decoder comes off a network and is therefore
//! hostile until proven otherwise. This reader is the single place where the
//! decoder touches raw memory, and it is built so that running off the end of a
//! packet is impossible rather than merely unlikely:
//!
//! * There is no indexing. Every read goes through [`slice::get`], which returns
//!   [`None`] instead of panicking.
//! * Every read returns an [`Option`], so a caller that forgets to handle a
//!   short packet does not compile.
//! * The cursor advances with checked arithmetic, so no offset can wrap.
//!
//! Combined with `unsafe_code = "forbid"` on the crate, this makes
//! out-of-bounds reads a *compile-time* impossibility rather than a promise.

/// A read cursor over a packet.
#[derive(Debug, Clone)]
pub struct ByteReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> ByteReader<'a> {
    /// Starts reading at the beginning of `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    /// How many bytes are left to read.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    /// How many bytes have been consumed so far.
    pub fn position(&self) -> usize {
        self.offset
    }

    /// Whether at least `count` more bytes are available.
    pub fn has(&self, count: usize) -> bool {
        self.remaining() >= count
    }

    /// Reads a fixed-size array, or [`None`] if too few bytes remain.
    pub fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let end = self.offset.checked_add(N)?;
        let slice = self.data.get(self.offset..end)?;
        let value = <[u8; N]>::try_from(slice).ok()?;
        self.offset = end;
        Some(value)
    }

    /// Reads one byte.
    pub fn u8(&mut self) -> Option<u8> {
        let value = *self.data.get(self.offset)?;
        self.offset = self.offset.checked_add(1)?;
        Some(value)
    }

    /// Reads a big-endian `u16`.
    ///
    /// Network byte order is big-endian, so every multi-byte field in every
    /// protocol here is read this way.
    pub fn u16(&mut self) -> Option<u16> {
        self.array::<2>().map(u16::from_be_bytes)
    }

    /// Reads a big-endian `u32`.
    pub fn u32(&mut self) -> Option<u32> {
        self.array::<4>().map(u32::from_be_bytes)
    }

    /// Borrows the next `count` bytes without copying them.
    pub fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(count)?;
        let slice = self.data.get(self.offset..end)?;
        self.offset = end;
        Some(slice)
    }

    /// Skips `count` bytes, failing if that many are not available.
    pub fn skip(&mut self, count: usize) -> Option<()> {
        self.take(count).map(|_| ())
    }

    /// Borrows everything not yet read, consuming the reader.
    pub fn rest(self) -> &'a [u8] {
        self.data.get(self.offset..).unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_fields_in_network_byte_order() {
        let mut reader = ByteReader::new(&[0x08, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x2a]);

        assert_eq!(reader.u16(), Some(0x0800));
        assert_eq!(reader.u32(), Some(0xdead_beef));
        assert_eq!(reader.u8(), Some(0x2a));
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn an_empty_reader_yields_none_for_everything() {
        let mut reader = ByteReader::new(&[]);

        assert_eq!(reader.u8(), None);
        assert_eq!(reader.u16(), None);
        assert_eq!(reader.u32(), None);
        assert_eq!(reader.array::<6>(), None);
        assert_eq!(reader.take(1), None);
        assert_eq!(reader.skip(1), None);
        assert_eq!(reader.remaining(), 0);
        assert!(!reader.has(1));
        assert_eq!(reader.clone().rest(), &[] as &[u8]);
    }

    #[test]
    fn a_read_one_byte_short_fails_without_consuming() {
        let mut reader = ByteReader::new(&[0xff]);

        assert_eq!(reader.u16(), None, "two bytes were not available");
        // The failed read must not have moved the cursor.
        assert_eq!(reader.position(), 0);
        assert_eq!(reader.u8(), Some(0xff));
    }

    #[test]
    fn every_prefix_of_a_packet_is_safe_to_read() {
        // Table-driven: for every possible truncation of a frame, run the same
        // sequence of reads. None of them may panic.
        let frame: Vec<u8> = (0..40u8).collect();

        for length in 0..=frame.len() {
            let prefix = frame.get(..length).unwrap_or(&[]);
            let mut reader = ByteReader::new(prefix);

            let _ = reader.array::<6>();
            let _ = reader.array::<6>();
            let _ = reader.u16();
            let _ = reader.u8();
            let _ = reader.u32();
            let _ = reader.take(9);
            let _ = reader.skip(3);
            assert!(reader.position() <= length);
            assert_eq!(reader.remaining(), length - reader.position());
        }
    }

    #[test]
    fn oversized_requests_cannot_wrap_the_cursor() {
        let mut reader = ByteReader::new(&[1, 2, 3, 4]);

        assert_eq!(reader.take(usize::MAX), None);
        assert_eq!(reader.skip(usize::MAX), None);
        assert_eq!(reader.array::<64>(), None);
        assert_eq!(reader.position(), 0);
    }

    #[test]
    fn take_and_rest_borrow_the_right_windows() {
        let mut reader = ByteReader::new(&[1, 2, 3, 4, 5]);

        assert_eq!(reader.take(2), Some(&[1, 2][..]));
        assert!(reader.has(3));
        assert!(!reader.has(4));
        assert_eq!(reader.rest(), &[3, 4, 5]);
    }
}
