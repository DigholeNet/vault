// SPDX-License-Identifier: MIT
use std::{fmt::Display, io::Write};

pub struct Buffer {
    space_before: usize,
    // Heap-allocated: several async state machines hold Buffers across await
    // points, and 64KB inline arrays on the stack are a stack-overflow hazard
    // on threads with small stacks (tokio workers, mobile VPN extensions).
    buffer: Box<[u8]>,
    start: usize,
    end: usize,
}

impl Buffer {
    pub fn new(space_before: usize) -> Self {
        Self {
            buffer: vec![0; 65535].into_boxed_slice(),
            space_before,
            start: space_before,
            end: space_before,
        }
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    pub fn clear(&mut self) {
        self.set_start(self.space_before);
        self.set_length(0);
    }

    pub(crate) fn get_start(&self) -> usize {
        self.start
    }

    pub(crate) fn set_start(&mut self, start: usize) {
        self.start = start
    }

    pub fn set_length(&mut self, length: usize) {
        debug_assert!(
            self.start + length <= self.buffer.len(),
            "set_length({length}) overruns the {}-byte backing buffer (start {})",
            self.buffer.len(),
            self.start
        );
        self.end = self.start + length
    }

    pub(crate) fn prepend_byte(&mut self, byte: u8) {
        self.start -= 1;
        self.buffer[self.start] = byte
    }

    pub fn take_prefix(&mut self) -> u8 {
        let byte = self.buffer[self.start];
        self.start += 1;
        byte
    }

    pub fn buffer(&mut self) -> &mut [u8] {
        &mut self.buffer[self.start..]
    }

    pub fn message_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[self.start..self.end]
    }
}

impl Write for Buffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let len = self.len();
        let length = buf.len();
        self.buffer[self.end..self.end + length].clone_from_slice(buf);
        self.set_length(len + length);
        Ok(length)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[self.start..self.end]
    }
}

impl Display for Buffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{:?}", &self.buffer[self.start..self.end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression test for the supernode receive loop: it reuses one Buffer
    // and relies on clear() to reset the cursor that take_prefix/decrypt
    // advanced while handling the previous packet.
    #[test]
    fn clear_resets_cursor() {
        let mut buf = Buffer::new(128);
        buf.set_length(100);
        buf.take_prefix();
        buf.set_start(buf.get_start() + 8);
        assert!(buf.get_start() > 128);
        buf.clear();
        assert_eq!(buf.get_start(), 128);
        assert_eq!(buf.len(), 0);
    }
}
