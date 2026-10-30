//! Exact WSL 2.6.3 exit-status frame; no guest interop request is dispatchable.
// microsoft/WSL tag 2.6.3: lxinitshared.h and interop::VmModeWorkerThread.
#[derive(Default)]
pub(super) struct ExitStatus {
    bytes: [u8; 16],
    received: usize,
    invalid: bool,
}

impl ExitStatus {
    pub(super) fn push(&mut self, bytes: &[u8]) -> Result<bool, &'static str> {
        if self.invalid || bytes.len() > self.bytes.len() - self.received || self.received == 16 {
            self.invalid = true;
            return Err("invalid_guest_exit_status");
        }
        self.bytes[self.received..self.received + bytes.len()].copy_from_slice(bytes);
        self.received += bytes.len();
        // Message type 9, size 16, first sequence 1. Reject other guest requests
        // before accepting their payload, including Windows process creation.
        for (end, expected) in [(4, 9u32), (8, 16), (12, 1)] {
            if self.received >= end
                && u32::from_le_bytes(self.bytes[end - 4..end].try_into().unwrap()) != expected
            {
                self.invalid = true;
                return Err("invalid_guest_exit_status");
            }
        }
        Ok(self.received == 16)
    }

    pub(super) fn acknowledgement(&self) -> Result<&[u8; 16], &'static str> {
        if self.invalid || self.received != 16 {
            return Err("missing_guest_exit_status");
        }
        // Both directions start at sequence 1; the fixed frame is echoed once.
        Ok(&self.bytes)
    }

    pub(super) fn success(&self) -> Result<(), &'static str> {
        let frame = self.acknowledgement()?;
        if i32::from_le_bytes(frame[12..16].try_into().unwrap()) != 0 {
            return Err("guest_query_failed");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(code: i32) -> [u8; 16] {
        let mut bytes = [0; 16];
        for (index, value) in [9u32, 16, 1, code as u32].iter().enumerate() {
            bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn fragmented_exit_is_acknowledged_once_and_never_inferred_from_stdout() {
        let bytes = frame(0);
        for split in 0..=16 {
            let mut exit = ExitStatus::default();
            assert!(exit.success().is_err());
            if split != 0 {
                assert_eq!(exit.push(&bytes[..split]).unwrap(), split == 16);
            }
            if split != 16 {
                assert!(exit.acknowledgement().is_err());
                assert!(exit.push(&bytes[split..]).unwrap());
            }
            assert_eq!(exit.acknowledgement().unwrap(), &bytes);
            assert!(exit.success().is_ok());
            assert!(exit.push(&bytes).is_err());
        }
        let mut exit = ExitStatus::default();
        for (index, byte) in bytes.iter().enumerate() {
            assert_eq!(exit.push(&[*byte]).unwrap(), index == 15);
        }
        assert!(exit.success().is_ok());
    }

    #[test]
    fn malformed_truncated_oversized_or_interop_frames_are_refused() {
        for (word, value) in [(0, 8u32), (0, 0), (1, 15), (1, u32::MAX), (2, 0), (2, 2)] {
            let mut bytes = frame(0);
            bytes[word * 4..word * 4 + 4].copy_from_slice(&value.to_le_bytes());
            let mut exit = ExitStatus::default();
            assert!(exit.push(&bytes).is_err());
            assert!(exit.acknowledgement().is_err());
            assert!(exit.success().is_err());
            assert!(exit.push(&frame(0)).is_err());
        }
        for length in 0..16 {
            let mut exit = ExitStatus::default();
            assert!(!exit.push(&frame(0)[..length]).unwrap());
            assert!(exit.success().is_err());
        }
        assert!(ExitStatus::default().push(&[0; 17]).is_err());
        assert!(
            ExitStatus::default()
                .push(b"data:image/png;base64,AAAA")
                .is_err()
        );
    }

    #[test]
    fn unsuccessful_guest_exit_never_publishes_an_apparently_valid_snapshot() {
        for code in [1, 2, 127, -1, i32::MIN, i32::MAX] {
            let mut exit = ExitStatus::default();
            assert!(exit.push(&frame(code)).unwrap());
            assert!(exit.acknowledgement().is_ok());
            assert_eq!(exit.success(), Err("guest_query_failed"));
        }
    }
}
