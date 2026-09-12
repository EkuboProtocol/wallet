use super::*;
use std::io::Cursor;

fn checkpoint() -> RecoveryCheckpoint {
    serde_json::from_value(serde_json::json!({
        "version":1,"destination":{"owner":"owner","service":"service","profile":uuid::Uuid::new_v4()},
        "session":uuid::Uuid::new_v4(),"stage":uuid::Uuid::new_v4(),
        "source":{"bytes":1024,"sha256":([0u8;32])},"source_fingerprint":([0u8;32]),
        "canonical":{"bytes":1024,"sha256":([1u8;32])},"relay_digest":([2u8;32])
    })).unwrap()
}

struct Stream {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}
impl Read for Stream {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(b)
    }
}
impl Write for Stream {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.output.write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn confirmation_requires_matching_evidence_and_successful_live_verification() {
    let checkpoint = checkpoint();
    for (matching, verified) in [(true, true), (false, true), (true, false)] {
        let mut input = vec![1];
        input.extend([7; 16]);
        let mut fingerprint = digest(&checkpoint).unwrap();
        if !matching {
            fingerprint[0] ^= 1;
        }
        input.extend(fingerprint);
        input.push(0);
        let mut stream = Stream {
            input: Cursor::new(input),
            output: Vec::new(),
        };
        let mut called = false;
        let result = retain(&mut stream, &checkpoint, || {
            called = true;
            ensure!(verified, "verification failed");
            Ok(())
        });
        assert_eq!(called, matching);
        assert_eq!(result.is_ok(), matching && verified);
        if matching && verified {
            assert_eq!(&stream.output[..8], PREFACE);
            assert_eq!(&stream.output[8..24], &[7; 16]);
            assert_eq!(&stream.output[24..], &fingerprint);
        } else {
            assert!(stream.output.is_empty());
        }
    }
}

#[test]
fn abort_and_malformed_commands_cannot_produce_confirmation() {
    let checkpoint = checkpoint();
    for input in [vec![0], vec![], vec![2], vec![1; 12]] {
        let abort = input == [0];
        let mut stream = Stream {
            input: Cursor::new(input),
            output: Vec::new(),
        };
        assert_eq!(
            retain(&mut stream, &checkpoint, || panic!("must not verify")).is_ok(),
            abort
        );
        assert!(stream.output.is_empty());
    }
}

#[test]
fn client_rejects_missing_or_unrelated_receipts() {
    let checkpoint = checkpoint();
    for input in [Vec::new(), vec![0; 56]] {
        let mut stream = Stream {
            input: Cursor::new(input),
            output: Vec::new(),
        };
        assert!(confirm(&mut stream, &checkpoint).is_err());
        assert_eq!(stream.output.len(), 49);
    }
}

#[test]
fn confirmation_round_trip_retains_channel_until_abort_and_rejects_repeat() {
    use std::{
        net::{TcpListener, TcpStream},
        time::Duration,
    };
    for abort in [true, false] {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut installer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut owner, _) = listener.accept().unwrap();
        for stream in [&owner, &installer] {
            stream
                .set_read_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(15)))
                .unwrap();
        }
        let checkpoint = checkpoint();
        let expected = checkpoint.clone();
        let worker = std::thread::spawn(move || retain(&mut owner, &expected, || Ok(())));
        confirm(&mut installer, &checkpoint).unwrap();
        if abort {
            installer.write_all(&[0]).unwrap();
        } else {
            assert!(confirm(&mut installer, &checkpoint).is_err());
        }
        drop(installer);
        assert_eq!(worker.join().unwrap().is_ok(), abort);
    }
}
