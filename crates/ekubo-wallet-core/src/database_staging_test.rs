use super::*;
use std::io::Cursor;

#[test]
fn framed_transfer_verifies_readback_and_preserves_next_frame() {
    let bytes = vec![0x55; 100_003];
    let transfer = DatabaseTransfer::describe(&mut bytes.as_slice()).unwrap();
    let mut framed = bytes.clone();
    framed.extend_from_slice(b"next frame");
    let mut input = Cursor::new(framed);
    let mut file = tempfile::tempfile().unwrap();
    receive(&transfer, &mut input, &mut file).unwrap();
    assert_eq!(input.position(), transfer.bytes);
    let mut next = String::new();
    input.read_to_string(&mut next).unwrap();
    assert_eq!(next, "next frame");
    file.seek(SeekFrom::Start(0)).unwrap();
    assert_eq!(DatabaseTransfer::describe(&mut file).unwrap(), transfer);
    assert!(file_name(Uuid::nil()).is_err());
}

#[test]
fn truncated_corrupt_and_empty_transfers_fail() {
    let bytes = vec![0x77; 50_000];
    let expected = DatabaseTransfer::describe(&mut bytes.as_slice()).unwrap();
    for mut input in [&bytes[..0], &bytes[..40_000], &vec![0x66; 50_000][..]] {
        assert!(receive(&expected, &mut input, &mut tempfile::tempfile().unwrap()).is_err());
    }
    let empty = DatabaseTransfer {
        bytes: 0,
        sha256: [0; 32],
    };
    assert!(receive(&empty, &mut &b""[..], &mut tempfile::tempfile().unwrap()).is_err());
    assert!(DatabaseTransfer::describe(&mut &b""[..]).is_err());
}
