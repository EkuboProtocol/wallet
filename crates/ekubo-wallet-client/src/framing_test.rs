use super::*;

fn header(length: u32) -> Vec<u8> {
    [
        MAGIC.as_slice(),
        VERSION.to_be_bytes().as_slice(),
        length.to_be_bytes().as_slice(),
    ]
    .concat()
}

#[tokio::test]
async fn fragmented_frames_keep_message_boundaries() {
    let (mut tx, mut rx) = tokio::io::duplex(1);
    let sender = tokio::spawn(async move {
        write_frame(&mut tx, b"first").await.unwrap();
        write_frame(&mut tx, b"second").await.unwrap();
    });
    assert_eq!(read_frame(&mut rx).await.unwrap().unwrap(), b"first");
    assert_eq!(read_frame(&mut rx).await.unwrap().unwrap(), b"second");
    assert!(read_frame(&mut rx).await.unwrap().is_none());
    sender.await.unwrap();
}

#[tokio::test]
async fn incomplete_responses_are_never_clean_disconnects() {
    let mut complete = header(3);
    complete.extend_from_slice(b"abc");
    for end in 1..complete.len() {
        assert_eq!(
            read_frame(&mut &complete[..end]).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}

#[tokio::test]
async fn invalid_lengths_are_rejected_without_reading_the_body() {
    for length in [0, u32::try_from(MAX_FRAME_BYTES + 1).unwrap(), u32::MAX] {
        // Keep the sender open without providing a payload. Reading an
        // unvalidated length would block or allocate attacker-chosen memory.
        let (mut tx, mut rx) = tokio::io::duplex(HEADER_BYTES);
        tx.write_all(&header(length)).await.unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), read_frame(&mut rx))
            .await
            .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
}

#[tokio::test]
async fn incompatible_peers_are_rejected_before_payload_processing() {
    for offset in [0, 7] {
        let mut wire = header(1);
        wire[offset] ^= 1;
        assert_eq!(
            read_frame(&mut wire.as_slice()).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[tokio::test]
async fn invalid_outgoing_frames_write_nothing() {
    for payload in [vec![], vec![0; MAX_FRAME_BYTES + 1]] {
        let mut wire = Vec::new();
        assert_eq!(
            write_frame(&mut wire, &payload).await.unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(wire.is_empty());
    }
}
