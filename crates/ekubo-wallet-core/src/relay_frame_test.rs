use super::*;

#[tokio::test]
async fn relay_frames_preserve_the_maximum_payload() {
    let (mut output, mut input) = tokio::io::duplex(MAX_BYTES + 4);
    let bytes = vec![0x44; MAX_BYTES];
    write_frame(&mut output, &bytes).await.unwrap();
    assert_eq!(read_frame(&mut input).await.unwrap(), bytes);
}

#[tokio::test]
async fn invalid_lengths_stop_before_consuming_payload_and_truncation_fails() {
    for length in [0u32, 4097, u32::MAX] {
        let mut bytes = length.to_le_bytes().to_vec();
        bytes.extend_from_slice(b"retained");
        let mut input = bytes.as_slice();
        assert!(read_frame(&mut input).await.is_err());
        assert_eq!(input, b"retained");
    }
    let mut truncated = &[2, 0, 0, 0, 1][..];
    assert!(read_frame(&mut truncated).await.is_err());
    assert!(write_frame(&mut tokio::io::sink(), &[]).await.is_err());
    assert!(
        write_frame(&mut tokio::io::sink(), &vec![0; MAX_BYTES + 1])
            .await
            .is_err()
    );
}
