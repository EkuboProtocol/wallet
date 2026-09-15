use super::*;

#[tokio::test]
async fn greeting_and_body_preserve_the_exact_instance_and_json_bytes() {
    let (mut writer, mut reader) = tokio::io::duplex(256);
    let instance = uuid::Uuid::new_v4();
    write(&mut writer, Kind::Hello, instance.as_bytes())
        .await
        .unwrap();
    assert_eq!(read_hello(&mut reader).await.unwrap(), instance);
    write(&mut writer, Kind::Ok, br#"{"value":"exact"}"#)
        .await
        .unwrap();
    let frame = read(&mut reader).await.unwrap().unwrap();
    assert_eq!(frame.kind, Kind::Ok);
    assert_eq!(frame.body(), br#"{"value":"exact"}"#);
}

#[tokio::test]
async fn rejects_invalid_tags_and_invalid_service_greetings() {
    for bytes in [
        vec![99],
        vec![Kind::Hello as u8],
        vec![Kind::Hello as u8; 18],
        [vec![Kind::Hello as u8], vec![0; 16]].concat(),
        vec![Kind::Ok as u8],
    ] {
        let (mut writer, mut reader) = tokio::io::duplex(128);
        crate::framing::write_frame(&mut writer, &bytes)
            .await
            .unwrap();
        assert!(read_hello(&mut reader).await.is_err());
    }
}
