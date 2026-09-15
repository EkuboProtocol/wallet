use super::*;

#[tokio::test]
async fn absent_or_nested_empty_context_cannot_authenticate() {
    let request = PresenceRequest::SignTransaction {
        wallet: "fixture".into(),
    };
    assert!(confirm(&request).await.is_err());
    scope(None, async {
        assert!(confirm(&request).await.is_err());
    })
    .await;
}

#[tokio::test]
async fn bounded_wire_rejects_desktop_approval_and_oversized_frames() {
    let (mut writer, mut reader) = tokio::io::duplex(16_384);
    writer
        .write_u32(u32::try_from(MAX_FRAME + 1).unwrap())
        .await
        .unwrap();
    assert!(read::<Receipt>(&mut reader).await.is_err());
    let value = serde_json::json!({"nonce":"a".repeat(64),"operation_digest":"b".repeat(64),"approved":true});
    write(&mut writer, &value).await.unwrap();
    assert!(read::<Receipt>(&mut reader).await.is_err());
}

#[test]
fn a_receipt_cannot_cross_a_challenge_or_review() {
    let challenge = Challenge {
        nonce: "a".repeat(64),
        operation_digest: "b".repeat(64),
        reason: "fixture".into(),
    };
    assert!(
        Receipt {
            nonce: "c".repeat(64),
            operation_digest: challenge.operation_digest.clone()
        }
        .verify(&challenge)
        .is_err()
    );
    assert!(
        Receipt {
            nonce: challenge.nonce.clone(),
            operation_digest: "d".repeat(64)
        }
        .verify(&challenge)
        .is_err()
    );
}
