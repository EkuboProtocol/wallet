use super::*;

#[tokio::test]
async fn abandoned_call_keeps_its_worker_slot_until_the_work_finishes() {
    let worker = TransactionPreviews::default();
    let started = worker.clone();
    let (entered, waiting) = tokio::sync::oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let task = tokio::spawn(async move {
        started
            .run(move || {
                entered.send(()).unwrap();
                blocked.recv().unwrap();
                Ok(())
            })
            .await
    });
    waiting.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let mut queued = std::pin::pin!(worker.run(|| Ok(())));
    assert!(futures::poll!(&mut queued).is_pending());
    release.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), queued)
        .await
        .unwrap()
        .unwrap();
    worker.shutdown();
    assert!(worker.run(|| Ok(())).await.is_err());
}

#[tokio::test]
async fn oversized_batches_fail_before_loading_records_or_the_model() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let error = TransactionPreviews::default()
        .generate(owner, vec![Uuid::new_v4(); 9])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("at most 8"));
}

#[tokio::test]
async fn dropping_a_waiting_request_releases_its_queue_place() {
    let worker = TransactionPreviews::default();
    let slot = worker.slot.acquire().await.unwrap();
    let mut queued = Box::pin(worker.run(|| Ok(())));
    assert!(futures::poll!(&mut queued).is_pending());
    assert_eq!(worker.requests.available_permits(), 15);
    drop(queued);
    assert_eq!(worker.requests.available_permits(), 16);
    drop(slot);
    assert!(worker.run(|| Ok(())).await.is_ok());
}
