use super::*;

struct TestAuthority {
    checks: tokio::sync::mpsc::UnboundedSender<(String, tokio::sync::oneshot::Sender<bool>)>,
    cancellations: tokio::sync::mpsc::UnboundedSender<String>,
}

#[zbus::interface(name = "org.freedesktop.PolicyKit1.Authority")]
impl TestAuthority {
    async fn check_authorization(
        &self,
        subject: Subject,
        action_id: &str,
        details: HashMap<String, String>,
        flags: u32,
        cancellation_id: &str,
    ) -> zbus::fdo::Result<zbus_polkit::policykit1::AuthorizationResult> {
        assert_eq!(subject.subject_kind, "system-bus-name");
        assert_eq!(action_id, crate::polkit::ACTION_ID);
        assert!(details.is_empty()); // this fixture has no service storage
        assert_eq!(flags, 1);
        assert!(!cancellation_id.is_empty());
        let (reply, response) = tokio::sync::oneshot::channel();
        self.checks
            .send((cancellation_id.to_owned(), reply))
            .unwrap();
        Ok(zbus_polkit::policykit1::AuthorizationResult {
            is_authorized: response.await.unwrap_or(false),
            is_challenge: false,
            details: HashMap::new(),
        })
    }

    fn cancel_check_authorization(&self, cancellation_id: &str) {
        self.cancellations.send(cancellation_id.to_owned()).unwrap();
    }
}

/// Tests the production cancellation RPC over a real private bus. This double
/// is NOT evidence of an interactive polkit/PAM authentication success.
#[tokio::test]
#[ignore = "requires dbus-daemon; launches an isolated test bus"]
async fn dropped_authentication_cancels_only_its_own_native_challenge() {
    use std::io::{BufRead as _, BufReader};
    use std::process::{Command, Stdio};
    struct Bus(std::process::Child);
    impl Drop for Bus {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut daemon = Bus(Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address=1"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap());
    let mut address = String::new();
    BufReader::new(daemon.0.stdout.take().unwrap())
        .read_line(&mut address)
        .unwrap();
    let (checks, mut received) = tokio::sync::mpsc::unbounded_channel();
    let (cancellations, mut cancelled) = tokio::sync::mpsc::unbounded_channel();
    let _server = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .name("org.freedesktop.PolicyKit1")
        .unwrap()
        .serve_at(
            "/org/freedesktop/PolicyKit1/Authority",
            TestAuthority {
                checks,
                cancellations,
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();
    let bus = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .build()
        .await
        .unwrap();
    let subject = OwnerCall {
        sender: bus.unique_name().unwrap().clone(),
        bus: bus.clone(),
        owner_uid: rustix::process::geteuid().as_raw(),
    }
    .subject()
    .unwrap();
    let authority = zbus_polkit::policykit1::AuthorityProxy::new(&bus)
        .await
        .unwrap();
    let mut first = Box::pin(check_authorization(authority.clone(), &subject, "first"));
    let (first_id, first_reply) = tokio::select! {
        check = received.recv() => check.unwrap(),
        result = &mut first => panic!("authentication completed before a decision: {result:?}"),
    };
    drop(first);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), cancelled.recv())
            .await
            .unwrap()
            .unwrap(),
        first_id
    );
    // A late success on the abandoned request cannot settle the next request.
    let _ = first_reply.send(true);
    let mut second = Box::pin(check_authorization(authority, &subject, "second"));
    let (second_id, second_reply) = tokio::select! {
        check = received.recv() => check.unwrap(),
        result = &mut second => panic!("replacement consumed a stale approval: {result:?}"),
    };
    assert_ne!(first_id, second_id);
    second_reply.send(false).unwrap();
    assert!(
        !tokio::time::timeout(Duration::from_secs(5), second)
            .await
            .unwrap()
            .unwrap()
            .is_authorized
    );
    assert!(
        cancelled.try_recv().is_err(),
        "completed decision must not cancel another challenge"
    );
}

#[tokio::test]
async fn owner_context_is_required_even_on_a_runtime_thread() {
    assert!(current(1000).is_err());
    assert!(
        tokio::spawn(async { current(1000).is_err() })
            .await
            .unwrap()
    );
}

/// Uses a private bus with no wallet credentials and never invokes polkit or a
/// desktop authentication prompt. The ordinary test process owns all clients.
#[tokio::test]
#[ignore = "requires dbus-daemon; launches an isolated test bus"]
async fn bus_identity_is_live_profile_bound_and_task_local() {
    use std::io::{BufRead as _, BufReader};
    use std::process::{Command, Stdio};
    struct Bus(std::process::Child);
    impl Drop for Bus {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut daemon = Bus(Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address=1"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap());
    let mut address = String::new();
    BufReader::new(daemon.0.stdout.take().unwrap())
        .read_line(&mut address)
        .unwrap();
    let bus = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .build()
        .await
        .unwrap();
    let message = zbus::Message::method_call("/org/ekubo/Wallet", "Call")
        .unwrap()
        .sender(":1.123")
        .unwrap()
        .build(&())
        .unwrap();
    let entered = std::sync::atomic::AtomicBool::new(false);
    let result = with_owner_call(&bus, &message.header(), async {
        entered.store(true, std::sync::atomic::Ordering::SeqCst);
    })
    .await;
    assert!(result.is_err());
    assert!(!entered.load(std::sync::atomic::Ordering::SeqCst));
    let desktop = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .build()
        .await
        .unwrap();
    let uid = rustix::process::geteuid().as_raw();
    let call = OwnerCall {
        bus,
        sender: desktop.unique_name().unwrap().clone(),
        owner_uid: uid,
    };
    call.verify().await.unwrap();
    let mut wrong = call.clone();
    wrong.owner_uid = uid.wrapping_add(1);
    assert!(wrong.verify().await.is_err());
    OWNER_CALL
        .scope(call.clone(), async {
            assert_eq!(current(uid).unwrap().sender, call.sender);
            assert!(current(uid.wrapping_add(1)).is_err());
            assert!(
                tokio::spawn(async move { current(uid).is_err() })
                    .await
                    .unwrap()
            );
            assert_eq!(
                current(uid).unwrap().subject().unwrap().subject_kind,
                "system-bus-name"
            );
        })
        .await;
    assert!(current(uid).is_err());
    assert_cancelled_on_disconnect(&call, async { desktop.clone().close().await.unwrap() }).await;
    assert!(call.verify().await.is_err());
    let entered = std::sync::atomic::AtomicBool::new(false);
    assert!(
        call.execute(async {
            entered.store(true, std::sync::atomic::Ordering::SeqCst);
        })
        .await
        .is_err()
    );
    assert!(!entered.load(std::sync::atomic::Ordering::SeqCst));

    let replacement = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .build()
        .await
        .unwrap();
    let replacement_call = OwnerCall {
        sender: replacement.unique_name().unwrap().clone(),
        ..call
    };
    assert_ne!(&replacement_call.sender, desktop.unique_name().unwrap());
    assert_eq!(replacement_call.execute(async { 42 }).await.unwrap(), 42);
    assert_cancelled_on_disconnect(&replacement_call, async {
        daemon.0.kill().unwrap();
        daemon.0.wait().unwrap();
    })
    .await;
}

async fn assert_cancelled_on_disconnect(call: &OwnerCall, disconnect: impl Future<Output = ()>) {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Reservation<'a>(&'a AtomicBool);
    impl Drop for Reservation<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let released = AtomicBool::new(false);
    let (started, entered) = tokio::sync::oneshot::channel();
    let operation = call.execute(async {
        let _reservation = Reservation(&released);
        assert_eq!(current(call.owner_uid).unwrap().sender, call.sender);
        started.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    let disconnect = async {
        entered.await.unwrap();
        disconnect.await;
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(operation, disconnect)
    })
    .await
    .expect("an abandoned owner operation must be cancelled");
    assert!(matches!(result, Err(HumanPresenceError::Denied(_))));
    assert!(released.load(Ordering::SeqCst));
    assert!(current(call.owner_uid).is_err());
}
