use async_trait::async_trait;
use std::time::{Duration, Instant};
use thiserror::Error;

const OWNER_AUTHORIZATION_LIFETIME: Duration = Duration::from_mins(2);

/// The class of protected owner state one authentication may change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerAuthorizationScope {
    DappAccess,
    UpdateTrust,
    PolicySettings,
    NetworkSettings,
    NotificationPrivacy,
    TokenMetadata,
}

/// Single-use proof that the owner authenticated the exact dapp review and
/// account which the session boundary is about to settle.
pub struct DappAuthorization {
    owner: OwnerAuthorization,
    review_identity: String,
    account_id: String,
}

impl DappAuthorization {
    /// Consume the proof and bind settlement to a freshly generated review.
    pub fn verify(self, review_identity: &str, account_id: &str) -> Result<(), HumanPresenceError> {
        self.owner.require(OwnerAuthorizationScope::DappAccess)?;
        if self.review_identity != review_identity || self.account_id != account_id {
            return Err(HumanPresenceError::Denied(
                "the dapp proposal or selected account changed after owner authentication".into(),
            ));
        }
        Ok(())
    }
}

/// Authenticate the owner for one exact dapp review. The returned proof is
/// deliberately single-use and can settle only matching, freshly re-read state.
pub async fn authorize_dapp_access(
    review_identity: &str,
    account_id: &str,
) -> Result<DappAuthorization, HumanPresenceError> {
    let owner = authorize_owner(OwnerAuthorizationScope::DappAccess).await?;
    Ok(DappAuthorization {
        owner,
        review_identity: review_identity.to_owned(),
        account_id: account_id.to_owned(),
    })
}

/// Short-lived, scope-bound proof minted only after platform authentication.
///
/// Its fields are private so presentation and transport crates cannot forge
/// it. Core mutation APIs validate both scope and age immediately before they
/// write protected state.
pub struct OwnerAuthorization {
    scope: OwnerAuthorizationScope,
    granted_at: Instant,
}

impl OwnerAuthorization {
    pub(crate) fn require(&self, scope: OwnerAuthorizationScope) -> Result<(), HumanPresenceError> {
        if self.scope != scope {
            return Err(HumanPresenceError::Denied(
                "owner authorization was granted for a different setting".into(),
            ));
        }
        if self.granted_at.elapsed() > OWNER_AUTHORIZATION_LIFETIME {
            return Err(HumanPresenceError::Denied(
                "owner authorization expired before the setting was changed".into(),
            ));
        }
        Ok(())
    }

    #[cfg(any(test, feature = "test-hooks"))]
    #[must_use]
    pub fn for_test(scope: OwnerAuthorizationScope) -> Self {
        Self {
            scope,
            granted_at: Instant::now(),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn expired_for_test(scope: OwnerAuthorizationScope) -> Self {
        Self {
            scope,
            granted_at: Instant::now()
                .checked_sub(OWNER_AUTHORIZATION_LIFETIME + Duration::from_secs(1))
                .expect("the monotonic clock has enough test history"),
        }
    }
}

/// Authenticate the owner for one narrow class of security-sensitive changes.
#[cfg(not(any(test, feature = "test-hooks")))]
pub async fn authorize_owner(
    scope: OwnerAuthorizationScope,
) -> Result<OwnerAuthorization, HumanPresenceError> {
    PlatformHumanPresence
        .confirm(&PresenceRequest::ChangeProtectedSettings { scope })
        .await?;
    Ok(OwnerAuthorization {
        scope,
        granted_at: Instant::now(),
    })
}

#[cfg(any(test, feature = "test-hooks"))]
pub async fn authorize_owner(
    scope: OwnerAuthorizationScope,
) -> Result<OwnerAuthorization, HumanPresenceError> {
    Ok(std::future::ready(OwnerAuthorization::for_test(scope)).await)
}

/// What the owner is being asked to authorize at the platform prompt.
///
/// Every variant either uses private-key material or changes a protected input
/// that can widen unattended authority, redirect network trust, change trusted
/// display metadata, reduce privacy, or install update authority. A policy
/// transition proven to be tightening, disabling an exact reviewed network,
/// and removing an exact reviewed token row are the three fail-safe reductions
/// that deliberately create no request here; their typed core operations still
/// exact-match current state and commit atomically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PresenceRequest {
    SignTransaction { wallet: String },
    SignTypedData { wallet: String },
    SignMessage { wallet: String },
    ExportPrivateKey { wallet: String },
    RemoveWallet { wallet: String },
    ReplacePolicy { wallet: String },
    ConfirmTokenNames { count: usize },
    ConfirmNetwork { network: String },
    ChangeProtectedSettings { scope: OwnerAuthorizationScope },
}

/// How much of a name the platform dialog will carry. The dialog is a single
/// line of prose in a window someone else draws.
const SUBJECT_LIMIT: usize = 48;

impl PresenceRequest {
    /// The sentence the platform dialog completes.
    ///
    /// macOS renders this as "Ekubo Wallet is trying to <reason>", so each
    /// one is a lowercase verb phrase that finishes that sentence, and reads
    /// on its own under Windows Hello and polkit. It says which wallet and
    /// what will happen to it — nothing else. A digest here told the reader
    /// nothing they could check and buried the one clause they could.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::SignTransaction { wallet } => {
                format!("sign a transaction from wallet {}", subject(wallet))
            }
            Self::SignTypedData { wallet } => {
                format!("sign a typed-data request with wallet {}", subject(wallet))
            }
            Self::SignMessage { wallet } => {
                format!("sign a message with wallet {}", subject(wallet))
            }
            Self::ExportPrivateKey { wallet } => {
                format!("reveal the private key for wallet {}", subject(wallet))
            }
            Self::RemoveWallet { wallet } => {
                format!("delete wallet {} and its private key", subject(wallet))
            }
            Self::ReplacePolicy { wallet } => {
                format!("replace the signing policy for wallet {}", subject(wallet))
            }
            Self::ConfirmTokenNames { count } => {
                format!("name {count} token(s) shown when approving transfers")
            }
            Self::ConfirmNetwork { network } => {
                format!("trust the RPC endpoint for network {}", subject(network))
            }
            Self::ChangeProtectedSettings { scope } => match scope {
                OwnerAuthorizationScope::DappAccess => {
                    "approve the dapp connection shown in Ekubo Wallet".into()
                }
                OwnerAuthorizationScope::UpdateTrust => {
                    "install the authenticated application update shown in Ekubo Wallet".into()
                }
                OwnerAuthorizationScope::PolicySettings => {
                    "widen automatic signing policy permissions".into()
                }
                OwnerAuthorizationScope::NetworkSettings => {
                    "change the wallet's trusted network configuration".into()
                }
                OwnerAuthorizationScope::NotificationPrivacy => {
                    "change whether notifications reveal wallet activity".into()
                }
                OwnerAuthorizationScope::TokenMetadata => {
                    "change trusted token names and amount scaling".into()
                }
            },
        }
    }
}

/// One name, fit for a dialog someone else draws: no control characters, no
/// newlines, and short enough not to push the verb off the end of the line.
fn subject(value: &str) -> String {
    let cleaned: String = crate::sanitize::terminal_safe_line(value)
        .chars()
        .take(SUBJECT_LIMIT)
        .collect();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        "(unnamed)".to_owned()
    } else {
        cleaned.to_owned()
    }
}

#[derive(Debug, Error)]
pub enum HumanPresenceError {
    #[error("platform owner authentication is unavailable: {0}")]
    Unavailable(String),
    #[error("the owner did not authorize this operation: {0}")]
    Denied(String),
    #[error("platform owner authentication failed: {0}")]
    Backend(String),
}

/// Proof that the machine's owner is present and consented to one operation.
///
/// Sealed, and of the kernel's two sealed traits this is the one that matters
/// most. Every owner authentication in the process — signing a reviewed
/// message or typed-data payload, exporting a private key, removing a wallet —
/// is exactly one `confirm` call, so an implementation that returns `Ok(())`
/// is not a weak presence check but the absence of every presence check at
/// once. Requiring the kernel-private [`crate::sealed::SealedHumanPresence`]
/// is what stops presentation code writing that four-line impl and handing it
/// to an orchestrator entry point.
#[async_trait]
pub trait HumanPresence: crate::sealed::SealedHumanPresence + Send + Sync {
    async fn confirm(&self, request: &PresenceRequest) -> Result<(), HumanPresenceError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PlatformHumanPresence;

impl crate::sealed::SealedHumanPresence for PlatformHumanPresence {}

#[cfg(any(test, target_os = "macos"))]
async fn run_on_dedicated_thread<T, F>(name: &str, operation: F) -> Result<T, HumanPresenceError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (sender, receiver) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let _ = sender.send(operation());
        })
        .map_err(|error| HumanPresenceError::Backend(error.to_string()))?;
    receiver.await.map_err(|_| {
        HumanPresenceError::Backend("owner-authentication thread exited unexpectedly".into())
    })
}

#[cfg(target_os = "macos")]
#[async_trait]
impl HumanPresence for PlatformHumanPresence {
    async fn confirm(&self, request: &PresenceRequest) -> Result<(), HumanPresenceError> {
        let reason = request.reason();
        run_on_dedicated_thread("ekubo-owner-auth", move || macos::confirm(&reason)).await?
    }
}

#[cfg(target_os = "macos")]
mod macos {
    #![allow(unsafe_code)]

    use super::HumanPresenceError;
    use block2::RcBlock;
    use objc2::{rc::autoreleasepool, runtime::Bool};
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use std::{sync::mpsc, time::Duration};

    pub fn confirm(reason: &str) -> Result<(), HumanPresenceError> {
        autoreleasepool(|_| {
            // SAFETY: LAContext::new returns an owned Objective-C object. All
            // Objective-C values and the callback block remain alive until the
            // callback completes or this operation times out.
            let context = unsafe { LAContext::new() };
            // SAFETY: The policy is a valid LocalAuthentication enum value and
            // the retained context is alive for this call.
            unsafe { context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication) }
                .map_err(|error| HumanPresenceError::Unavailable(error.to_string()))?;

            let reason = NSString::from_str(reason);
            let (sender, receiver) = mpsc::sync_channel(1);
            let reply = RcBlock::new(move |success: Bool, _error: *mut NSError| {
                let _ = sender.send(success.as_bool());
            });

            // SAFETY: `reply` is a heap-copied block with a thread-safe channel
            // sender. The context, NSString, and block outlive the callback.
            unsafe {
                context.evaluatePolicy_localizedReason_reply(
                    LAPolicy::DeviceOwnerAuthentication,
                    &reason,
                    &reply,
                );
            }

            match receiver.recv_timeout(Duration::from_mins(5)) {
                Ok(true) => Ok(()),
                Ok(false) => Err(HumanPresenceError::Denied(
                    "authentication was canceled or rejected".into(),
                )),
                Err(mpsc::RecvTimeoutError::Timeout) => Err(HumanPresenceError::Denied(
                    "authentication timed out".into(),
                )),
                Err(mpsc::RecvTimeoutError::Disconnected) => Err(HumanPresenceError::Backend(
                    "authentication callback disconnected".into(),
                )),
            }
        })
    }
}

#[cfg(target_os = "windows")]
#[async_trait]
impl HumanPresence for PlatformHumanPresence {
    async fn confirm(&self, request: &PresenceRequest) -> Result<(), HumanPresenceError> {
        use windows::{
            Security::Credentials::UI::{
                UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
            },
            core::HSTRING,
        };

        let availability = UserConsentVerifier::CheckAvailabilityAsync()
            .map_err(|error| HumanPresenceError::Backend(error.to_string()))?
            .await
            .map_err(|error| HumanPresenceError::Backend(error.to_string()))?;
        if availability != UserConsentVerifierAvailability::Available {
            return Err(HumanPresenceError::Unavailable(format!(
                "Windows Hello availability was {availability:?}"
            )));
        }

        let result =
            UserConsentVerifier::RequestVerificationAsync(&HSTRING::from(request.reason()))
                .map_err(|error| HumanPresenceError::Backend(error.to_string()))?
                .await
                .map_err(|error| HumanPresenceError::Backend(error.to_string()))?;
        if result == UserConsentVerificationResult::Verified {
            Ok(())
        } else {
            Err(HumanPresenceError::Denied(format!(
                "Windows Hello returned {result:?}"
            )))
        }
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl HumanPresence for PlatformHumanPresence {
    async fn confirm(&self, _request: &PresenceRequest) -> Result<(), HumanPresenceError> {
        use std::collections::HashMap;
        use zbus_polkit::policykit1::{CheckAuthorizationFlags, Subject};

        use crate::polkit::{ACTION_ID as ACTION, Readiness};

        // The same probe the Settings pane runs, so the two never disagree
        // about what a polkit failure is called.
        let authority = crate::polkit::connect().await.map_err(|detail| {
            HumanPresenceError::Unavailable(format!("polkit is not reachable ({detail})"))
        })?;
        match crate::polkit::probe(&authority).await {
            Readiness::Ready => {}
            // The desktop's Settings pane installs the definition through
            // pkexec; this message is what every owner operation shows until
            // someone gets there.
            Readiness::PolicyMissing => {
                return Err(HumanPresenceError::Unavailable(
                    "the wallet's polkit policy is not installed yet; \
                     open Settings → Owner authentication to set it up"
                        .into(),
                ));
            }
            Readiness::Unreachable(detail) => {
                return Err(HumanPresenceError::Unavailable(format!(
                    "polkit is not reachable ({detail})"
                )));
            }
        }

        let subject = Subject::new_for_owner(std::process::id(), None, None)
            .map_err(|error| HumanPresenceError::Backend(error.to_string()))?;
        let result = authority
            .check_authorization(
                &subject,
                ACTION,
                &HashMap::new(),
                CheckAuthorizationFlags::AllowUserInteraction.into(),
                "",
            )
            .await
            .map_err(|error| HumanPresenceError::Backend(error.to_string()))?;
        if result.is_authorized {
            Ok(())
        } else if result
            .details
            .get("polkit.dismissed")
            .is_some_and(|value| !value.is_empty())
        {
            Err(HumanPresenceError::Denied(
                "the polkit prompt was dismissed".into(),
            ))
        } else {
            Err(HumanPresenceError::Denied(
                "polkit did not authorize the operation".into(),
            ))
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
#[async_trait]
impl HumanPresence for PlatformHumanPresence {
    async fn confirm(&self, _request: &PresenceRequest) -> Result<(), HumanPresenceError> {
        Err(HumanPresenceError::Unavailable(
            "this operating system has no owner-authentication backend".into(),
        ))
    }
}

#[cfg(any(test, feature = "test-hooks"))]
pub struct TestHumanPresence {
    pub allow: bool,
}

#[cfg(any(test, feature = "test-hooks"))]
impl crate::sealed::SealedHumanPresence for TestHumanPresence {}

#[cfg(any(test, feature = "test-hooks"))]
#[async_trait]
impl HumanPresence for TestHumanPresence {
    async fn confirm(&self, _request: &PresenceRequest) -> Result<(), HumanPresenceError> {
        if self.allow {
            Ok(())
        } else {
            Err(HumanPresenceError::Denied("test denial".into()))
        }
    }
}

#[cfg(test)]
#[path = "human_presence_test.rs"]
mod tests;
