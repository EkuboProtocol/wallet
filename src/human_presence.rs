use async_trait::async_trait;
use thiserror::Error;

/// What the owner is being asked to authorize at the platform prompt.
///
/// Every variant is a moment the private key comes out of the credential
/// store or leaves it for good — plus one that never touches the key:
/// replacing a wallet's policy. The policy is what decides what an agent may
/// sign with nobody watching, so rewriting it grants signing authority even
/// though it reads no key material, and it is authenticated like signing.
/// Nothing else belongs here. Changing a network, saving an alias, importing
/// a token list — none of those grant signing authority, and asking for a
/// fingerprint before each one only teaches the owner to give it without
/// reading. Those are confirmed in the terminal instead; see
/// [`crate::tui::Confirmation`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PresenceRequest {
    SignTransaction { wallet: String },
    SignTypedData { wallet: String },
    SignMessage { wallet: String },
    ExportPrivateKey { wallet: String },
    RemoveWallet { wallet: String },
    ReplacePolicy { wallet: String },
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
        }
    }
}

/// One name, fit for a dialog someone else draws: no control characters, no
/// newlines, and short enough not to push the verb off the end of the line.
fn subject(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
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

#[async_trait]
pub trait HumanPresence: Send + Sync {
    async fn confirm(&self, request: &PresenceRequest) -> Result<(), HumanPresenceError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PlatformHumanPresence;

#[cfg(target_os = "macos")]
#[async_trait]
impl HumanPresence for PlatformHumanPresence {
    async fn confirm(&self, request: &PresenceRequest) -> Result<(), HumanPresenceError> {
        let reason = request.reason();
        tokio::task::spawn_blocking(move || macos::confirm(&reason))
            .await
            .map_err(|error| HumanPresenceError::Backend(error.to_string()))?
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
        use zbus::Connection;
        use zbus_polkit::policykit1::{AuthorityProxy, CheckAuthorizationFlags, Subject};

        const ACTION: &str = "com.ekubo.wallet.human-presence";
        let connection = Connection::system()
            .await
            .map_err(|error| HumanPresenceError::Unavailable(error.to_string()))?;
        let authority = AuthorityProxy::new(&connection)
            .await
            .map_err(|error| HumanPresenceError::Unavailable(error.to_string()))?;
        let actions = authority
            .enumerate_actions("")
            .await
            .map_err(|error| HumanPresenceError::Backend(error.to_string()))?;
        if !actions.iter().any(|action| action.action_id == ACTION) {
            return Err(HumanPresenceError::Unavailable(
                "install contrib/polkit/com.ekubo.wallet.policy under /usr/share/polkit-1/actions"
                    .into(),
            ));
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

#[cfg(test)]
pub(crate) struct TestHumanPresence {
    pub allow: bool,
}

#[cfg(test)]
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
mod tests {
    use super::*;

    #[test]
    fn reasons_read_as_one_sentence_and_carry_no_digest() {
        let reason = PresenceRequest::SignTransaction {
            wallet: "primary".into(),
        }
        .reason();
        assert_eq!(reason, "sign a transaction from wallet primary");
        assert!(!reason.contains("0x"));
        assert_eq!(
            PresenceRequest::RemoveWallet {
                wallet: "primary".into()
            }
            .reason(),
            "delete wallet primary and its private key"
        );
        assert_eq!(
            PresenceRequest::ReplacePolicy {
                wallet: "primary".into()
            }
            .reason(),
            "replace the signing policy for wallet primary"
        );
    }

    #[test]
    fn a_hostile_name_cannot_repaint_the_platform_dialog() {
        let reason = PresenceRequest::SignMessage {
            wallet: format!("evil\n\u{1b}[31m{}", "long".repeat(40)),
        }
        .reason();
        assert!(!reason.contains('\n') && !reason.contains('\u{1b}'));
        assert!(reason.len() < 100);
    }

    #[test]
    fn an_empty_name_still_names_something() {
        assert_eq!(
            PresenceRequest::SignMessage {
                wallet: "   ".into()
            }
            .reason(),
            "sign a message with wallet (unnamed)"
        );
    }
}
