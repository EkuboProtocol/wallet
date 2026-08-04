use async_trait::async_trait;
use std::fmt;
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresenceAction {
    ExportPrivateKey,
    ChangePolicy,
    ChangeNetworkConfiguration,
    ApprovePolicyException,
    RemoveWallet,
    SignTypedData,
    ModifyAddressBook,
}

impl fmt::Display for PresenceAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ExportPrivateKey => "export the private key",
            Self::ChangePolicy => "change the wallet policy",
            Self::ChangeNetworkConfiguration => "change the wallet network configuration",
            Self::ApprovePolicyException => "approve a policy exception",
            Self::RemoveWallet => "remove the wallet and its private key",
            Self::SignTypedData => "sign EIP-712 typed data",
            Self::ModifyAddressBook => "modify the address book",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresenceRequest {
    pub action: PresenceAction,
    pub wallet_id: String,
    pub operation_digest: Option<String>,
}

impl PresenceRequest {
    #[must_use]
    pub fn reason(&self) -> String {
        match &self.operation_digest {
            Some(digest) => format!(
                "{} for Ekubo wallet {} (request {})",
                self.action, self.wallet_id, digest
            ),
            None => format!("{} for Ekubo wallet {}", self.action, self.wallet_id),
        }
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
