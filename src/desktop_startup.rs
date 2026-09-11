//! Choose custody before opening any local wallet authority.
use crate::{
    authority::{AgentApi, ApplicationAuthority},
    config::ConfigStore,
    desktop_dapps::DesktopDapps,
    desktop_owner::DesktopOwner,
    events::EventBus,
    walletconnect::{ProposalPresenter, WalletConnectManager},
};
use anyhow::Result;
use std::sync::{Arc, Mutex};

pub(crate) struct LocalServices {
    pub config: ConfigStore,
    pub agent: AgentApi,
    pub events: EventBus,
}

pub(crate) struct DesktopStartup {
    pub owner: DesktopOwner,
    pub dapps: DesktopDapps,
    pub local: Option<LocalServices>,
    pub session: Option<ekubo_wallet_client::desktop_session::DesktopSession>,
}

impl DesktopStartup {
    pub fn open(runtime: &tokio::runtime::Runtime, presenter: ProposalPresenter) -> Result<Self> {
        select(
            installed(),
            || Self::local(presenter),
            || Self::service(runtime),
        )
    }

    fn local(presenter: ProposalPresenter) -> Result<Self> {
        let config = ConfigStore::production()?;
        let authority = ApplicationAuthority::open(config.clone())?;
        let owner = authority.owner_api();
        Ok(Self {
            dapps: DesktopDapps::local(
                owner.clone(),
                Arc::new(Mutex::new(WalletConnectManager::default())),
                presenter,
            ),
            owner: owner.into(),
            local: Some(LocalServices {
                config,
                agent: authority.agent_api(),
                events: authority.events(),
            }),
            session: None,
        })
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    fn service(runtime: &tokio::runtime::Runtime) -> Result<Self> {
        runtime.block_on(async {
            let owner = ekubo_wallet_client::OwnerClient::connect().await?;
            let session = owner.start_desktop_session();
            session.ready().await?;
            Ok(Self {
                dapps: DesktopDapps::service(owner.clone()),
                owner: DesktopOwner::Service(owner),
                local: None,
                session: Some(session),
            })
        })
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn service(_: &tokio::runtime::Runtime) -> Result<Self> {
        anyhow::bail!("service custody is unavailable on this platform")
    }
}

fn installed() -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        Ok(ekubo_wallet_core::service_storage::find_installed_service_identity()?.is_some())
    }
    #[cfg(target_os = "windows")]
    {
        Ok(ekubo_wallet_core::windows_service_config::find_installed_service_identity()?.is_some())
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(false)
    }
}

fn select<T>(
    installed: Result<bool>,
    local: impl FnOnce() -> Result<T>,
    service: impl FnOnce() -> Result<T>,
) -> Result<T> {
    if installed? { service() } else { local() }
}

#[cfg(test)]
#[path = "desktop_startup_test.rs"]
mod tests;
