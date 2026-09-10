//! Same-user local IPC listener for resilient stdio MCP bridges.

#![cfg_attr(windows, allow(unsafe_code))]

use crate::mcp_transport::serve_connection;
use crate::{
    authority::AgentApi,
    events::{DomainEventKind, EventBus},
};
use anyhow::{Context, Result, ensure};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub struct McpIpcServer {
    cancel: CancellationToken,
    task: JoinHandle<()>,
    events: EventBus,
    #[cfg(unix)]
    socket_path: PathBuf,
    active: Arc<AtomicUsize>,
}

impl McpIpcServer {
    pub fn start(data_dir: &Path, agent: AgentApi, events: EventBus) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            use tokio::net::UnixListener;

            std::fs::create_dir_all(data_dir)?;
            std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))?;
            let socket_path = data_dir.join("mcp.sock");
            if socket_path.exists() {
                use std::os::unix::fs::FileTypeExt as _;
                ensure!(
                    std::fs::symlink_metadata(&socket_path)?
                        .file_type()
                        .is_socket(),
                    "refusing to replace a non-socket MCP IPC path"
                );
                std::fs::remove_file(&socket_path).context("failed to remove stale MCP socket")?;
            }
            let listener =
                UnixListener::bind(&socket_path).context("failed to bind local MCP socket")?;
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
            let cancel = CancellationToken::new();
            let stopped = cancel.clone();
            let active = Arc::new(AtomicUsize::new(0));
            let connection_count = active.clone();
            let expected_uid = unix_owner(data_dir)?;
            events.publish(DomainEventKind::McpStatusChanged { online: true });
            let listener_events = events.clone();
            let task = tokio::spawn(async move {
                loop {
                    let accepted = tokio::select! { () = stopped.cancelled() => break, accepted = listener.accept() => accepted };
                    let Ok((stream, _)) = accepted else {
                        break;
                    };
                    if stream.peer_cred().ok().map(|credential| credential.uid())
                        != Some(expected_uid)
                    {
                        tracing::warn!("rejected local MCP peer owned by another user");
                        continue;
                    }
                    // An authenticated bridge just connected, so a harness
                    // spawned whatever bytes sit at the shared helper path.
                    // This wallet answers the socket, so those bytes are its
                    // to own; see `reassert_bridge_helper`.
                    tokio::task::spawn_blocking(crate::agent_config::reassert_bridge_helper);
                    let agent = agent.clone();
                    let events = listener_events.clone();
                    let active = connection_count.clone();
                    tokio::spawn(async move {
                        if let Err(error) = serve_connection(stream, agent, active, events).await {
                            tracing::warn!(%error, "local MCP bridge disconnected");
                        }
                    });
                }
            });
            Ok(Self {
                cancel,
                task,
                events,
                socket_path,
                active,
            })
        }
        #[cfg(windows)]
        {
            let pipe_name = windows_pipe_name()?;
            let cancel = CancellationToken::new();
            let stopped = cancel.clone();
            let active = Arc::new(AtomicUsize::new(0));
            let connection_count = active.clone();
            events.publish(DomainEventKind::McpStatusChanged { online: true });
            let listener_events = events.clone();
            let task = tokio::spawn(async move {
                let mut first = true;
                loop {
                    let server = match create_current_user_pipe(&pipe_name, first) {
                        Ok(server) => server,
                        Err(error) => {
                            tracing::error!(%error, "failed to create local MCP named pipe");
                            break;
                        }
                    };
                    first = false;
                    let connected = tokio::select! {
                        _ = stopped.cancelled() => break,
                        connected = server.connect() => connected,
                    };
                    if let Err(error) = connected {
                        tracing::warn!(%error, "failed to accept local MCP named-pipe client");
                        continue;
                    }
                    match windows_peer_is_current_user(&server) {
                        Ok(true) => {}
                        Ok(false) => {
                            tracing::warn!("rejected local MCP peer owned by another user");
                            continue;
                        }
                        Err(error) => {
                            tracing::warn!(%error, "could not authenticate local MCP peer");
                            continue;
                        }
                    }
                    // See the Unix arm: the wallet answering this pipe owns
                    // the bytes at the shared helper path.
                    tokio::task::spawn_blocking(crate::agent_config::reassert_bridge_helper);
                    let agent = agent.clone();
                    let events = listener_events.clone();
                    let active = connection_count.clone();
                    tokio::spawn(async move {
                        if let Err(error) = serve_connection(server, agent, active, events).await {
                            tracing::warn!(%error, "local MCP bridge disconnected");
                        }
                    });
                }
            });
            Ok(Self {
                cancel,
                task,
                events,
                active,
            })
        }
    }

    #[must_use]
    pub fn active_connections(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    pub async fn stop(self) -> Result<()> {
        self.cancel.cancel();
        let _ = self.task.await;
        #[cfg(unix)]
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }
        self.events
            .publish(DomainEventKind::McpStatusChanged { online: false });
        Ok(())
    }
}

#[cfg(unix)]
fn unix_owner(path: &Path) -> Result<u32> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(std::fs::metadata(path)?.uid())
}

#[cfg(windows)]
fn windows_pipe_name() -> Result<String> {
    Ok(format!(
        r"\\.\pipe\ekubo-wallet-mcp-{}",
        current_user_sid_string()?.replace('-', "_")
    ))
}

#[cfg(windows)]
fn current_user_sid_string() -> Result<String> {
    use std::ptr;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, LocalFree},
        Security::{
            Authorization::ConvertSidToStringSidW, GetTokenInformation, TOKEN_QUERY, TOKEN_USER,
            TokenUser,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        ensure!(
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) != 0,
            "could not open current-user token"
        );
        let result = token_sid_string(token);
        CloseHandle(token);
        result
    }
}

#[cfg(windows)]
unsafe fn token_sid_string(token: windows_sys::Win32::Foundation::HANDLE) -> Result<String> {
    use std::ptr;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::ConvertSidToStringSidW, GetTokenInformation, TOKEN_USER, TokenUser,
        },
    };

    let mut size = 0;
    unsafe {
        let _ = GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut size);
    }
    ensure!(size > 0, "could not size user token");
    let mut buffer = vec![0u8; size as usize];
    ensure!(
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        } != 0,
        "could not read user token"
    );
    let sid = unsafe { (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    let mut text = ptr::null_mut();
    ensure!(
        unsafe { ConvertSidToStringSidW(sid, &mut text) } != 0,
        "could not format user SID"
    );
    let length = (0..)
        .take_while(|offset| unsafe { *text.add(*offset) } != 0)
        .count();
    let result = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })?;
    unsafe {
        LocalFree(text.cast());
    }
    Ok(result)
}

#[cfg(windows)]
fn create_current_user_pipe(
    name: &str,
    first: bool,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use std::{mem, ptr};
    use tokio::net::windows::named_pipe::ServerOptions;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            SECURITY_ATTRIBUTES,
        },
    };

    let sddl = format!("D:P(A;;GA;;;{})", current_user_sid_string()?);
    let wide = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    unsafe {
        let mut descriptor = ptr::null_mut();
        ensure!(
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut()
            ) != 0,
            "could not create current-user pipe DACL"
        );
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let mut options = ServerOptions::new();
        options
            .reject_remote_clients(true)
            .first_pipe_instance(first);
        let result = options.create_with_security_attributes_raw(
            name,
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
        );
        LocalFree(descriptor);
        result.context("could not create current-user MCP named pipe")
    }
}

#[cfg(windows)]
fn windows_peer_is_current_user(
    pipe: &tokio::net::windows::named_pipe::NamedPipeServer,
) -> Result<bool> {
    use std::{os::windows::io::AsRawHandle as _, ptr};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE},
        Security::TOKEN_QUERY,
        System::{
            Pipes::GetNamedPipeClientProcessId,
            Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION},
        },
    };

    unsafe {
        let mut process_id = 0;
        ensure!(
            GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut process_id) != 0,
            "could not identify named-pipe peer"
        );
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id);
        ensure!(!process.is_null(), "could not open named-pipe peer process");
        let mut token: HANDLE = ptr::null_mut();
        let opened = OpenProcessToken(process, TOKEN_QUERY, &mut token) != 0;
        CloseHandle(process);
        ensure!(opened, "could not open named-pipe peer token");
        let peer = token_sid_string(token);
        CloseHandle(token);
        Ok(peer? == current_user_sid_string()?)
    }
}
