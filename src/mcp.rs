use crate::config::ConfigStore;
use anyhow::{Result, bail};

pub fn serve(_config: ConfigStore) -> Result<()> {
    bail!("MCP services are not initialized yet")
}
