//! Byte-bounded owner reads. Never retains a transfer, accepts serialized state,
//! or exposes a mutator; selectors are resolved against current protected rows.

use crate::authority::OwnerApi;
use anyhow::{Result, ensure};
use ekubo_wallet_client::activity::{OwnerActivityRecord, OwnerActivityReference};
use serde_json::Value;

pub(crate) fn read(owner: &OwnerApi, references: &[OwnerActivityReference]) -> Result<Value> {
    ensure!(
        (1..=1000).contains(&references.len()),
        "activity batches require between 1 and 1000 selectors"
    );
    bounded_batch(references.iter().map(|reference| {
        Ok(match reference {
            OwnerActivityReference::Transaction(id) => {
                OwnerActivityRecord::Transaction(Box::new(owner.transaction(*id)?))
            }
            OwnerActivityReference::Message(id) => {
                OwnerActivityRecord::Message(owner.message(*id)?)
            }
            OwnerActivityReference::TypedData(id) => {
                OwnerActivityRecord::TypedData(owner.typed_data(*id)?)
            }
        })
    }))
}

fn bounded_batch(records: impl Iterator<Item = Result<OwnerActivityRecord>>) -> Result<Value> {
    let mut batch = Vec::new();
    let mut bytes = 2; // Array delimiters; every additional element adds a comma.
    for record in records {
        let value = serde_json::to_value(record?)?;
        let length = serde_json::to_vec(&value)?.len();
        let next = bytes + usize::from(!batch.is_empty()) + length;
        if next > crate::framing::MAX_FRAME_BYTES {
            ensure!(
                !batch.is_empty(),
                "individual activity record exceeds its size limit"
            );
            break;
        }
        batch.push(value);
        bytes = next;
    }
    Ok(Value::Array(batch))
}

#[cfg(test)]
#[path = "owner_activity_batch_test.rs"]
mod tests;
