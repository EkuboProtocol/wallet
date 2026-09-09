//! JavaScript boundary; the execution-plan implementation lives in `no_std` erc8410.
use erc8410::ExecutionPlan;
use wasm_bindgen::prelude::*;

/// Validate a JSON plan and return its normalized JSON. Throws on invalid input.
/// Quantities remain decimal strings, so uint256 values never lose precision.
#[wasm_bindgen(js_name = validateExecutionPlan)]
pub fn validate_execution_plan(json: &str) -> Result<String, JsError> {
    let plan =
        ExecutionPlan::from_json(json).map_err(|error| JsError::new(&format!("{error:#}")))?;
    serde_json::to_string(&plan).map_err(|error| JsError::new(&error.to_string()))
}

/// Validate a JSON plan and return the wallet-compatible 0x-prefixed digest.
#[wasm_bindgen(js_name = executionPlanDigest)]
pub fn execution_plan_digest(json: &str) -> Result<String, JsError> {
    let plan =
        ExecutionPlan::from_json(json).map_err(|error| JsError::new(&format!("{error:#}")))?;
    Ok(format!("{:#x}", plan.digest()))
}
