const assert = require("node:assert/strict");
const { validateExecutionPlan, executionPlanDigest } = require("./pkg-node/erc8410_wasm.js");

const sender = "0x1111111111111111111111111111111111111111";
const plan = {
  schema_version: "1",
  chain_id: "1",
  caip2_chain_id: "eip155:1",
  sender,
  ordered_steps: [{
    step: 1,
    kind: "execution",
    transaction: {
      chain_id: "1",
      from: sender,
      to: "0x2222222222222222222222222222222222222222",
      data: "0x",
      value: "0",
    },
  }],
};
const json = JSON.stringify(plan);
assert.deepEqual(JSON.parse(validateExecutionPlan(json)), plan);
assert.equal(executionPlanDigest(json),
  "0x93aeec006e55dfe0f54041d53c94387e08c504d4f3b3826cd3426dbc7da38ea5");
plan.ordered_steps[0].transaction.value = (2n ** 256n - 1n).toString();
assert.equal(JSON.parse(validateExecutionPlan(JSON.stringify(plan)))
  .ordered_steps[0].transaction.value, plan.ordered_steps[0].transaction.value);
plan.ordered_steps[0].transaction.value = (2n ** 256n).toString();
assert.throws(() => validateExecutionPlan(JSON.stringify(plan)), /uint256/);
assert.throws(() => executionPlanDigest(JSON.stringify(plan)), /uint256/);
assert.throws(() => validateExecutionPlan("{"), /invalid execution plan/);
assert.throws(() => executionPlanDigest("{}"), /invalid execution plan/);
assert.throws(() => validateExecutionPlan(" ".repeat(16 * 1024 * 1024 + 1)), /serialized bytes/);
console.log("ERC-8410 JavaScript smoke tests passed");
