# JavaScript / WebAssembly

This thin adapter exposes the `no_std` `erc8410` library through wasm-bindgen.
The adapter uses Rust's standard Wasm allocator/runtime. The core crate itself
does not require `std`.

From the repository root, install the Rust Wasm target and wasm-pack, then build:

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack --locked
wasm-pack build crates/erc8410-wasm --target web --out-dir pkg
```

This produces the Wasm binary, JavaScript loader, TypeScript declarations, and
package metadata in `crates/erc8410-wasm/pkg`. Serve these files with your app:

```js
import init, {
  validateExecutionPlan,
  executionPlanDigest,
} from "./pkg/erc8410_wasm.js";

await init();
const json = JSON.stringify(plan);
const validated = JSON.parse(validateExecutionPlan(json));
const digest = executionPlanDigest(json);
```

Both functions validate the plan and throw a JavaScript Error on invalid input.
The API takes JSON strings and returns strings. Keep uint256 quantities as
decimal strings and addresses/calldata as hex strings; no conversion to
JavaScript Number is needed. `validateExecutionPlan` returns normalized JSON.
The digest is the wallet's approval identity; see the core crate README for
its scope.

For a bundler, use `--target bundler`. For Node and the smoke test:

```sh
wasm-pack build crates/erc8410-wasm --target nodejs --out-dir pkg-node
node crates/erc8410-wasm/smoke-test.cjs
```

Generated packages are local build artifacts; publishing is a separate step.
