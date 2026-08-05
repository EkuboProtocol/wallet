# First use

Accept the legal documents, then create a wallet from your own terminal:

```sh
ekubo-wallet legal show terms      # or: privacy, licenses
ekubo-wallet legal accept          # separate terms + privacy acknowledgments
ekubo-wallet wallet create primary
ekubo-wallet wallet list
ekubo-wallet policy show primary
```

Every MCP tool except `wallet_get_legal` is disabled until the current Terms
of Service are accepted and the Privacy Policy is separately acknowledged.
Acceptance binds the exact document digests, so a release that changes a
document (including its generated list of default RPC endpoints) requires
re-acceptance before the wallet works again. An agent can read the documents
and acceptance state, but only the interactive CLI can accept them.

Every wallet starts under a policy, chosen when the key is created rather than
assumed and corrected afterwards:

- `wallet create` asks which policy to start under, with the cursor on
  require-approval, and installs the answer. `--policy require-approval` or
  `--policy allow-all` answers it without the prompt; a non-interactive run
  with no flag takes require-approval, because a run with nobody to ask is not
  a run that should quietly enable automatic signing. The choice is made
  before the key is generated, so backing out leaves no wallet behind.
- `wallet import` brings in a key that usually already controls funds, so it
  installs the require-approval policy outright: nothing signs automatically
  until you deliberately choose otherwise.

Both profiles are one command to install at any time, and every transaction
under the require-approval profile still runs the full simulation and decoded
review before you approve it in the terminal:

```sh
ekubo-wallet policy require-approval primary   # every transaction needs explicit CLI approval
ekubo-wallet policy allow-all primary          # simulated + policy-clean transactions sign automatically
ekubo-wallet policy validate ./policy.json     # or draft something in between
ekubo-wallet policy set primary ./policy.json
ekubo-wallet policy review primary             # review an agent-proposed policy change
```

Agents can propose policy changes with the `wallet_propose_policy` tool
(guided by the `wallet://docs/policy-authoring` and `wallet://schemas/policy`
resources), but only `policy review` applies one: it shows a minimized
human-readable diff of the permissions against the current policy together
with the agent's rationale, requires terminal approval plus OS owner
authentication, and fails closed if the policy changed since the proposal was
written.

Policy changes, exceptional approvals, network changes, key export, and wallet
removal require an interactive terminal and OS-backed owner authentication.
On Linux, first install the polkit action shipped in the archive:

```sh
sudo install -m 0644 contrib/polkit/com.ekubo.wallet.policy \
  /usr/share/polkit-1/actions/com.ekubo.wallet.policy
```

Linux also needs a working Secret Service provider for credential storage. If
polkit, Windows Hello, or macOS Local Authentication is unavailable, sensitive
operations fail closed.

Start the MCP server over stdio with `ekubo-wallet server`. It publishes the
`wallet://docs/security-model` resource. Run `ekubo-wallet --help` for the
complete CLI, or install a packaged completion:

```sh
ekubo-wallet completion zsh > ~/.zfunc/_ekubo-wallet
```
