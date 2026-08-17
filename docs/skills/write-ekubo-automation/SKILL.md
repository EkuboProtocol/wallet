---
name: write-ekubo-automation
description: Write, test, and propose an Ekubo Wallet automation — EVM runtime bytecode the wallet polls on a cron schedule and whose returned calls it queues through the ordinary policy path. Trigger when asked to automate a recurring onchain action, run something every block or on a schedule, react to a chain condition without a live agent, or debug an installed automation.
---

# Write an Ekubo Automation

An automation is EVM runtime bytecode installed against one wallet and one
network, plus a cron schedule. On each tick the wallet runs your bytecode
through `eth_simulateV1` — as the code at the wallet's own address — and reads
back a list of calls. Those calls are queued through the same simulation and
policy path as anything else the wallet sends. An automation cannot do anything
the installed policy does not already allow.

You write the contract. You compile it. The wallet takes hex.

## The contract

```solidity
interface IEkuboAutomation {
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    /// Runs as the wallet, at the wallet's address, inside a simulation whose
    /// writes are discarded. Deliberately not `view`: probe freely.
    function automate(bytes calldata config) external returns (Call[] memory);
}
```

Return an empty array to mean "nothing to do this tick". Return a non-empty
array and every entry executes as one atomic batch.

## Compilation is your responsibility

The wallet does not compile anything and has no opinion about your source
language. Solidity, Vyper, Huff, or hand-written opcodes are all fine. The
contract is that you hand over **deployed runtime bytecode** as hex — solc's
`deployedBytecode`, not `bytecode` — that runs correctly on the target network.

Getting the artifact field wrong is the most common first mistake: `bytecode`
is creation code, and the wallet never runs a constructor.

## Automations are network-specific

An automation is installed against exactly one wallet and one network, and it
is not portable between networks for two separate reasons.

**Addresses differ.** Every protocol address, token address, and pool
identifier you hardcode or pass through `config` exists on one chain. The same
bytecode pointed at another chain calls whatever happens to live at those
addresses there, which is at best nothing.

**The EVM differs.** Compile for the target network's actual fork. A chain
without Shanghai rejects `PUSH0`, which recent solc emits by default; `MCOPY`
and `TSTORE` need Cancun; `BLOBBASEFEE` needs a chain that has blobs at all.
Set `evm_version` to what the target network supports rather than to your
compiler's default, or the bytecode reverts on the first tick with nothing
useful to say.

Check the chain ID inside `automate` if you want a loud failure instead of a
confusing one:

```solidity
require(block.chainid == 1, "wrong network");
```

## Hard rules

These follow from where the code runs, and violating them produces bugs that
look like nothing else.

**Declare no state variables.** Your code runs at the wallet's address, so
`SLOAD` reads the *wallet's* storage — for an EIP-7702 delegated account, that
is Calibur's storage at Calibur's layout. A `uint256 public threshold;` in your
contract does not read your value; it reads whatever the wallet happens to keep
in slot 0. Use `constant`, or read parameters out of `config`.

**No `immutable`, no constructor.** Immutable values are written into the
runtime code by the constructor at deploy time. Taking `deployedBytecode`
straight from a compiler artifact leaves those slots as unresolved
placeholders. Same for external libraries, whose artifacts carry
`__$...$__` link placeholders. Internal libraries inline and are fine.

**There is no memory between ticks.** The simulation discards every write, so
you cannot keep a counter, a cursor, or a "last run" timestamp. Derive that
from chain state you can read: the effect of your own previous transaction, a
timestamp the target contract stores, a balance that changed.

**Receiver hooks and ERC-1271 do not work during the tick.** The state
override replaces the wallet's code with yours for the duration of the poll, so
a contract that calls back into the wallet — `onERC721Received`,
`onERC1155Received`, `isValidSignature` — reaches your dispatcher instead of
Calibur. If you need to *probe* such a call, answer those selectors yourself or
`DELEGATECALL` to the canonical Calibur implementation for anything you do not
handle. This affects the poll only; the batch the wallet actually sends runs
through the intact delegation.

**Emit only calls the policy allows.** A batch that does not resolve to
all-allow disables the automation and notifies the owner. Read the wallet's
policy first, and if the automation needs authority it does not have, propose a
policy change through the normal path before installing.

## Examples

### 1. The minimum: do nothing

Establishes the shape. Every automation degenerates to this on a tick where its
condition is not met, and returning early is the cheap, normal case.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract Idle {
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    function automate(bytes calldata) external pure returns (Call[] memory) {
        return new Call[](0);
    }
}
```

### 2. Claim when the reward clears a threshold

The point of running as the wallet: `claim()` is `msg.sender`-gated, so you can
call it inside the tick to learn the amount, then decide whether it is worth a
transaction. The write is discarded either way.

`config` is `abi.encode(address distributor, uint256 minimumAmount)`, so the
same bytecode serves any distributor and any threshold without recompiling.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IDistributor {
    function claim() external returns (uint256 amount);
}

contract ClaimAboveThreshold {
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    function automate(bytes calldata config) external returns (Call[] memory) {
        (address distributor, uint256 minimumAmount) = abi.decode(config, (address, uint256));

        // Probing: this runs for real inside the simulation and is thrown
        // away with it. `msg.sender` is the wallet, so the gate passes.
        uint256 amount = IDistributor(distributor).claim();
        if (amount < minimumAmount) {
            return new Call[](0);
        }

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            to: distributor,
            value: 0,
            data: abi.encodeCall(IDistributor.claim, ())
        });
        return calls;
    }
}
```

### 3. A multi-call batch, and using chain state as memory

Two calls that must land together — approve, then deposit — and a cadence
enforced by a timestamp the *target* stores, because the automation cannot
remember when it last ran. Set the cron tighter than the interval you actually
want and let this check be the authority; a skipped tick then costs one
`eth_simulateV1` and nothing else.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IVault {
    function lastDepositAt(address account) external view returns (uint256);
    function deposit(uint256 amount) external;
}

contract PeriodicDeposit {
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    function automate(bytes calldata config) external view returns (Call[] memory) {
        (address token, address vault, uint256 minimumInterval, uint256 minimumAmount) =
            abi.decode(config, (address, address, uint256, uint256));

        // The automation has no memory, so the schedule lives on chain.
        if (block.timestamp < IVault(vault).lastDepositAt(address(this)) + minimumInterval) {
            return new Call[](0);
        }

        uint256 balance = IERC20(token).balanceOf(address(this));
        if (balance < minimumAmount) {
            return new Call[](0);
        }

        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            to: token,
            value: 0,
            data: abi.encodeCall(IERC20.approve, (vault, balance))
        });
        calls[1] = Call({
            to: vault,
            value: 0,
            data: abi.encodeCall(IVault.deposit, (balance))
        });
        return calls;
    }
}
```

`address(this)` is the wallet, which is why the balance and the stored
timestamp are the wallet's own.

### 4. Surviving a callback during a probe

Only needed when the call you want to *probe* makes the target call back into
the wallet. Answer the hook yourself; without this the probe reverts on a check
that would pass in the real batch.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract ProbesAnNftTransfer {
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    /// Calibur answers this in production. During a tick this contract *is*
    /// the wallet's code, so it has to answer for itself.
    function onERC721Received(address, address, uint256, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC721Received.selector;
    }

    function automate(bytes calldata) external pure returns (Call[] memory) {
        return new Call[](0);
    }
}
```

## Test before you propose

`wallet_dry_run_automation` takes your bytecode and config, installs nothing,
signs nothing, and tells you what happened: the decoded call list, the policy
verdict for every call with the rule that decided it, the simulation of the
resulting batch, gas used by the poll, and — on failure — the revert selector, a
decoded `Error(string)` or `Panic(uint256)`, the raw return bytes, and why an
ABI decode failed. Iterate there. It is the same poll the scheduler performs.

Then `wallet_propose_automation` with the bytecode, config, cron expression,
wallet, and network. The owner installs it from the Automations tab; you cannot.

## Scheduling notes

Cron expressions are six fields, seconds first, in UTC. `*/12 * * * * *` is
roughly per-block on a twelve-second chain.

Ticks are skipped, never queued up, when the previous run's transaction is
still pending or another send holds that wallet and chain's slot, and missed
ticks — application closed, wallet locked, machine asleep — are not backfilled.
A schedule is a maximum rate, not a guarantee. Write the contract so that a
skipped tick is harmless and the next one recomputes from live state.

The automation disables itself and notifies the owner on a policy rejection, an
on-chain revert, a transaction that never mines, or ten consecutive failed
ticks. `wallet_get_automation_status` reports which of those happened.
