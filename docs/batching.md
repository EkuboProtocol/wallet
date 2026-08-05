# EIP-7702 batching

Multi-call plans execute through [Uniswap Calibur](https://github.com/Uniswap/calibur),
a non-upgradeable EIP-7702 singleton with ERC-7821 batch execution. Only the
canonical v1.1.0 deployment at `0x000000005c84F8Fd50b21CAC312528A64437030e` is
accepted, and its runtime code is verified before delegation. The wallet neither
deploys nor accepts a configurable implementation.

A one-call plan is sent directly to its target and never checks or uses
delegation. Two or more ordered calls become one `revertOnFailure` Calibur batch:
an undelegated wallet includes a self-executed authorization, an
already-canonical wallet sends a normal transaction to itself, and a wallet
delegated elsewhere has that delegation replaced with canonical Calibur in the
same transaction.

Replacing a delegation changes persistent account code even if the batch later
reverts, and can expose storage-layout incompatibilities left by the previous
delegate. Use a separate wallet if a prior delegation or its storage must be
preserved. Accounts holding arbitrary bytecode rather than an EIP-7702
delegation designator are rejected.
