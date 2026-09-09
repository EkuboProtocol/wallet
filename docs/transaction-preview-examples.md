# Transaction preview examples

Actual outputs from the committed revision-4 weights, run through the browser CPU backend on 2026-09-09. These are illustrative synthetic decoded inputs; no transactions were sent. Standard calls and opaque-call warnings can use deterministic fallbacks. Summaries select fields rather than freely paraphrasing them.

The omissions are intentional evidence of remaining limitations: cooldown omits its amount, and liquidity removal selects a minimum output instead of the liquidity quantity. The full decoded reading remains visible in the wallet.

## Token approval

Decoded input:

- approve spender 0x2222222222222222222222222222222222222222 for 100 USDC

> approve spender 0x2222222222222222222222222222222222222222 for 100 USDC

Category: `approval`. Advisory risk: `caution`.

## Third-party transfer

Decoded input:

- transferFrom 25 USDC from 0x1111111111111111111111111111111111111111 to 0x2222222222222222222222222222222222222222

> transferFrom 25 USDC from 0x1111111111111111111111111111111111111111 to 0x2222222222222222222222222222222222222222

Category: `transfer`. Advisory risk: `caution`.

## Cooldown

Decoded input:

- Ethena — Cooldown shares; Amount: 12 sUSDe

> Ethena: Cooldown shares

Category: `unstake`. Advisory risk: `routine`.

## Deposit

Decoded input:

- Aave — Supply; Amount: 250 USDC

> Aave: Supply — Amount: 250 USDC

Category: `supply`. Advisory risk: `routine`.

## Claim rewards

Decoded input:

- Sei — Claim rewards

> Sei: Claim rewards

Category: `claim`. Advisory risk: `routine`.

## Stake

Decoded input:

- Lido — Stake ETH; Amount: 0.5 ETH; native value 0.5 ETH

> Lido: Stake ETH — Amount: 0.5 ETH

Category: `stake`. Advisory risk: `routine`.

## Remove liquidity

Decoded input:

- Uniswap — Remove liquidity; Liquidity: 50; Minimum token 0: 10 USDC; Minimum token 1: 0.01 ETH

> Uniswap: Remove liquidity — Minimum token 1: 0.01 ETH

Category: `liquidity_remove`. Advisory risk: `routine`.

## Undecoded call

Decoded input:

- Undecoded call to 0x1111111111111111111111111111111111111111; native value 0.25 ETH

> Undecoded call to 0x1111111111111111111111111111111111111111 sending 0.25 ETH

Category: `unrecognized`. Advisory risk: `critical`.

## Late opaque call

Decoded input:

- Sei — Claim rewards
- Ethena — Cooldown shares; Amount: 12 sUSDe
- Undecoded call to 0x1111111111111111111111111111111111111111

> 3 calls; call 3: Unrecognized. Review all calls.

Category: `batch`. Advisory risk: `critical`.

## Operator approval

Decoded input:

- setApprovalForAll operator 0x2222222222222222222222222222222222222222 approved true
- Warning: Operator can transfer all tokens

> setApprovalForAll operator 0x2222222222222222222222222222222222222222 approved true

Category: `approval`. Advisory risk: `critical`.

## Operator revocation

Decoded input:

- setApprovalForAll operator 0x2222222222222222222222222222222222222222 approved false

> setApprovalForAll operator 0x2222222222222222222222222222222222222222 approved false

Category: `revocation`. Advisory risk: `routine`.
