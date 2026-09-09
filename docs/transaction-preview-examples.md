# Generated transaction card examples

Actual native CPU outputs from the committed weights and card path; the same 22 cases passed in browser CPU builds and WebGPU. Inputs are synthetic fixtures, and no transactions were sent. These examples demonstrate regression coverage, not independent semantic accuracy. All summaries fit the 100-character hard cap.

## 1. Exact approval then swap

- approve spender 0x1111111111111111111111111111111111111111 for 250 USDC
- Uniswap — Swap; Amount in: 250 USDC; Token out: ETH; Minimum output: 0.1 ETH

**Generated:** Approve and swap 250 USDC for ETH

Category: `swap`. Advisory risk: `caution`.

## 2. Unlimited approval then swap

- approve spender 0x1111111111111111111111111111111111111111 for unlimited USDC; warnings: Unlimited allowance
- Uniswap — Swap; Amount in: 250 USDC; Token out: ETH; Minimum output: 0.1 ETH

**Generated:** Unlimited approve USDC and swap 250 USDC for ETH

Category: `swap`. Advisory risk: `critical`.

## 3. Swap then revoke

- Uniswap — Swap; Amount in: 250 USDC; Token out: ETH; Minimum output: 0.1 ETH
- revoke USDC allowance for spender 0x1111111111111111111111111111111111111111

**Generated:** Swap 250 USDC for ETH, then revoke approval

Category: `swap`. Advisory risk: `routine`.

## 4. Larger finite allowance

- approve spender 0x1111111111111111111111111111111111111111 for 1000 USDC
- Uniswap — Swap; Amount in: 250 USDC; Token out: ETH; Minimum output: 0.1 ETH

**Generated:** Approve 1000 USDC and swap 250 USDC for ETH

Category: `swap`. Advisory risk: `caution`.

## 5. Unrelated unlimited approval

- approve spender 0x2222222222222222222222222222222222222222 for unlimited USDC; warnings: Unlimited allowance
- Uniswap — Swap; Amount in: 250 USDC; Token out: ETH; Minimum output: 0.1 ETH

**Generated:** Unlimited approve USDC to 0x222222…222222 and swap 250 USDC for ETH

Category: `swap`. Advisory risk: `critical`.

## 6. Claim, swap, deposit

- Sei — Claim rewards
- Uniswap — Swap; Token in: rewards; Token out: USDC
- Aave — Supply; Amount: 250 USDC

**Generated:** Claim rewards on Sei, swap rewards for USDC, and deposit 250 USDC

Category: `supply`. Advisory risk: `routine`.

## 7. Deposit

- Aave — Supply; Amount: 250 USDC

**Generated:** Deposit 250 USDC

Category: `supply`. Advisory risk: `routine`.

## 8. Cooldown

- Ethena — Cooldown shares; Amount: 12 sUSDe

**Generated:** Start cooldown 12 sUSDe

Category: `unstake`. Advisory risk: `routine`.

## 9. Stake

- Lido — Stake ETH; Amount: 0.5 ETH; native value: 0.5 ETH

**Generated:** Stake 0.5 ETH

Category: `stake`. Advisory risk: `routine`.

## 10. Liquidity minimum

- Uniswap — Remove liquidity; Liquidity: 50; Minimum token 0: 10 USDC; Minimum token 1: 0.01 ETH

**Generated:** Remove liquidity on Uniswap

Category: `liquidity_remove`. Advisory risk: `routine`.

## 11. Minimum is not expected output

- Uniswap — Swap; Amount in: 250 USDC; Token out: ETH; Minimum output: 0.1 ETH

**Generated:** Swap 250 USDC for ETH

Category: `swap`. Advisory risk: `routine`.

## 12. Unknown tail

- Aave — Supply; Amount: 250 USDC
- Unknown call

**Generated:** Deposit 250 USDC and unknown call

Category: `supply`. Advisory risk: `critical`.

## 13. Unknown head

- Unknown call
- Aave — Supply; Amount: 250 USDC

**Generated:** Unknown call and deposit 250 USDC

Category: `supply`. Advisory risk: `critical`.

## 14. Unknown value transfer

- Unknown call; native value: 0.25 ETH

**Generated:** Unknown call sending 0.25 ETH

Category: `unrecognized`. Advisory risk: `critical`.

## 15. Distinct recipient

- Uniswap — Swap; Amount in: 250 USDC; Token out: ETH; Recipient: 0x2222222222222222222222222222222222222222

**Generated:** Swap 250 USDC for ETH to 0x222222…222222

Category: `swap`. Advisory risk: `routine`.

## 16. Operator grant

- setApprovalForAll operator 0x2222222222222222222222222222222222222222 approved true; warnings: Operator can transfer all tokens

**Generated:** Approve all tokens

Category: `approval`. Advisory risk: `critical`.

## 17. Operator revocation

- setApprovalForAll operator 0x2222222222222222222222222222222222222222 approved false

**Generated:** Revoke approval

Category: `revocation`. Advisory risk: `routine`.

## 18. Preserve signer change

- Safe — Swap signer; Old signer: 0x1111111111111111111111111111111111111111; New signer: 0x2222222222222222222222222222222222222222

**Generated:** Swap signer on Safe

Category: `governance`. Advisory risk: `routine`.

## 19. Preserve compound action

- Protocol — Claim rewards and restake

**Generated:** Claim rewards and restake on Protocol

Category: `claim`. Advisory risk: `routine`.

## 20. Do not promise instant withdrawal

- Lido — Request withdrawal; Amount: 2 ETH

**Generated:** Request withdrawal on Lido

Category: `withdraw`. Advisory risk: `routine`.

## 21. Preserve transfer roles

- transferFrom 0x1111111111111111111111111111111111111111 to 0x2222222222222222222222222222222222222222 for 25 USDC

**Generated:** TransferFrom 0x111111…111111 to 0x222222…222222 for 25 USDC

Category: `transfer`. Advisory risk: `caution`.

## 22. Conflicting fields

- Aave — Supply; Amount: 250 USDC; Amount: 500 USDC

**Generated:** Deposit on Aave

Category: `supply`. Advisory risk: `routine`.

## Simulation context and inferred intent

These outputs use the embedded model and constrained renderer. Simulation provenance is shown in the card metadata, not in the headline. Inferred function candidates remain advisory; the risk floor stays critical.

| Evidence | Generated headline |
|---|---|
| Opaque ETH payment receiving USDG | Send 1 ETH and receive 2400 USDG |
| Opaque ETH payment with USDG transfer logs | Send 1 ETH and receive 2400 USDG |
| Opaque ETH payment without simulation | Unknown call sending 1 ETH |
| Swap candidate with matching asset exchange | Swap 1 ETH for 2400 USDG |
| Vault deposit is not inferred as a swap | Deposit 1 ETH |
| Wrap is not inferred as a swap | Wrap 1 ETH |
| Ambiguous execute stays an outcome | Send 1 ETH and receive 2400 USDG |
