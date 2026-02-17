# incognito-program

Solana on-chain program for Incognito Swap.

This program:
- Custodies SPL tokens in PDA-owned vaults
- Verifies Groth16 (BN254) ZK proofs via Solana `alt_bn128` syscalls
- Tracks spent nullifiers to prevent double-spends
- Emits deposit/withdraw events for off-chain indexing

This repository contains **only the on-chain program**. Merkle witness generation, root updates, batching, and swap execution are handled off-chain by a relayer/indexer.

Maintained by **xyzthiago**.

---

## Protocol Versions

### v1 (Fixed Denomination – Legacy)

Tornado-style fixed-denomination pool:

`deposit(commitment)` → prove membership + nullifier → `action_withdraw(proof, nullifierHash)`

Pool identity:
- One pool per `(mint, denomination)`
- `state` PDA seeds: `["state", mint, denomination_le_u64]`
- `vault` PDA seeds: `["vault", state]` (TokenAccount owned by `state`)
- Nullifier stored as PDA per spend

Proof statement:
- Public inputs: `root`, `nullifierHash`
- Constraints:
  - Merkle membership
  - Knowledge of `(secret, nullifier)`
  - `nullifierHash = Poseidon(nullifier)`

---

### v2 (Variable-Amount UTXO Notes + Optional Change)

Variable-amount UTXO notes per mint, with optional change commitments appended on withdraw.

Pool identity:
- One pool per `mint`
- `state` PDA seeds: `["state", mint, "v2"]`
- `vault` PDA seeds: `["vault", state]` (TokenAccount owned by `state`)
- Root history ring buffer stored on-chain
- Nullifiers stored in sharded pages

Note formats:

Deposit note:
`commitment = r * 2^64 + amountIn`  
Amount is the low 64 bits and enforced on-chain.

Change note:
`commitment = Poseidon(nullifier, secret, amountIn, mintLo, mintHi)`

Proof statement (“spend-with-change”):

Public inputs:
- `root`
- `nullifierHash`
- `withdrawAmount`
- `fee`
- `recipient` (two u128 halves, LE)
- `mint` (two u128 halves, LE)
- `changeCommitment` (0 if none)

Constraints:
- Merkle membership
- Nullifier correctness
- Value conservation:
  `amountIn = withdrawAmount + fee + changeAmount`
- Optional change note commitment correctness

Important:
Batching and “change-not-spendable-in-same-batch” rules are enforced off-chain.

---

## Merkle / Roots

- Append-only Merkle tree (Poseidon(2))
- Witness generation off-chain
- On-chain storage:
  - Current `merkle_root`
  - v2: recent `root_history` ring buffer

Root updates performed by configured `root_updater` via:
- `set_root`
- `set_root_v2`

---

## Nullifier Storage

- v1: Stored as PDA (simple, low-volume friendly)
- v2: Sharded by first byte of `nullifierHash` into pages

---

## Token Support

Uses `anchor_spl::token_interface` and supports:

- SPL Token (Tokenkeg…)
- Token-2022 (TokenzQd…)

---

## Instructions

### v1

- `initialize_pool(denomination, initial_root, root_updater)`
- `deposit(commitment)`
- `deposit_many(commitments)` (max 20)
- `set_root(new_root)`
- `action_withdraw(proof, nullifier_hash)`

### v2

- `initialize_pool_v2(initial_root, root_updater)`
- `deposit_v2(commitment, amount)`
- `set_root_v2(new_root)`
- `withdraw_v2(proof, root, nullifier_hash, withdraw_amount, fee, change_commitment, shard_byte, page_index)`

On success:
- Transfers `withdraw_amount` to recipient
- Transfers `fee` to relayer fee ATA (optional)
- Emits change commitment event if present

---

## Build & Deploy

Prerequisites:
- Solana CLI
- Anchor CLI

Build:
```bash
cd incognito-program
anchor build
```

Deploy (devnet example):
```bash
cd incognito-program
anchor deploy --provider.cluster devnet
```

---

## Updating Verifying Keys

Verifying keys are embedded as Rust constants:

- `programs/incognito_program/src/verifying_key.rs` (v1)
- `programs/incognito_program/src/verifying_key_v2.rs` (v2)

If Groth16 keys are regenerated:
- Update the files
- Rebuild
- Redeploy or upgrade the program

---

## Generating a New Program ID (Recommended)

Do not commit keypairs.

1. Generate keypair:
```bash
solana-keygen new --no-bip39-passphrase -o target/deploy/incognito_program-keypair.json
```

2. Update:
- `programs/incognito_program/src/lib.rs` (`declare_id!`)
- `Anchor.toml` (`[programs.*].incognito_program`)

3. Rebuild + deploy:
```bash
anchor build
anchor deploy --provider.cluster devnet
```

---

## Security Notes

- Not audited
- Privacy is unlinkability-focused
- Metadata leakage remains possible (timing, relayer behavior, RPC fingerprinting)
- v1 does not hide amounts
- v2 supports variable-amount notes and change commitments
- Privacy policy and batching logic are largely enforced off-chain

---

Maintainer: **xyzthiago**
