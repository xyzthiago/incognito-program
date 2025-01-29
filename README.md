# incognito-program

Solana on-chain program for Incognito Swap.

This program:
- Custodies SPL tokens in PDA-owned vaults
- Verifies Groth16 (BN254) ZK proofs via Solana `alt_bn128` syscalls
- Tracks spent nullifiers to prevent double-spends
- Emits deposit/withdraw events for off-chain indexing

This repo contains **only the on-chain program**. Merkle witness generation, root updates, batching, and swap execution are handled off-chain by a relayer/indexer.

## Protocol versions

### v1 (fixed denomination; legacy)

Tornado-style fixed-denomination pool:

`deposit(commitment)` → prove membership + nullifier → `action_withdraw(proof, nullifierHash)`.

Pool identity:
- One pool per `(mint, denomination)`
- `state` PDA seeds: `["state", mint, denomination_le_u64]`
- `vault` PDA seeds: `["vault", state]` (TokenAccount owned by `state`)
- Nullifier stored as PDA per spend (purpose-limited and simple).

Proof statement:
- Public inputs: `root`, `nullifierHash`
- Constraints: Merkle membership + knowledge of `(secret, nullifier)` + `nullifierHash = Poseidon(nullifier)`

### v2 (variable-amount UTXO notes + optional change)

Variable-amount UTXO notes per mint, with optional change commitments appended on withdraw.

Pool identity:
- One pool per `mint`
- `state` PDA seeds: `["state", mint, "v2"]`
- `vault` PDA seeds: `["vault", state]` (TokenAccount owned by `state`)
- Root history ring buffer stored on-chain (for recent root membership)
- Nullifiers stored in **sharded pages** (see below) to keep compute + account size manageable

Note formats (commitment field element):
- Deposit note (binds amount cheaply on-chain):
  - `commitment = r * 2^64 + amountIn` (amount is the low 64 bits)
  - The program enforces `amountIn == deposit_amount` by parsing the commitment bytes.
- Change note (hides amount):
  - `commitment = Poseidon(nullifier, secret, amountIn, mintLo, mintHi)`

Proof statement (“spend-with-change”):
- Public inputs:
  - `root`, `nullifierHash`, `withdrawAmount`, `fee`
  - `recipient` (as two u128 halves, LE)
  - `mint` (as two u128 halves, LE)
  - `changeCommitment` (0 if no change)
- Constraints:
  - Merkle membership
  - Nullifier correctness
  - Value conservation: `amountIn = withdrawAmount + fee + changeAmount`
  - Optional change note commitment correctness if `changeAmount > 0`

Important:
- Batching / “change-not-spendable-in-same-batch” rules are enforced by the relayer/indexer (this program only verifies the proof and moves tokens).

## Merkle / roots

- Append-only Merkle tree (Poseidon(2))
- Witness generation off-chain
- On-chain stores:
  - Current `merkle_root`
  - v2 only: a recent `root_history` ring buffer (to accept proofs against recently-seen roots)
- Root updates are performed by a configured `root_updater` via `set_root` / `set_root_v2`

## Nullifier storage

- v1: nullifier stored as PDA (simple, low-volume friendly)
- v2: sharded by first byte of `nullifierHash` into pages to avoid unbounded account growth

## Token support

This program uses `anchor_spl::token_interface` and supports both:
- SPL Token (Tokenkeg…)
- Token-2022 (TokenzQd…)

## Instructions (high level)

v1:
- `initialize_pool(denomination, initial_root, root_updater)`
- `deposit(commitment)` / `deposit_many(commitments)` (max 20)
- `set_root(new_root)`
- `action_withdraw(proof, nullifier_hash)`

v2:
- `initialize_pool_v2(initial_root, root_updater)`
- `deposit_v2(commitment, amount)` (amount is enforced against the commitment low-64 bits)
- `set_root_v2(new_root)` (also updates the root history ring buffer)
- `withdraw_v2(proof, root, nullifier_hash, withdraw_amount, fee, change_commitment, shard_byte, page_index)`
  - On success: transfers `withdraw_amount` to recipient, `fee` to relayer fee ATA (optional), and emits a change commitment event if present.

## Build & deploy

Prereqs:
- Solana CLI
- Anchor CLI

Build:
```bash
cd incognito-program
anchor build
```

Deploy:
```bash
cd incognito-program
anchor deploy --provider.cluster devnet
```

## Updating verifying keys

Verifying keys are embedded as Rust constants:
- `programs/incognito_program/src/verifying_key.rs` (v1)
- `programs/incognito_program/src/verifying_key_v2.rs` (v2)

If you regenerate Groth16 keys, you must update these files and redeploy/upgrade the program.

## Generating a new program id (recommended)

Do **not** commit keypairs.

1. Generate a new keypair:
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

## Security notes

- This is **not audited**.
- Privacy is unlinkability-focused; metadata leakage (timing, relayer behavior, RPC fingerprinting) is still possible.
- v1 does **not** hide amounts.
- v2 supports variable-amount notes and change commitments, but batching/privacy policy is largely enforced off-chain.
