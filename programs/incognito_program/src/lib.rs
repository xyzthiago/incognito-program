use anchor_lang::prelude::*;
use anchor_spl::token_interface::{self, Mint, TokenAccount, TokenInterface, TransferChecked};
use groth16_solana::errors::Groth16Error;
use groth16_solana::groth16::Groth16Verifier;

declare_id!("APQauWUWYf1pd7BwG8xWe2eQT7uhXX4NRnRYQJfnAiYW");

pub const STATE_SEED: &[u8] = b"state";
pub const VAULT_SEED: &[u8] = b"vault";
pub const NULLIFIER_SEED: &[u8] = b"nullifier";
pub const NULLIFIER_PAGE_SEED: &[u8] = b"nullifier_page";
pub const V2_SEED: &[u8] = b"v2";

pub const FR_BYTES: usize = 32;
pub const GROTH16_PROOF_BYTES: usize = 256;
pub const GROTH16_A_BYTES: usize = 64;
pub const GROTH16_B_BYTES: usize = 128;
pub const GROTH16_C_BYTES: usize = 64;
pub const ZERO_32: [u8; 32] = [0u8; 32];
pub const MAX_DEPOSITS_PER_TX: usize = 20;
pub const ROOT_HISTORY_SIZE: usize = 32;
// Keep this small enough to avoid Solana BPF stack issues with Anchor account deserialization.
pub const NULLIFIER_PAGE_CAPACITY: usize = 96;

// BN254 scalar field modulus (Fr) used by Groth16 public inputs (Circom/snarkjs).
// Hex: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
pub const BN254_FR_MODULUS_BE: [u8; 32] = [
    48, 100, 78, 114, 225, 49, 160, 41, 184, 80, 69, 182, 129, 129, 88, 93, 40, 51, 232, 72, 121,
    185, 112, 145, 67, 225, 245, 147, 240, 0, 0, 1,
];

mod verifying_key;
mod verifying_key_v2;

#[program]
pub mod incognito_program {
    use super::*;

    /// Initialize a v1 pool for a single mint + fixed denomination.
    ///
    /// v1 is a Tornado-style fixed-denomination pool:
    /// - On-chain stores a single current Merkle root for membership checks
    /// - Deposits transfer `denomination` tokens per commitment into a PDA-owned vault
    /// - Withdrawals verify a Groth16 proof and prevent double spends via nullifier PDAs
    pub fn initialize_pool(
        ctx: Context<Initialize>,
        denomination: u64,
        initial_root: [u8; 32],
        root_updater: Pubkey,
    ) -> Result<()> {
        let state = &mut ctx.accounts.state;
        state.mint = ctx.accounts.mint.key();
        state.denomination = denomination;
        state.root_updater = root_updater;
        state.merkle_root = initial_root;
        state.next_index = 0;
        state.state_bump = ctx.bumps.state;
        state.vault_bump = ctx.bumps.vault;

        Ok(())
    }

    pub fn set_root(ctx: Context<SetRoot>, new_root: [u8; 32]) -> Result<()> {
        require_keys_eq!(
            ctx.accounts.root_updater.key(),
            ctx.accounts.state.root_updater,
            IncognitoError::UnauthorizedRootUpdater
        );

        ctx.accounts.state.merkle_root = new_root;
        emit!(RootUpdatedEvent {
            state: ctx.accounts.state.key(),
            mint: ctx.accounts.state.mint,
            denomination: ctx.accounts.state.denomination,
            merkle_root: new_root,
            next_index: ctx.accounts.state.next_index,
        });
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, commitment: [u8; 32]) -> Result<()> {
        deposit_many_inner(ctx, vec![commitment])
    }

    pub fn deposit_many(ctx: Context<Deposit>, commitments: Vec<[u8; 32]>) -> Result<()> {
        deposit_many_inner(ctx, commitments)
    }

    pub fn action_withdraw(
        ctx: Context<ActionWithdraw>,
        proof: [u8; 256],
        nullifier_hash: [u8; 32],
    ) -> Result<()> {
        require_keys_eq!(
            ctx.accounts.mint.key(),
            ctx.accounts.state.mint,
            IncognitoError::InvalidMint
        );
        require_keys_eq!(
            ctx.accounts.destination.mint,
            ctx.accounts.state.mint,
            IncognitoError::InvalidMint
        );
        require_keys_eq!(
            ctx.accounts.vault.mint,
            ctx.accounts.state.mint,
            IncognitoError::InvalidMint
        );

        let proof_a: [u8; GROTH16_A_BYTES] = proof[0..GROTH16_A_BYTES]
            .try_into()
            .map_err(|_| IncognitoError::InvalidProof)?;
        let proof_b: [u8; GROTH16_B_BYTES] = proof
            [GROTH16_A_BYTES..(GROTH16_A_BYTES + GROTH16_B_BYTES)]
            .try_into()
            .map_err(|_| IncognitoError::InvalidProof)?;
        let proof_c: [u8; GROTH16_C_BYTES] = proof
            [(GROTH16_A_BYTES + GROTH16_B_BYTES)..GROTH16_PROOF_BYTES]
            .try_into()
            .map_err(|_| IncognitoError::InvalidProof)?;

        let public_inputs: [[u8; 32]; 2] = [ctx.accounts.state.merkle_root, nullifier_hash];
        let mut verifier = Groth16Verifier::<2>::new(
            &proof_a,
            &proof_b,
            &proof_c,
            &public_inputs,
            &verifying_key::VERIFYINGKEY,
        )
        .map_err(|e| {
            msg!("groth16 verifier init failed: {}", e);
            match e {
                Groth16Error::InvalidG1Length
                | Groth16Error::InvalidG2Length
                | Groth16Error::InvalidPublicInputsLength
                | Groth16Error::PublicInputGreaterThanFieldSize
                | Groth16Error::IncompatibleVerifyingKeyWithNrPublicInputs => {
                    IncognitoError::InvalidProof
                }
                _ => IncognitoError::Groth16SyscallFailed,
            }
        })?;

        verifier.verify().map_err(|e| {
            msg!("groth16 verify failed: {}", e);
            match e {
                Groth16Error::ProofVerificationFailed => IncognitoError::InvalidProof,
                _ => IncognitoError::Groth16SyscallFailed,
            }
        })?;

        let state_bump = ctx.accounts.state.state_bump;
        let denom_le = ctx.accounts.state.denomination.to_le_bytes();
        let signer_seeds: &[&[&[u8]]] = &[&[
            STATE_SEED,
            ctx.accounts.state.mint.as_ref(),
            denom_le.as_ref(),
            &[state_bump],
        ]];

        token_interface::transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.vault.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.destination.to_account_info(),
                    authority: ctx.accounts.state.to_account_info(),
                },
                signer_seeds,
            ),
            ctx.accounts.state.denomination,
            ctx.accounts.mint.decimals,
        )?;

        emit!(WithdrawEvent {
            state: ctx.accounts.state.key(),
            mint: ctx.accounts.state.mint,
            denomination: ctx.accounts.state.denomination,
            nullifier_hash,
            destination: ctx.accounts.destination.key(),
        });

        Ok(())
    }

    // -------------------------
    // v2: variable-amount notes + change commitments
    // -------------------------

    /// Initialize a v2 pool for a single mint.
    ///
    /// v2 uses variable-amount UTXO-style notes. Deposits bind the deposited amount
    /// to the leaf commitment (see `deposit_v2`), while optional change commitments
    /// may be appended during `withdraw_v2`.
    pub fn initialize_pool_v2(
        ctx: Context<InitializeV2>,
        initial_root: [u8; 32],
        root_updater: Pubkey,
    ) -> Result<()> {
        let state = &mut ctx.accounts.state;
        state.mint = ctx.accounts.mint.key();
        state.root_updater = root_updater;
        state.merkle_root = initial_root;
        state.next_index = 0;
        // Accounts are zero-initialized by `init`; avoid large stack assignments here.
        state.root_history[0] = initial_root;
        state.root_history_cursor = 1;
        state.state_bump = ctx.bumps.state;
        state.vault_bump = ctx.bumps.vault;
        Ok(())
    }

    pub fn set_root_v2(ctx: Context<SetRootV2>, new_root: [u8; 32]) -> Result<()> {
        require_keys_eq!(
            ctx.accounts.root_updater.key(),
            ctx.accounts.state.root_updater,
            IncognitoError::UnauthorizedRootUpdater
        );

        ctx.accounts.state.merkle_root = new_root;
        let i = ctx.accounts.state.root_history_cursor as usize % ROOT_HISTORY_SIZE;
        ctx.accounts.state.root_history[i] = new_root;
        ctx.accounts.state.root_history_cursor =
            ctx.accounts.state.root_history_cursor.wrapping_add(1);

        emit!(RootUpdatedEventV2 {
            state: ctx.accounts.state.key(),
            mint: ctx.accounts.state.mint,
            merkle_root: new_root,
            next_index: ctx.accounts.state.next_index,
        });
        Ok(())
    }

    /// Deposit a v2 note commitment and transfer the corresponding token amount into the vault.
    ///
    /// The program enforces that `amount` matches the low 64 bits of `commitment`.
    /// This binds deposited tokens to the committed leaf without requiring on-chain hashing.
    pub fn deposit_v2(ctx: Context<DepositV2>, commitment: [u8; 32], amount: u64) -> Result<()> {
        require_keys_eq!(
            ctx.accounts.mint.key(),
            ctx.accounts.state.mint,
            IncognitoError::InvalidMint
        );
        require_keys_eq!(
            ctx.accounts.depositor_token.mint,
            ctx.accounts.state.mint,
            IncognitoError::InvalidMint
        );
        require_keys_eq!(
            ctx.accounts.vault.mint,
            ctx.accounts.state.mint,
            IncognitoError::InvalidMint
        );
        require!(amount > 0, IncognitoError::InvalidDepositAmount);

        // Deposit-note leaf encoding (v2) binds the deposit token amount into the commitment's low 64 bits.
        //
        // Change notes appended during `withdraw_v2` use a different commitment format (Poseidon hash output)
        // and are not deposited via this instruction.
        //
        // Enforce:
        // - commitment is a canonical Fr field element (required for Poseidon/Merkle membership)
        // - extracted amountIn == provided `amount`
        require!(
            commitment < BN254_FR_MODULUS_BE,
            IncognitoError::InvalidCommitment
        );
        let amount_in = u64::from_be_bytes(
            commitment[24..32]
                .try_into()
                .map_err(|_| IncognitoError::InvalidCommitment)?,
        );
        require!(
            amount_in == amount,
            IncognitoError::CommitmentAmountMismatch
        );

        token_interface::transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.depositor_token.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.vault.to_account_info(),
                    authority: ctx.accounts.depositor.to_account_info(),
                },
            ),
            amount,
            ctx.accounts.mint.decimals,
        )?;

        let index = ctx.accounts.state.next_index;
        ctx.accounts.state.next_index = ctx
            .accounts
            .state
            .next_index
            .checked_add(1)
            .ok_or(IncognitoError::IndexOverflow)?;

        emit!(DepositEventV2 {
            state: ctx.accounts.state.key(),
            mint: ctx.accounts.state.mint,
            commitment,
            index,
            is_change: false,
        });

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn withdraw_v2(
        ctx: Context<WithdrawV2>,
        proof: [u8; 256],
        root: [u8; 32],
        nullifier_hash: [u8; 32],
        withdraw_amount: u64,
        fee: u64,
        change_commitment: [u8; 32],
        nullifier_shard_byte: u8,
        nullifier_page_index: u16,
    ) -> Result<()> {
        require_keys_eq!(
            ctx.accounts.mint.key(),
            ctx.accounts.state.mint,
            IncognitoError::InvalidMint
        );
        require_keys_eq!(
            ctx.accounts.destination.mint,
            ctx.accounts.state.mint,
            IncognitoError::InvalidMint
        );
        require_keys_eq!(
            ctx.accounts.vault.mint,
            ctx.accounts.state.mint,
            IncognitoError::InvalidMint
        );
        require_keys_eq!(
            ctx.accounts.relayer_fee_ata.mint,
            ctx.accounts.state.mint,
            IncognitoError::InvalidMint
        );

        require!(
            nullifier_shard_byte == nullifier_hash[0],
            IncognitoError::InvalidNullifierShard
        );

        require!(
            is_known_root(&ctx.accounts.state, &root),
            IncognitoError::UnknownRoot
        );

        let (recipient_lo, recipient_hi) =
            pubkey_to_u128_halves_le(&ctx.accounts.destination.owner);
        let (mint_lo, mint_hi) = pubkey_to_u128_halves_le(&ctx.accounts.state.mint);

        let public_inputs: [[u8; 32]; 9] = [
            root,
            nullifier_hash,
            u64_to_be_bytes32(withdraw_amount),
            u64_to_be_bytes32(fee),
            u128_to_be_bytes32(recipient_lo),
            u128_to_be_bytes32(recipient_hi),
            u128_to_be_bytes32(mint_lo),
            u128_to_be_bytes32(mint_hi),
            change_commitment,
        ];

        verify_groth16_v2(&proof, &public_inputs)?;

        check_and_insert_nullifier_v2(
            NullifierInsertArgsV2 {
                program_id: ctx.program_id,
                state_key: ctx.accounts.state.key(),
                nullifier_hash: &nullifier_hash,
                nullifier_shard_byte,
                nullifier_page_index,
                bump_shard: ctx.bumps.nullifier_shard,
                bump_page: ctx.bumps.nullifier_page,
            },
            ctx.accounts.nullifier_shard.as_mut(),
            ctx.accounts.nullifier_page.as_ref(),
            ctx.remaining_accounts,
        )?;

        // Transfer funds
        let state_bump = ctx.accounts.state.state_bump;
        let signer_seeds: &[&[&[u8]]] = &[&[
            STATE_SEED,
            ctx.accounts.state.mint.as_ref(),
            V2_SEED,
            &[state_bump],
        ]];

        if withdraw_amount > 0 {
            token_interface::transfer_checked(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    TransferChecked {
                        from: ctx.accounts.vault.to_account_info(),
                        mint: ctx.accounts.mint.to_account_info(),
                        to: ctx.accounts.destination.to_account_info(),
                        authority: ctx.accounts.state.to_account_info(),
                    },
                    signer_seeds,
                ),
                withdraw_amount,
                ctx.accounts.mint.decimals,
            )?;
        }

        if fee > 0 {
            token_interface::transfer_checked(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    TransferChecked {
                        from: ctx.accounts.vault.to_account_info(),
                        mint: ctx.accounts.mint.to_account_info(),
                        to: ctx.accounts.relayer_fee_ata.to_account_info(),
                        authority: ctx.accounts.state.to_account_info(),
                    },
                    signer_seeds,
                ),
                fee,
                ctx.accounts.mint.decimals,
            )?;
        }

        // Optional change commitment append (tree update happens off-chain via set_root_v2).
        // Change commitments intentionally do not reveal the note amount (no token transfer accompanies the append).
        let mut change_index: Option<u32> = None;
        if change_commitment != ZERO_32 {
            let idx = ctx.accounts.state.next_index;
            ctx.accounts.state.next_index = ctx
                .accounts
                .state
                .next_index
                .checked_add(1)
                .ok_or(IncognitoError::IndexOverflow)?;
            change_index = Some(idx);

            emit!(DepositEventV2 {
                state: ctx.accounts.state.key(),
                mint: ctx.accounts.state.mint,
                commitment: change_commitment,
                index: idx,
                is_change: true,
            });
        }

        emit!(WithdrawEventV2 {
            state: ctx.accounts.state.key(),
            mint: ctx.accounts.state.mint,
            root,
            nullifier_hash,
            withdraw_amount,
            fee,
            recipient: ctx.accounts.destination.owner,
            change_commitment,
            change_index,
        });

        Ok(())
    }
}

fn deposit_many_inner(ctx: Context<Deposit>, commitments: Vec<[u8; 32]>) -> Result<()> {
    require_keys_eq!(
        ctx.accounts.mint.key(),
        ctx.accounts.state.mint,
        IncognitoError::InvalidMint
    );
    require_keys_eq!(
        ctx.accounts.depositor_token.mint,
        ctx.accounts.state.mint,
        IncognitoError::InvalidMint
    );
    require_keys_eq!(
        ctx.accounts.vault.mint,
        ctx.accounts.state.mint,
        IncognitoError::InvalidMint
    );

    require!(
        !commitments.is_empty() && commitments.len() <= MAX_DEPOSITS_PER_TX,
        IncognitoError::InvalidDepositCount
    );

    let amount = (ctx.accounts.state.denomination as u128)
        .checked_mul(commitments.len() as u128)
        .ok_or(IncognitoError::DepositAmountOverflow)? as u64;

    token_interface::transfer_checked(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            TransferChecked {
                from: ctx.accounts.depositor_token.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.vault.to_account_info(),
                authority: ctx.accounts.depositor.to_account_info(),
            },
        ),
        amount,
        ctx.accounts.mint.decimals,
    )?;

    for commitment in commitments {
        let index = ctx.accounts.state.next_index;
        ctx.accounts.state.next_index = ctx
            .accounts
            .state
            .next_index
            .checked_add(1)
            .ok_or(IncognitoError::IndexOverflow)?;

        emit!(DepositEvent {
            state: ctx.accounts.state.key(),
            mint: ctx.accounts.state.mint,
            denomination: ctx.accounts.state.denomination,
            commitment,
            index,
        });
    }
    Ok(())
}

#[derive(Accounts)]
#[instruction(denomination: u64, initial_root: [u8; 32], root_updater: Pubkey)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        init,
        payer = payer,
        space = IncognitoState::SPACE,
        seeds = [STATE_SEED, mint.key().as_ref(), &denomination.to_le_bytes()],
        bump
    )]
    pub state: Account<'info, IncognitoState>,

    #[account(
        init,
        payer = payer,
        seeds = [VAULT_SEED, state.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = state,
        token::token_program = token_program
    )]
    pub vault: InterfaceAccount<'info, TokenAccount>,

    pub mint: InterfaceAccount<'info, Mint>,

    pub system_program: Program<'info, System>,
    pub token_program: Interface<'info, TokenInterface>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct SetRoot<'info> {
    pub root_updater: Signer<'info>,

    #[account(
        mut,
        seeds = [STATE_SEED, state.mint.as_ref(), &state.denomination.to_le_bytes()],
        bump = state.state_bump
    )]
    pub state: Account<'info, IncognitoState>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub depositor: Signer<'info>,

    #[account(mut, constraint = depositor_token.owner == depositor.key())]
    pub depositor_token: InterfaceAccount<'info, TokenAccount>,

    #[account(
        mut,
        seeds = [STATE_SEED, state.mint.as_ref(), &state.denomination.to_le_bytes()],
        bump = state.state_bump
    )]
    pub state: Account<'info, IncognitoState>,

    #[account(mut, seeds = [VAULT_SEED, state.key().as_ref()], bump = state.vault_bump)]
    pub vault: InterfaceAccount<'info, TokenAccount>,

    pub mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
#[instruction(proof: [u8; 256], nullifier_hash: [u8; 32])]
pub struct ActionWithdraw<'info> {
    #[account(mut)]
    pub relayer: Signer<'info>,

    #[account(
        mut,
        seeds = [STATE_SEED, state.mint.as_ref(), &state.denomination.to_le_bytes()],
        bump = state.state_bump
    )]
    pub state: Account<'info, IncognitoState>,

    #[account(mut, seeds = [VAULT_SEED, state.key().as_ref()], bump = state.vault_bump)]
    pub vault: InterfaceAccount<'info, TokenAccount>,

    #[account(
        init,
        payer = relayer,
        space = Nullifier::SPACE,
        seeds = [NULLIFIER_SEED, state.key().as_ref(), nullifier_hash.as_ref()],
        bump
    )]
    pub nullifier: Account<'info, Nullifier>,

    #[account(mut)]
    pub destination: InterfaceAccount<'info, TokenAccount>,

    pub mint: InterfaceAccount<'info, Mint>,

    pub system_program: Program<'info, System>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
#[instruction(initial_root: [u8; 32], root_updater: Pubkey)]
pub struct InitializeV2<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        init,
        payer = payer,
        space = IncognitoStateV2::SPACE,
        seeds = [STATE_SEED, mint.key().as_ref(), V2_SEED],
        bump
    )]
    pub state: Box<Account<'info, IncognitoStateV2>>,

    #[account(
        init,
        payer = payer,
        seeds = [VAULT_SEED, state.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = state,
        token::token_program = token_program
    )]
    pub vault: Box<InterfaceAccount<'info, TokenAccount>>,

    pub mint: InterfaceAccount<'info, Mint>,

    pub system_program: Program<'info, System>,
    pub token_program: Interface<'info, TokenInterface>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct SetRootV2<'info> {
    pub root_updater: Signer<'info>,

    #[account(
        mut,
        seeds = [STATE_SEED, state.mint.as_ref(), V2_SEED],
        bump = state.state_bump
    )]
    pub state: Box<Account<'info, IncognitoStateV2>>,
}

#[derive(Accounts)]
#[instruction(commitment: [u8; 32], amount: u64)]
pub struct DepositV2<'info> {
    #[account(mut)]
    pub depositor: Signer<'info>,

    #[account(mut, constraint = depositor_token.owner == depositor.key())]
    pub depositor_token: InterfaceAccount<'info, TokenAccount>,

    #[account(
        mut,
        seeds = [STATE_SEED, state.mint.as_ref(), V2_SEED],
        bump = state.state_bump
    )]
    pub state: Box<Account<'info, IncognitoStateV2>>,

    #[account(mut, seeds = [VAULT_SEED, state.key().as_ref()], bump = state.vault_bump)]
    pub vault: Box<InterfaceAccount<'info, TokenAccount>>,

    pub mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
#[instruction(
    proof: [u8; 256],
    root: [u8; 32],
    nullifier_hash: [u8; 32],
    withdraw_amount: u64,
    fee: u64,
    change_commitment: [u8; 32],
    nullifier_shard_byte: u8,
    nullifier_page_index: u16
)]
pub struct WithdrawV2<'info> {
    #[account(mut)]
    pub relayer: Signer<'info>,

    #[account(
        mut,
        seeds = [STATE_SEED, state.mint.as_ref(), V2_SEED],
        bump = state.state_bump
    )]
    pub state: Box<Account<'info, IncognitoStateV2>>,

    #[account(mut, seeds = [VAULT_SEED, state.key().as_ref()], bump = state.vault_bump)]
    pub vault: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(
        init_if_needed,
        payer = relayer,
        space = NullifierShard::SPACE,
        seeds = [NULLIFIER_SEED, state.key().as_ref(), &[nullifier_shard_byte]],
        bump
    )]
    pub nullifier_shard: Box<Account<'info, NullifierShard>>,

    #[account(
        init_if_needed,
        payer = relayer,
        space = NullifierPage::SPACE,
        seeds = [NULLIFIER_PAGE_SEED, state.key().as_ref(), &[nullifier_shard_byte], &nullifier_page_index.to_le_bytes()],
        bump
    )]
    /// CHECK: Zero-copy `NullifierPage` uses a manual discriminator + bytemuck-based parser to support `init_if_needed`.
    pub nullifier_page: UncheckedAccount<'info>,

    #[account(mut)]
    pub destination: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(mut, constraint = relayer_fee_ata.owner == relayer.key())]
    pub relayer_fee_ata: Box<InterfaceAccount<'info, TokenAccount>>,

    pub mint: Box<InterfaceAccount<'info, Mint>>,

    pub system_program: Program<'info, System>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[account]
pub struct IncognitoState {
    pub mint: Pubkey,
    pub denomination: u64,
    pub root_updater: Pubkey,
    pub merkle_root: [u8; 32],
    pub next_index: u32,
    pub state_bump: u8,
    pub vault_bump: u8,
}

impl IncognitoState {
    pub const SPACE: usize = 8 + 32 + 8 + 32 + 32 + 4 + 1 + 1;
}

#[account]
pub struct IncognitoStateV2 {
    pub mint: Pubkey,
    pub root_updater: Pubkey,
    pub merkle_root: [u8; 32],
    pub next_index: u32,
    pub root_history: [[u8; 32]; ROOT_HISTORY_SIZE],
    pub root_history_cursor: u8,
    pub state_bump: u8,
    pub vault_bump: u8,
}

impl IncognitoStateV2 {
    pub const SPACE: usize = 8 + 32 + 32 + 32 + 4 + (32 * ROOT_HISTORY_SIZE) + 1 + 1 + 1;
}

#[account]
pub struct Nullifier {}

impl Nullifier {
    pub const SPACE: usize = 8;
}

#[account]
pub struct NullifierShard {
    pub state: Pubkey,
    pub shard: u8,
    pub page_count: u16,
    pub bump: u8,
}

impl NullifierShard {
    pub const SPACE: usize = 8 + 32 + 1 + 2 + 1;
}

#[account(zero_copy)]
#[repr(C)]
pub struct NullifierPage {
    pub state: Pubkey,
    pub index: u16,
    pub len: u16,
    pub shard: u8,
    pub bump: u8,
    pub hashes: [[u8; 32]; NULLIFIER_PAGE_CAPACITY],
}

impl NullifierPage {
    pub const SPACE: usize = 8 + core::mem::size_of::<Self>();

    pub fn validate(&self, state: Pubkey, shard: u8, index: u16) -> Result<()> {
        require_keys_eq!(self.state, state, IncognitoError::InvalidNullifierPage);
        require!(self.shard == shard, IncognitoError::InvalidNullifierPage);
        require!(self.index == index, IncognitoError::InvalidNullifierPage);
        Ok(())
    }

    pub fn contains(&self, nullifier_hash: &[u8; 32]) -> bool {
        let n = self.len as usize;
        let max = if n > NULLIFIER_PAGE_CAPACITY {
            NULLIFIER_PAGE_CAPACITY
        } else {
            n
        };
        for i in 0..max {
            if &self.hashes[i] == nullifier_hash {
                return true;
            }
        }
        false
    }
}

#[event]
pub struct DepositEvent {
    pub state: Pubkey,
    pub mint: Pubkey,
    pub denomination: u64,
    pub commitment: [u8; 32],
    pub index: u32,
}

#[event]
pub struct DepositEventV2 {
    pub state: Pubkey,
    pub mint: Pubkey,
    pub commitment: [u8; 32],
    pub index: u32,
    pub is_change: bool,
}

#[event]
pub struct RootUpdatedEvent {
    pub state: Pubkey,
    pub mint: Pubkey,
    pub denomination: u64,
    pub merkle_root: [u8; 32],
    pub next_index: u32,
}

#[event]
pub struct RootUpdatedEventV2 {
    pub state: Pubkey,
    pub mint: Pubkey,
    pub merkle_root: [u8; 32],
    pub next_index: u32,
}

#[event]
pub struct WithdrawEvent {
    pub state: Pubkey,
    pub mint: Pubkey,
    pub denomination: u64,
    pub nullifier_hash: [u8; 32],
    pub destination: Pubkey,
}

#[event]
pub struct WithdrawEventV2 {
    pub state: Pubkey,
    pub mint: Pubkey,
    pub root: [u8; 32],
    pub nullifier_hash: [u8; 32],
    pub withdraw_amount: u64,
    pub fee: u64,
    pub recipient: Pubkey,
    pub change_commitment: [u8; 32],
    pub change_index: Option<u32>,
}

#[error_code]
pub enum IncognitoError {
    #[msg("Caller is not the configured root updater.")]
    UnauthorizedRootUpdater,
    #[msg("Token mint does not match the configured mint.")]
    InvalidMint,
    #[msg("Invalid deposit count (must be 1..=20).")]
    InvalidDepositCount,
    #[msg("Deposit amount overflow.")]
    DepositAmountOverflow,
    #[msg("Deposit index overflow.")]
    IndexOverflow,
    #[msg("Invalid Groth16 proof.")]
    InvalidProof,
    #[msg("Groth16 verifier syscall failed (alt_bn128).")]
    Groth16SyscallFailed,
    #[msg("Invalid deposit amount (must be > 0).")]
    InvalidDepositAmount,
    #[msg("Invalid commitment (not a valid BN254 Fr field element).")]
    InvalidCommitment,
    #[msg("Commitment amount mismatch (does not match deposit amount).")]
    CommitmentAmountMismatch,
    #[msg("Unknown Merkle root (not in history).")]
    UnknownRoot,
    #[msg("Invalid nullifier shard (must match nullifier_hash[0]).")]
    InvalidNullifierShard,
    #[msg("Missing required nullifier page account.")]
    MissingNullifierPage,
    #[msg("Nullifier already spent.")]
    NullifierAlreadySpent,
    #[msg("Invalid nullifier page.")]
    InvalidNullifierPage,
    #[msg("Nullifier page full.")]
    NullifierPageFull,
}

// -------------------------
// Helpers (v2)
// -------------------------

fn is_known_root(state: &IncognitoStateV2, root: &[u8; 32]) -> bool {
    if &state.merkle_root == root {
        return true;
    }
    for r in state.root_history.iter() {
        if r == root {
            return true;
        }
    }
    false
}

fn verify_groth16_v2(
    proof: &[u8; GROTH16_PROOF_BYTES],
    public_inputs: &[[u8; 32]; 9],
) -> Result<()> {
    let proof_a: [u8; GROTH16_A_BYTES] = proof[0..GROTH16_A_BYTES]
        .try_into()
        .map_err(|_| IncognitoError::InvalidProof)?;
    let proof_b: [u8; GROTH16_B_BYTES] = proof
        [GROTH16_A_BYTES..(GROTH16_A_BYTES + GROTH16_B_BYTES)]
        .try_into()
        .map_err(|_| IncognitoError::InvalidProof)?;
    let proof_c: [u8; GROTH16_C_BYTES] = proof
        [(GROTH16_A_BYTES + GROTH16_B_BYTES)..GROTH16_PROOF_BYTES]
        .try_into()
        .map_err(|_| IncognitoError::InvalidProof)?;

    let mut verifier = Groth16Verifier::<9>::new(
        &proof_a,
        &proof_b,
        &proof_c,
        public_inputs,
        &verifying_key_v2::VERIFYINGKEY,
    )
    .map_err(|e| {
        msg!("groth16 verifier init failed: {}", e);
        match e {
            Groth16Error::InvalidG1Length
            | Groth16Error::InvalidG2Length
            | Groth16Error::InvalidPublicInputsLength
            | Groth16Error::PublicInputGreaterThanFieldSize
            | Groth16Error::IncompatibleVerifyingKeyWithNrPublicInputs => {
                IncognitoError::InvalidProof
            }
            _ => IncognitoError::Groth16SyscallFailed,
        }
    })?;

    verifier.verify().map_err(|e| {
        msg!("groth16 verify failed: {}", e);
        match e {
            Groth16Error::ProofVerificationFailed => IncognitoError::InvalidProof,
            _ => IncognitoError::Groth16SyscallFailed,
        }
    })?;

    Ok(())
}

struct NullifierInsertArgsV2<'a> {
    program_id: &'a Pubkey,
    state_key: Pubkey,
    nullifier_hash: &'a [u8; 32],
    nullifier_shard_byte: u8,
    nullifier_page_index: u16,
    bump_shard: u8,
    bump_page: u8,
}

fn check_and_insert_nullifier_v2(
    args: NullifierInsertArgsV2<'_>,
    nullifier_shard: &mut Account<'_, NullifierShard>,
    nullifier_page: &AccountInfo<'_>,
    remaining_accounts: &[AccountInfo<'_>],
) -> Result<()> {
    init_or_validate_nullifier_shard(
        nullifier_shard,
        args.state_key,
        args.nullifier_shard_byte,
        args.bump_shard,
    )?;
    let existing_pages = nullifier_shard.page_count;

    let mut last_page_len: Option<u16> = None;
    for idx in 0..existing_pages {
        let (page_len, contains) = if idx == args.nullifier_page_index {
            nullifier_page_contains_and_len(
                nullifier_page,
                args.state_key,
                args.nullifier_shard_byte,
                idx,
                args.nullifier_hash,
            )?
        } else {
            let expected = expected_nullifier_page_pda(
                args.program_id,
                args.state_key,
                args.nullifier_shard_byte,
                idx,
            );
            let ai = remaining_accounts
                .iter()
                .find(|a| a.key() == expected)
                .ok_or_else(|| error!(IncognitoError::MissingNullifierPage))?;
            nullifier_page_contains_and_len(
                ai,
                args.state_key,
                args.nullifier_shard_byte,
                idx,
                args.nullifier_hash,
            )?
        };
        if contains {
            return err!(IncognitoError::NullifierAlreadySpent);
        }
        if idx + 1 == existing_pages {
            last_page_len = Some(page_len);
        }
    }

    if existing_pages == 0 {
        require!(
            args.nullifier_page_index == 0,
            IncognitoError::InvalidNullifierPage
        );
    } else if args.nullifier_page_index < existing_pages {
        require!(
            args.nullifier_page_index + 1 == existing_pages,
            IncognitoError::InvalidNullifierPage
        );
    } else if args.nullifier_page_index == existing_pages {
        require!(
            last_page_len.unwrap_or(0) as usize >= NULLIFIER_PAGE_CAPACITY,
            IncognitoError::InvalidNullifierPage
        );
    } else {
        return err!(IncognitoError::InvalidNullifierPage);
    }

    {
        use anchor_lang::Discriminator;
        use bytemuck::from_bytes_mut;
        use core::mem::size_of;

        require!(
            nullifier_page.is_writable,
            IncognitoError::InvalidNullifierPage
        );

        let mut data = nullifier_page.try_borrow_mut_data()?;
        let disc = NullifierPage::discriminator();
        require!(
            data.len() >= (8 + size_of::<NullifierPage>()),
            IncognitoError::InvalidNullifierPage
        );

        let given_disc = &data[0..8];
        let has_disc = given_disc.iter().any(|b| *b != 0);
        if has_disc {
            require!(given_disc == disc, IncognitoError::InvalidNullifierPage);
        } else {
            data[0..8].copy_from_slice(&disc);
        }

        let page: &mut NullifierPage =
            from_bytes_mut(&mut data[8..(8 + size_of::<NullifierPage>())]);

        init_or_validate_nullifier_page(
            page,
            args.state_key,
            args.nullifier_shard_byte,
            args.nullifier_page_index,
            args.bump_page,
        )?;

        if page.len as usize >= NULLIFIER_PAGE_CAPACITY {
            return err!(IncognitoError::NullifierPageFull);
        }

        if args.nullifier_page_index + 1 > nullifier_shard.page_count {
            nullifier_shard.page_count = args.nullifier_page_index + 1;
        }

        let insert_i = page.len as usize;
        page.hashes[insert_i] = *args.nullifier_hash;
        page.len = page
            .len
            .checked_add(1)
            .ok_or(IncognitoError::IndexOverflow)?;
    }

    Ok(())
}

fn u64_to_be_bytes32(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&v.to_be_bytes());
    out
}

fn u128_to_be_bytes32(v: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..32].copy_from_slice(&v.to_be_bytes());
    out
}

fn pubkey_to_u128_halves_le(pk: &Pubkey) -> (u128, u128) {
    let b = pk.to_bytes();
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    lo.copy_from_slice(&b[0..16]);
    hi.copy_from_slice(&b[16..32]);
    (u128::from_le_bytes(lo), u128::from_le_bytes(hi))
}

fn expected_nullifier_page_pda(
    program_id: &Pubkey,
    state: Pubkey,
    shard: u8,
    index: u16,
) -> Pubkey {
    Pubkey::find_program_address(
        &[
            NULLIFIER_PAGE_SEED,
            state.as_ref(),
            &[shard],
            &index.to_le_bytes(),
        ],
        program_id,
    )
    .0
}

fn init_or_validate_nullifier_shard(
    shard: &mut Account<NullifierShard>,
    state: Pubkey,
    shard_byte: u8,
    bump: u8,
) -> Result<()> {
    if shard.state == Pubkey::default() {
        shard.state = state;
        shard.shard = shard_byte;
        shard.page_count = 0;
        shard.bump = bump;
        return Ok(());
    }
    require_keys_eq!(shard.state, state, IncognitoError::InvalidNullifierPage);
    require!(
        shard.shard == shard_byte,
        IncognitoError::InvalidNullifierPage
    );
    Ok(())
}

fn init_or_validate_nullifier_page(
    page: &mut NullifierPage,
    state: Pubkey,
    shard_byte: u8,
    index: u16,
    bump: u8,
) -> Result<()> {
    if page.state == Pubkey::default() {
        page.state = state;
        page.shard = shard_byte;
        page.index = index;
        page.len = 0;
        page.bump = bump;
        return Ok(());
    }
    page.validate(state, shard_byte, index)
}

fn nullifier_page_contains_and_len(
    ai: &AccountInfo,
    state: Pubkey,
    shard: u8,
    index: u16,
    nullifier_hash: &[u8; 32],
) -> Result<(u16, bool)> {
    use anchor_lang::Discriminator;

    // Minimal parsing to avoid copying the whole `hashes` array onto the stack.
    let data = ai.data.borrow();
    // NullifierPage field order avoids padding (Pod requirement).
    let header_len = 8 + 32 + 2 + 2 + 1 + 1;
    require!(
        data.len() >= header_len,
        IncognitoError::InvalidNullifierPage
    );
    require!(
        data[0..8] == NullifierPage::discriminator(),
        IncognitoError::InvalidNullifierPage
    );

    let state_off = 8;
    let index_off = state_off + 32;
    let len_off = index_off + 2;
    let shard_off = len_off + 2;
    let bump_off = shard_off + 1;
    let hashes_off = bump_off + 1;

    let page_state = Pubkey::new_from_array(data[state_off..state_off + 32].try_into().unwrap());
    require_keys_eq!(page_state, state, IncognitoError::InvalidNullifierPage);

    let page_index = u16::from_le_bytes(data[index_off..index_off + 2].try_into().unwrap());
    require!(page_index == index, IncognitoError::InvalidNullifierPage);

    let len = u16::from_le_bytes(data[len_off..len_off + 2].try_into().unwrap());
    require!(
        data[shard_off] == shard,
        IncognitoError::InvalidNullifierPage
    );
    let max = std::cmp::min(len as usize, NULLIFIER_PAGE_CAPACITY);
    let needed = 8 + core::mem::size_of::<NullifierPage>();
    require!(data.len() >= needed, IncognitoError::InvalidNullifierPage);

    for i in 0..max {
        let off = hashes_off + (i * 32);
        if &data[off..off + 32] == nullifier_hash {
            return Ok((len, true));
        }
    }

    Ok((len, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_known_root_checks_current_and_history() {
        let mut s = IncognitoStateV2 {
            mint: Pubkey::new_unique(),
            root_updater: Pubkey::new_unique(),
            merkle_root: [1u8; 32],
            next_index: 0,
            root_history: [[0u8; 32]; ROOT_HISTORY_SIZE],
            root_history_cursor: 0,
            state_bump: 1,
            vault_bump: 2,
        };

        assert!(is_known_root(&s, &[1u8; 32]));
        assert!(!is_known_root(&s, &[2u8; 32]));

        s.root_history[0] = [9u8; 32];
        assert!(is_known_root(&s, &[9u8; 32]));
    }

    #[test]
    fn test_nullifier_page_contains_respects_len() {
        let state = Pubkey::new_unique();
        let mut page = NullifierPage {
            state,
            index: 0,
            len: 2,
            shard: 7,
            bump: 255,
            hashes: [[0u8; 32]; NULLIFIER_PAGE_CAPACITY],
        };
        page.hashes[0] = [1u8; 32];
        page.hashes[1] = [2u8; 32];
        page.hashes[2] = [3u8; 32];

        assert!(page.contains(&[1u8; 32]));
        assert!(page.contains(&[2u8; 32]));
        assert!(!page.contains(&[3u8; 32]));
    }
}
