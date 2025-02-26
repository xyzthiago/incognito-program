import * as anchorPkg from '@coral-xyz/anchor'
import type { Program } from '@coral-xyz/anchor'
import { Keypair, PublicKey } from '@solana/web3.js'
import {
  TOKEN_2022_PROGRAM_ID,
  createMint,
  createAccount,
  mintTo,
  getAccount,
} from '@solana/spl-token'
import { expect } from 'chai'

const anchor = (anchorPkg as any).default ?? anchorPkg

function pda(programId: PublicKey, seeds: (Buffer | Uint8Array)[]) {
  return PublicKey.findProgramAddressSync(seeds, programId)[0]
}

function commitmentForAmount(amount: bigint): number[] {
  const out = Buffer.alloc(32, 0)
  out.writeBigUInt64BE(amount, 24)
  return Array.from(out)
}

describe('incognito_program v2 (Token-2022)', () => {
  const provider = anchor.AnchorProvider.local()
  anchor.setProvider(provider)

  const program = anchor.workspace.IncognitoProgram as Program<anchor.Idl>

  it('deposit_v2 works with Token-2022 mint/token accounts', async () => {
    const payerKeypair = (provider.wallet as any).payer as Keypair

    const mint = await createMint(
      provider.connection,
      payerKeypair,
      payerKeypair.publicKey,
      null,
      6,
      undefined,
      undefined,
      TOKEN_2022_PROGRAM_ID,
    )

    const state = pda(program.programId, [Buffer.from('state'), mint.toBuffer(), Buffer.from('v2')])
    const vault = pda(program.programId, [Buffer.from('vault'), state.toBuffer()])

    await program.methods
      .initializePoolV2(Array(32).fill(0), payerKeypair.publicKey)
      .accounts({
        payer: payerKeypair.publicKey,
        state,
        vault,
        mint,
        tokenProgram: TOKEN_2022_PROGRAM_ID,
        systemProgram: anchor.web3.SystemProgram.programId,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
      })
      .rpc()

    const depositorToken = await createAccount(
      provider.connection,
      payerKeypair,
      mint,
      payerKeypair.publicKey,
      Keypair.generate(),
      undefined,
      TOKEN_2022_PROGRAM_ID,
    )

    const amountIn = 123_456n
    await mintTo(
      provider.connection,
      payerKeypair,
      mint,
      depositorToken,
      payerKeypair,
      amountIn,
      [],
      undefined,
      TOKEN_2022_PROGRAM_ID,
    )

    const sig = await program.methods
      .depositV2(commitmentForAmount(amountIn), new anchor.BN(amountIn.toString()))
      .accounts({
        depositor: payerKeypair.publicKey,
        depositorToken,
        state,
        vault,
        mint,
        tokenProgram: TOKEN_2022_PROGRAM_ID,
      })
      .rpc()

    await provider.connection.confirmTransaction(sig, 'confirmed')

    const vaultAcc = await getAccount(provider.connection, vault, 'confirmed', TOKEN_2022_PROGRAM_ID)
    const depositorAccAfter = await getAccount(
      provider.connection,
      depositorToken,
      'confirmed',
      TOKEN_2022_PROGRAM_ID,
    )

    if (BigInt(vaultAcc.amount.toString()) !== amountIn) {
      const vaultInfo = await provider.connection.getAccountInfo(vault, 'confirmed')
      const tx = await provider.connection.getTransaction(sig, {
        commitment: 'confirmed',
        maxSupportedTransactionVersion: 0,
      })
      console.error('[token2022 deposit debug]', {
        depositorAfter: depositorAccAfter.amount.toString(),
        vaultAfter: vaultAcc.amount.toString(),
        vaultOwner: vaultInfo?.owner?.toBase58(),
        vaultDataLen: vaultInfo?.data?.length,
        logs: tx?.meta?.logMessages,
      })
    }

    expect(BigInt(vaultAcc.amount.toString())).to.equal(amountIn)
    expect(BigInt(depositorAccAfter.amount.toString())).to.equal(0n)
  })
})
