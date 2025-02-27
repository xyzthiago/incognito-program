import * as anchorPkg from '@coral-xyz/anchor'
import type { Program } from '@coral-xyz/anchor'
import { Keypair, PublicKey } from '@solana/web3.js'
import {
  TOKEN_PROGRAM_ID,
  createMint,
  createAccount,
  mintTo,
  getAccount,
} from '@solana/spl-token'
import { expect } from 'chai'
import fs from 'fs'
import path from 'path'

const anchor = (anchorPkg as any).default ?? anchorPkg

function pda(programId: PublicKey, seeds: (Buffer | Uint8Array)[]) {
  return PublicKey.findProgramAddressSync(seeds, programId)[0]
}

type SpendWithChangeV2Fixture = {
  recipientSeed?: number[]
  mintSeed: number[]
  mint: string
  recipient: string
  decimals: number
  deposit: { amountIn: string; commitmentBe: number[] }
  withdraw: {
    rootBe: number[]
    proofBytes: number[]
    nullifierHashBe: number[]
    withdrawAmount: string
    fee: string
    changeCommitmentBe: number[]
    nullifierShardByte: number
    nullifierPageIndex: number
  }
}

describe('incognito_program v2', () => {
  const provider = anchor.AnchorProvider.local()
  anchor.setProvider(provider)

  const program = anchor.workspace.IncognitoProgram as Program<anchor.Idl>

  it('deposit_v2 → set_root_v2 → withdraw_v2 works; double-spend + invalid roots fail', async () => {
    const payerKeypair = (provider.wallet as any).payer as Keypair

    const fixturePath = path.resolve(process.cwd(), 'tests/fixtures/spend_with_change_v2_fixture.json')
    const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8')) as SpendWithChangeV2Fixture

    expect(fixture.withdraw.proofBytes).to.have.length(256)
    expect(fixture.withdraw.rootBe).to.have.length(32)
    expect(fixture.withdraw.nullifierHashBe).to.have.length(32)
    expect(fixture.withdraw.changeCommitmentBe).to.have.length(32)
    expect(fixture.deposit.commitmentBe).to.have.length(32)

    const mintKeypair = Keypair.fromSeed(Uint8Array.from(fixture.mintSeed))
    const mint = await createMint(
      provider.connection,
      payerKeypair,
      payerKeypair.publicKey,
      null,
      fixture.decimals,
      mintKeypair,
      undefined,
      TOKEN_PROGRAM_ID,
    )
    expect(mint.toBase58()).to.equal(fixture.mint)

    const state = pda(program.programId, [Buffer.from('state'), mint.toBuffer(), Buffer.from('v2')])
    const vault = pda(program.programId, [Buffer.from('vault'), state.toBuffer()])

    await program.methods
      .initializePoolV2(Array(32).fill(0), payerKeypair.publicKey)
      .accounts({
        payer: payerKeypair.publicKey,
        state,
        vault,
        mint,
        tokenProgram: TOKEN_PROGRAM_ID,
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
    )
    const recipientOwner = new PublicKey(fixture.recipient)
    const destinationToken = await createAccount(
      provider.connection,
      payerKeypair,
      mint,
      recipientOwner,
      Keypair.generate(),
    )
    const relayerFeeAta = await createAccount(
      provider.connection,
      payerKeypair,
      mint,
      payerKeypair.publicKey,
      Keypair.generate(),
    )

    // Fund depositor for deposit_v2.
    const amountIn = BigInt(fixture.deposit.amountIn)
    await mintTo(provider.connection, payerKeypair, mint, depositorToken, payerKeypair, amountIn)

    // Negative: commitment amount mismatch should fail before transfer.
    let mismatchThrew = false
    try {
      await program.methods
        .depositV2(fixture.deposit.commitmentBe, new anchor.BN((amountIn + 1n).toString()))
        .accounts({
          depositor: payerKeypair.publicKey,
          depositorToken,
          state,
          vault,
          mint,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .rpc()
    } catch {
      mismatchThrew = true
    }
    expect(mismatchThrew).to.equal(true)

    // Real deposit
    await program.methods
      .depositV2(fixture.deposit.commitmentBe, new anchor.BN(amountIn.toString()))
      .accounts({
        depositor: payerKeypair.publicKey,
        depositorToken,
        state,
        vault,
        mint,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .rpc()

    await program.methods
      .setRootV2(fixture.withdraw.rootBe)
      .accounts({ rootUpdater: payerKeypair.publicKey, state })
      .rpc()

    const shardByte = fixture.withdraw.nullifierShardByte
    const pageIndex = fixture.withdraw.nullifierPageIndex

    const nullifierShard = pda(program.programId, [Buffer.from('nullifier'), state.toBuffer(), Buffer.from([shardByte])])
    const pageIndexLe = Buffer.alloc(2)
    pageIndexLe.writeUInt16LE(pageIndex, 0)
    const nullifierPage = pda(program.programId, [
      Buffer.from('nullifier_page'),
      state.toBuffer(),
      Buffer.from([shardByte]),
      pageIndexLe,
    ])

    // These should not exist before the first withdraw.
    const shardInfoBefore = await provider.connection.getAccountInfo(nullifierShard, 'confirmed')
    const pageInfoBefore = await provider.connection.getAccountInfo(nullifierPage, 'confirmed')
    expect(shardInfoBefore).to.equal(null)
    expect(pageInfoBefore).to.equal(null)

    const withdrawAmount = new anchor.BN(BigInt(fixture.withdraw.withdrawAmount).toString())
    const fee = new anchor.BN(BigInt(fixture.withdraw.fee).toString())

    // Negative: wrong shard byte fails before proof verification.
    let shardThrew = false
    try {
      await program.methods
        .withdrawV2(
          fixture.withdraw.proofBytes,
          fixture.withdraw.rootBe,
          fixture.withdraw.nullifierHashBe,
          withdrawAmount,
          fee,
          fixture.withdraw.changeCommitmentBe,
          (shardByte + 1) & 0xff,
          pageIndex,
        )
        .accounts({
          relayer: payerKeypair.publicKey,
          state,
          vault,
          nullifierShard,
          nullifierPage,
          destination: destinationToken,
          relayerFeeAta,
          mint,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc()
    } catch {
      shardThrew = true
    }
    expect(shardThrew).to.equal(true)

    // Negative: unknown root fails before proof verification.
    const unknownRoot = Array.from({ length: 32 }, (_, i) => (i + 1) & 0xff)
    let rootThrew = false
    try {
      await program.methods
        .withdrawV2(
          fixture.withdraw.proofBytes,
          unknownRoot,
          fixture.withdraw.nullifierHashBe,
          withdrawAmount,
          fee,
          fixture.withdraw.changeCommitmentBe,
          shardByte,
          pageIndex,
        )
        .accounts({
          relayer: payerKeypair.publicKey,
          state,
          vault,
          nullifierShard,
          nullifierPage,
          destination: destinationToken,
          relayerFeeAta,
          mint,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc()
    } catch {
      rootThrew = true
    }
    expect(rootThrew).to.equal(true)

    // Negative: destination token account must match the pool mint.
    const otherMint = await createMint(
      provider.connection,
      payerKeypair,
      payerKeypair.publicKey,
      null,
      fixture.decimals,
      undefined,
      undefined,
      TOKEN_PROGRAM_ID,
    )
    const badDestinationToken = await createAccount(
      provider.connection,
      payerKeypair,
      otherMint,
      recipientOwner,
      Keypair.generate(),
    )
    let destinationMintThrew = false
    try {
      await program.methods
        .withdrawV2(
          fixture.withdraw.proofBytes,
          fixture.withdraw.rootBe,
          fixture.withdraw.nullifierHashBe,
          withdrawAmount,
          fee,
          fixture.withdraw.changeCommitmentBe,
          shardByte,
          pageIndex,
        )
        .accounts({
          relayer: payerKeypair.publicKey,
          state,
          vault,
          nullifierShard,
          nullifierPage,
          destination: badDestinationToken,
          relayerFeeAta,
          mint,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc()
    } catch {
      destinationMintThrew = true
    }
    expect(destinationMintThrew).to.equal(true)

    // Happy-path withdraw (partial withdrawal + change commitment).
    try {
      await program.methods
        .withdrawV2(
          fixture.withdraw.proofBytes,
          fixture.withdraw.rootBe,
          fixture.withdraw.nullifierHashBe,
          withdrawAmount,
          fee,
          fixture.withdraw.changeCommitmentBe,
          shardByte,
          pageIndex,
        )
        .accounts({
          relayer: payerKeypair.publicKey,
          state,
          vault,
          nullifierShard,
          nullifierPage,
          destination: destinationToken,
          relayerFeeAta,
          mint,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc()
    } catch (e: any) {
      if (e?.logs) console.error('withdraw_v2 logs:', e.logs)
      throw e
    }

    const dest = await getAccount(provider.connection, destinationToken)
    expect(BigInt(dest.amount.toString())).to.equal(BigInt(fixture.withdraw.withdrawAmount))

    const stateAcc = await program.account.incognitoStateV2.fetch(state)
    // deposit increments next_index to 1; change append increments it again to 2.
    expect(Number(stateAcc.nextIndex)).to.equal(2)

    // Double spend should fail (nullifier already stored in the page).
    let doubleSpendThrew = false
    try {
      await program.methods
        .withdrawV2(
          fixture.withdraw.proofBytes,
          fixture.withdraw.rootBe,
          fixture.withdraw.nullifierHashBe,
          withdrawAmount,
          fee,
          fixture.withdraw.changeCommitmentBe,
          shardByte,
          pageIndex,
        )
        .accounts({
          relayer: payerKeypair.publicKey,
          state,
          vault,
          nullifierShard,
          nullifierPage,
          destination: destinationToken,
          relayerFeeAta,
          mint,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc()
    } catch {
      doubleSpendThrew = true
    }
    expect(doubleSpendThrew).to.equal(true)
  })
})
