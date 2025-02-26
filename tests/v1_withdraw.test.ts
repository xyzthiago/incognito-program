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

type WithdrawV1Fixture = {
  proofBytes: number[]
  commitmentBe: number[]
  publicInputsBe: { root: number[]; nullifierHash: number[] }
}

describe('incognito_program v1', () => {
  const provider = anchor.AnchorProvider.local()
  anchor.setProvider(provider)

  const program = anchor.workspace.IncognitoProgram as Program<anchor.Idl>

  it('deposit → withdraw succeeds; double-spend fails', async () => {
    const payerKeypair = (provider.wallet as any).payer as Keypair

    const fixturePath = path.resolve(process.cwd(), 'tests/fixtures/withdraw_v1_fixture.json')
    const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8')) as WithdrawV1Fixture

    expect(fixture.proofBytes).to.have.length(256)
    expect(fixture.commitmentBe).to.have.length(32)
    expect(fixture.publicInputsBe.root).to.have.length(32)
    expect(fixture.publicInputsBe.nullifierHash).to.have.length(32)

    const denomination = new anchor.BN(1)
    const initialRoot = Array(32).fill(0)

    const mint = await createMint(provider.connection, payerKeypair, payerKeypair.publicKey, null, 0)

    const state = pda(program.programId, [Buffer.from('state'), mint.toBuffer(), denomination.toArrayLike(Buffer, 'le', 8)])
    const vault = pda(program.programId, [Buffer.from('vault'), state.toBuffer()])

    await program.methods
      .initializePool(denomination, initialRoot, payerKeypair.publicKey)
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

    const depositorToken = await createAccount(provider.connection, payerKeypair, mint, payerKeypair.publicKey)
    const destinationOwner = Keypair.generate()
    const destinationToken = await createAccount(provider.connection, payerKeypair, mint, destinationOwner.publicKey)

    await program.methods
      .setRoot(fixture.publicInputsBe.root)
      .accounts({ rootUpdater: payerKeypair.publicKey, state })
      .rpc()

    await mintTo(provider.connection, payerKeypair, mint, depositorToken, payerKeypair, 1)

    await program.methods
      .deposit(fixture.commitmentBe)
      .accounts({
        depositor: payerKeypair.publicKey,
        depositorToken,
        state,
        vault,
        mint,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .rpc()

    const nullifier = pda(program.programId, [
      Buffer.from('nullifier'),
      state.toBuffer(),
      Buffer.from(fixture.publicInputsBe.nullifierHash),
    ])

    await program.methods
      .actionWithdraw(fixture.proofBytes, fixture.publicInputsBe.nullifierHash)
      .accounts({
        relayer: payerKeypair.publicKey,
        state,
        vault,
        nullifier,
        destination: destinationToken,
        mint,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc()

    const dest = await getAccount(provider.connection, destinationToken)
    expect(Number(dest.amount)).to.equal(1)

    // Spend again should fail (nullifier PDA already exists).
    let threw = false
    try {
      await program.methods
        .actionWithdraw(fixture.proofBytes, fixture.publicInputsBe.nullifierHash)
        .accounts({
          relayer: payerKeypair.publicKey,
          state,
          vault,
          nullifier,
          destination: destinationToken,
          mint,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc()
    } catch {
      threw = true
    }
    expect(threw).to.equal(true)
  })
})
