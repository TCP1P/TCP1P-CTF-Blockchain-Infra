import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Setup } from "../target/types/setup";
import { Keypair } from "@solana/web3.js";

const solvedAccount = process.env.solvedAccount;

describe("setup", () => { 
  const provider = anchor.AnchorProvider.env()
  const solveAccountKeypair =  Keypair.fromSecretKey(Uint8Array.from(JSON.parse(solvedAccount)))
  anchor.setProvider(provider);
  const program = anchor.workspace.Setup as Program<Setup>;
  it("initialize program", async () => {
    const tx = await program.methods.isSolved().accounts({
      solvedAccount: solveAccountKeypair.publicKey,
    }).view({"commitment": "finalized"});
    console.log(JSON.stringify({"message": tx}));
  });
});
