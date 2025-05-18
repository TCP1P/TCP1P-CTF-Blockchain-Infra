const anchor = require('@coral-xyz/anchor');
const bs58 = require('bs58');
const { SystemProgram, Keypair, PublicKey } = anchor.web3;

// Replace these values with your own
const RPC_URL = "http://localhost:48334/b916b4c9-cb56-492c-ab5f-98ffb1368b65";
const PLAYER_KEYPAIR = "46hjyF7WNumqGsGpy2k7zHLBA5L6bxhkb28NEmWgsirN5TLBQLo1NL14HnYxUpbLSKBpx9CZg1SsUj4EuG3TzVKV";
const CTX_PUBKEY = "E7ooFfZCRqy7Y4gpgLmBSUxDAy4YYx2KvL4GSmQ9dffe";
const PROGRAM_ID = "nNeVXm78SpkbdqP8vhPmWz5gZqJbmNQja7NQdBHdDnq";

const main = async () => {
  // Create a connection to the cluster
  const connection = new anchor.web3.Connection(RPC_URL);

  // Decode the base58 secret key to create the wallet keypair
  const secretKey = bs58.default.decode(PLAYER_KEYPAIR);
  const walletKeypair = Keypair.fromSecretKey(secretKey);
  const wallet = new anchor.Wallet(walletKeypair);

  // Create a provider and set it as the default
  const provider = new anchor.AnchorProvider(connection, wallet, { commitment: "finalized" });
  anchor.setProvider(provider);

  // Fetch your program's IDL from the JSON RPC
  const programId = new PublicKey(PROGRAM_ID);
  const program = await anchor.Program.at(programId, provider);

  // Define the context account public key
  const ctxPubkey = new PublicKey(CTX_PUBKEY);

  // Call the "solve" instruction
  const txSolve = await program.methods.solve().accounts({
      solvedAccount: ctxPubkey,
      user: provider.wallet.publicKey,
      systemProgram: SystemProgram.programId,
  }).transaction();
  const txSolveSignature = await connection.sendTransaction(txSolve, [wallet.payer])
  console.log("Solve tx:", txSolveSignature);

  let isSolved = false;
  while (!isSolved) {
    const txIsSolved = await program.views.isSolved({
      accounts: {
        solvedAccount: ctxPubkey,
        user: provider.wallet.publicKey,
        systemProgram: SystemProgram.programId,
      },
    });
    if (txIsSolved) {
      isSolved = true;
      console.log("Challenge solved successfully.");
    } else {
      console.log("Challenge not yet solved. Trying again...");
      await new Promise(resolve => setTimeout(resolve, 1000)); // Wait for 1 second before trying again
    }
  }
};
main()
