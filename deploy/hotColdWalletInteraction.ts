import { utils, Wallet, Provider, Contract, EIP712Signer, types, ECDSASmartAccount } from "zksync-ethers";
import * as ethers from "ethers";
import { HardhatRuntimeEnvironment } from "hardhat/types";

// load env file
import dotenv from "dotenv";
import { util } from "chai";
dotenv.config();

/*
  1. We modify the signature format by adding a prefix to indicate which wallet signed the transaction.
  2. Interactions with zkSync are similar to Ethereum with some zkSync-specific modifications.
  3. Ensure you handle errors and edge cases, such as insufficient balance or invalid signatures, as needed.


*/

// Put the address of your AA factory
const AA_FACTORY_ADDRESS = "0x91f7265d420Ed43a329E1C093a6dAaE78D138C12";

// load the values into .env file after deploying the FactoryAccount
const DEPLOYED_ACCOUNT_OWNER_PRIVATE_KEY = process.env.DEPLOYED_ACCOUNT_OWNER_PRIVATE_KEY || "";
const ETH_ADDRESS = process.env.ETH_ADDRESS || "0x000000000000000000000000000000000000800A";
const ACCOUNT_ADDRESS = process.env.DEPLOYED_ACCOUNT_ADDRESS || "";

export default async function (hre: HardhatRuntimeEnvironment) {
  // @ts-ignore target zkSyncSepoliaTestnet in config file which can be testnet or local
  const provider = new Provider(hre.config.networks.zkSyncSepoliaTestnet.url);

  // Private key of the account used to deploy
  const wallet = new Wallet(DEPLOYED_ACCOUNT_OWNER_PRIVATE_KEY).connect(provider);
  const factoryArtifact = await hre.artifacts.readArtifact("AAFactory");
  const aaFactory = new ethers.Contract(AA_FACTORY_ADDRESS, factoryArtifact.abi, wallet);


  // Initialize hot and cold wallets
  const hotWalletPrivateKey = Wallet.createRandom().privateKey;
  const coldWalletPrivateKey = Wallet.createRandom().privateKey;
  const hotWallet = new Wallet(hotWalletPrivateKey, provider);
  const coldWallet = new Wallet(coldWalletPrivateKey, provider);

  // For the simplicity of the tutorial, we will use zero hash as salt
  const salt = ethers.ZeroHash;

  // deploy account owned by one owner but with two wallets, hot and cold wallet
  const tx = await aaFactory.deployAccount(salt, hotWallet, coldWallet, 0);
  await tx.wait();

  // Getting the address of the deployed contract account
  // Always use the JS utility methods
  const abiCoder = new ethers.AbiCoder();

  // The create2Address Generates a future-proof contract address using salt plus bytecode which allows determination of an address before deployment.
  const hotColdAddress = utils.create2Address(
    AA_FACTORY_ADDRESS,
    await aaFactory.aaBytecodeHash(),
    salt,
    abiCoder.encode(["address", "address", "uint256"], [hotWallet.address, coldWallet.address, 0])
  );

  console.log(`HotCold account deployed on address: ${hotColdAddress}`);

  console.log("Sending funds to HotCold account");
  // Send funds to the multisig account we just deployed
  await (
    await wallet.sendTransaction({
      to: hotColdAddress,
      // You can increase the amount of ETH sent to the HotCold
      value: ethers.parseEther("0.001"),
      nonce: await wallet.getNonce(),
    })
  ).wait();

  // HotCold balance
  let hotColdBalance = await provider.getBalance(hotColdAddress);
  console.log(`hotCold account balance is ${hotColdBalance.toString()}`);

  // We need to send a transaction from the hotColdAddress so we can activate the restriction?
  // TODO: Are we good at this point?


  // Define transaction parameters
  const to = 'recipient-address';
  const value = ethers.parseEther('0.01'); // Value in ETH
  const data = '0x'; // Optional data field


  // Transaction to deploy a new account using the multisig we just deployed
  let transaction = await aaFactory.deployAccount.populateTransaction(
    salt,
    // These are accounts that will own the newly deployed account
    hotWallet.address,
    coldWallet.address
  );


  const gasLimit = await provider.estimateGas({ ...transaction, from: wallet.address });
  const gasPrice = await provider.getGasPrice();

  // Create a transaction object
  transaction = {
      to,
      value,
      data,
      nonce: await provider.getTransactionCount(hotWallet.address),
      gasLimit: gasLimit,
      gasPrice: gasPrice,
  };


  // Encode the transaction hash
  const txHash = ethers.keccak256(abiCoder.encode(
      ['address', 'uint256', 'bytes', 'uint256', 'uint256'],
      [transaction.to, transaction.value, transaction.data, transaction.nonce, transaction.gasLimit, transaction.gasPrice]
  ));


  // Sign the transaction hash with hot wallet
  const hotWalletSignature = await hotWallet.signMessage(utils.arrayify(txHash));
  const modifiedSignature = '0x00' + hotWalletSignature.slice(2); // Add prefix for hot wallet


  // Construct transaction with the new signature format
  const signedTransaction = {
    ...transaction,
    signature: modifiedSignature
  };


  // Send the transaction
  const txResponse = await hotWallet.sendTransaction(signedTransaction);
  console.log('Transaction Hash:', txResponse.hash);

 // Wait for transaction confirmation
  const receipt = await txResponse.wait();
  console.log('Transaction Receipt:', receipt);

}
