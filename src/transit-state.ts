/**
 * State transition is a process of publishing the new issuer state after the claim is added to the claim tree.
 *
 * @see https://0xpolygonid.github.io/js-sdk-tutorials/docs/tutorial-basics/transit-state
 */

import {
  BjjProvider,
  CircuitData,
  CircuitId,
  CircuitStorage,
  core,
  CredentialRequest,
  CredentialStorage,
  CredentialWallet,
  defaultEthConnectionConfig,
  EthConnectionConfig,
  EthStateStorage,
  FSKeyLoader,
  ICredentialWallet,
  IDataStorage,
  Identity,
  IdentityStorage,
  IdentityWallet,
  IIdentityWallet,
  InMemoryDataSource,
  InMemoryMerkleTreeStorage,
  InMemoryPrivateKeyStore,
  IStateStorage,
  KMS,
  KmsKeyType,
  Profile,
  ProofService,
  W3CCredential,
} from "@0xpolygonid/js-sdk";
import { ethers } from "ethers";
import path from "path";

import config from "./config";

const { rhsUrl, rpcUrl, contractAddress, walletKey, circuitsFolder } = config;

function initDataStorage(): IDataStorage {
  const conf: EthConnectionConfig = {
    ...defaultEthConnectionConfig,
    contractAddress,
    url: rpcUrl,
  };

  const dataStorage = {
    credential: new CredentialStorage(new InMemoryDataSource<W3CCredential>()),
    identity: new IdentityStorage(
      new InMemoryDataSource<Identity>(),
      new InMemoryDataSource<Profile>()
    ),
    mt: new InMemoryMerkleTreeStorage(40),
    states: new EthStateStorage(conf),
  };

  return dataStorage;
}

async function initCredentialWallet(dataStorage: IDataStorage): Promise<CredentialWallet> {
  return new CredentialWallet(dataStorage);
}

async function initIdentityWallet(
  dataStorage: IDataStorage,
  credentialWallet: ICredentialWallet
): Promise<IIdentityWallet> {
  const memoryKeyStore = new InMemoryPrivateKeyStore();
  const bjjProvider = new BjjProvider(KmsKeyType.BabyJubJub, memoryKeyStore);
  const kms = new KMS();
  kms.registerKeyProvider(KmsKeyType.BabyJubJub, bjjProvider);

  return new IdentityWallet(kms, dataStorage, credentialWallet);
}

async function initProofService(
  identityWallet: IIdentityWallet,
  credentialWallet: ICredentialWallet,
  stateStorage: IStateStorage
): Promise<ProofService> {
  const circuitStorage = new CircuitStorage(new InMemoryDataSource<CircuitData>());
  const loader = new FSKeyLoader(path.join(__dirname, circuitsFolder));

  await circuitStorage.saveCircuitData(CircuitId.StateTransition, {
    circuitId: CircuitId.StateTransition,
    wasm: await loader.load(`${CircuitId.StateTransition}/circuit.wasm`),
    provingKey: await loader.load(`${CircuitId.StateTransition}/circuit_final.zkey`),
    verificationKey: await loader.load(`${CircuitId.StateTransition}/verification_key.json`),
  });

  return new ProofService(identityWallet, credentialWallet, circuitStorage, stateStorage);
}

async function transitState() {
  console.log("=============== transit state ===============");

  const dataStorage = initDataStorage();
  const credentialWallet = await initCredentialWallet(dataStorage);
  const identityWallet = await initIdentityWallet(dataStorage, credentialWallet);
  const proofService = await initProofService(identityWallet, credentialWallet, dataStorage.states);

  const { did: userDID, credential: authBJJCredentialUser } = await identityWallet.createIdentity(
    "http://mytestwallet.com/", // this is url that will be a part of auth bjj credential identifier
    {
      method: core.DidMethod.Iden3,
      blockchain: core.Blockchain.Polygon,
      networkId: core.NetworkId.Mumbai,
      rhsUrl, // url to check revocation status of auth bjj credential
    }
  );

  console.log("=============== user did ===============");
  console.log(userDID.toString());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity(
      "http://mytestwallet.com/", // this is url that will be a part of auth bjj credential identifier
      {
        method: core.DidMethod.Iden3,
        blockchain: core.Blockchain.Polygon,
        networkId: core.NetworkId.Mumbai,
        rhsUrl, // url to check revocation status of auth bjj credential
      }
    );

  const credentialRequest: CredentialRequest = {
    credentialSchema:
      "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json",
    type: "KYCAgeCredential",
    credentialSubject: {
      id: userDID.toString(),
      birthday: 19960424,
      documentType: 99,
    },
    expiration: 12345678888,
  };
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest,
    "http://mytestwallet.com/", // host url that will a prefix of credential identifier
    {
      withRHS: rhsUrl,
    }
  );

  dataStorage.credential.saveCredential(credential);

  console.log("================= generate Iden3SparseMerkleTreeProof =======================");

  const res = await identityWallet.addCredentialsToMerkleTree([credential], issuerDID);

  console.log("================= push states to rhs ===================");

  await identityWallet.publishStateToRHS(issuerDID, rhsUrl);

  console.log("================= publish to blockchain ===================");

  const ethSigner = new ethers.Wallet(walletKey, (dataStorage.states as EthStateStorage).provider);
  const txId = await proofService.transitState(
    issuerDID,
    res.oldTreeState,
    true,
    dataStorage.states,
    ethSigner
  );

  console.log("================= transaction hash ===================");
  console.log(txId);
}

transitState()
  .then(() => {
    process.exit(0);
  })
  .catch((err) => {
    console.error("ERROR:", err);
    process.exit(1);
  });
