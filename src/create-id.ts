/**
 * Identity creation contains two main parts: creation of identifier and Auth BJJ Credential.
 *
 * @see https://0xpolygonid.github.io/js-sdk-tutorials/docs/tutorial-basics/create-identity
 */

import {
  BjjProvider,
  core,
  CredentialStorage,
  CredentialWallet,
  defaultEthConnectionConfig,
  EthConnectionConfig,
  EthStateStorage,
  ICredentialWallet,
  IDataStorage,
  Identity,
  IdentityStorage,
  IdentityWallet,
  IIdentityWallet,
  InMemoryDataSource,
  InMemoryMerkleTreeStorage,
  InMemoryPrivateKeyStore,
  KMS,
  KmsKeyType,
  Profile,
  W3CCredential,
} from "@0xpolygonid/js-sdk";

import config from "./config";

const { rhsUrl, rpcUrl, contractAddress, walletKey } = config;

function initDataStorage(): IDataStorage {
  let conf: EthConnectionConfig = {
    ...defaultEthConnectionConfig,
    contractAddress,
    url: rpcUrl,
  };

  var dataStorage = {
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

async function identityCreation() {
  // console.log("=============== key creation ===============");

  const dataStorage = initDataStorage();
  const credentialWallet = await initCredentialWallet(dataStorage);
  const identityWallet = await initIdentityWallet(dataStorage, credentialWallet);

  const { did, credential } = await identityWallet.createIdentity(
    "https://mywallet.com", // this is url that will be a part of auth bjj credential identifier
    {
      method: core.DidMethod.Iden3,
      blockchain: core.Blockchain.Polygon,
      networkId: core.NetworkId.Main,
      rhsUrl: "http://rhs.com/node", // url to check revocation status of auth bjj credential, if it's not set hostUrl is used.
    }
  );

  console.log("=============== DID ===============");
  console.log(did.toString());
  console.log("=============== Auth BJJ credential ===============");
  console.log(JSON.stringify(credential, null, 2));
}

identityCreation()
  .then(() => {
    process.exit(0);
  })
  .catch((err) => {
    console.error("ERROR:", err);
    process.exit(1);
  });
