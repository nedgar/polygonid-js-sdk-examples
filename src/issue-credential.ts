/**
 * Credential is issued to the user with a BJJ signature proof.
 *
 * @see https://0xpolygonid.github.io/js-sdk-tutorials/docs/tutorial-basics/issue-credential
 */

import {
  BjjProvider,
  core,
  CredentialRequest,
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
  RevocationStatus,
  VerifiableConstants,
  W3CCredential,
} from "@0xpolygonid/js-sdk";

import config from "./config";

const { rhsUrl, rpcUrl, contractAddress } = config;

function initDataStorage(): IDataStorage {
  let conf: EthConnectionConfig = {
    ...defaultEthConnectionConfig,
    contractAddress,
    url: rpcUrl,
  };

  let dataStorage = {
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

class MyCredentialWallet extends CredentialWallet {
  async getRevocationStatusFromCredential(cred: W3CCredential): Promise<RevocationStatus> {
    console.log("in getRevocationStatusFromCredential");
    // throw new Error(VerifiableConstants.ERRORS.IDENTITY_DOES_NOT_EXIST);
    return super.getRevocationStatusFromCredential(cred);
  }
}

async function initCredentialWallet(dataStorage: IDataStorage): Promise<CredentialWallet> {
  // CredentialWallet.prototype.getRevocationStatusFromCredential = getRevocationStatusFromCredential;
  return new MyCredentialWallet(dataStorage);
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

async function issueCredential() {
  console.log("=============== issue credential ===============");

  const dataStorage = initDataStorage();
  const credentialWallet = await initCredentialWallet(dataStorage);
  const identityWallet = await initIdentityWallet(dataStorage, credentialWallet);

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

  // console.log("Publishing issuerDID to RHS at ", RHS_URL);
  //   await identityWallet.publishStateToRHS(issuerDID, RHS_URL);

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
    revNonce: 12345,
  };
  console.log(
    "Calling identityWallet.issueCredential with credentialRequest:",
    JSON.stringify(credentialRequest, null, 2)
  );
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest,
    "http://mytestwallet.com/", // host url that will a prefix of credential identifier
    {
      withRHS: rhsUrl,
    }
  );

  console.log("===============  credential ===============");
  console.log(JSON.stringify(credential, null, 2));

  dataStorage.credential.saveCredential(credential);
}

issueCredential()
  .then(() => {
    process.exit(0);
  })
  .catch((err) => {
    console.error("ERROR:", err);
    process.exit(1);
  });
