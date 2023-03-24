/**
 * Handle authorization request: flow without usage of profiles.
 * Adapted to issue a KYC Country credential and to verify it's not in list of sanctioned countries.
 *
 * @see https://0xpolygonid.github.io/js-sdk-tutorials/docs/tutorial-basics/auth-handler
 */

import { proving } from "@iden3/js-jwz";
import {
  AuthDataPrepareFunc,
  AuthHandler,
  AuthorizationRequestMessage,
  BjjProvider,
  CircuitData,
  CircuitId,
  CircuitStorage,
  core,
  CredentialRequest,
  CredentialStorage,
  CredentialWallet,
  DataPrepareHandlerFunc,
  defaultEthConnectionConfig,
  EthConnectionConfig,
  EthStateStorage,
  FSKeyLoader,
  ICircuitStorage,
  ICredentialWallet,
  IDataStorage,
  Identity,
  IdentityStorage,
  IdentityWallet,
  IIdentityWallet,
  InMemoryDataSource,
  InMemoryMerkleTreeStorage,
  InMemoryPrivateKeyStore,
  IPackageManager,
  IStateStorage,
  KMS,
  KmsKeyType,
  Operators,
  PackageManager,
  PlainPacker,
  Profile,
  ProofService,
  PROTOCOL_CONSTANTS,
  ProvingParams,
  StateVerificationFunc,
  VerificationHandlerFunc,
  VerificationParams,
  W3CCredential,
  ZeroKnowledgeProofRequest,
  ZKPPacker,
} from "@0xpolygonid/js-sdk";
import { Alpha2Code, alpha2ToNumeric } from "i18n-iso-countries";
import path from "path";

import config from "./config";

function getNumericCountryCode(alpha2: Alpha2Code): number {
  return Number(alpha2ToNumeric(alpha2));
}

const { rhsUrl, rpcUrl, contractAddress, circuitsFolder } = config;

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

async function initCircuitStorage(): Promise<ICircuitStorage> {
  const circuitStorage = new CircuitStorage(new InMemoryDataSource<CircuitData>());

  const loader = new FSKeyLoader(path.join(__dirname, circuitsFolder));

  await circuitStorage.saveCircuitData(CircuitId.AuthV2, {
    circuitId: CircuitId.AuthV2,
    wasm: await loader.load(`${CircuitId.AuthV2}/circuit.wasm`),
    provingKey: await loader.load(`${CircuitId.AuthV2}/circuit_final.zkey`),
    verificationKey: await loader.load(`${CircuitId.AuthV2}/verification_key.json`),
  });

  await circuitStorage.saveCircuitData(CircuitId.AtomicQuerySigV2, {
    circuitId: CircuitId.AtomicQuerySigV2,
    wasm: await loader.load(`${CircuitId.AtomicQuerySigV2}/circuit.wasm`),
    provingKey: await loader.load(`${CircuitId.AtomicQuerySigV2}/circuit_final.zkey`),
    verificationKey: await loader.load(`${CircuitId.AtomicQuerySigV2}/verification_key.json`),
  });

  await circuitStorage.saveCircuitData(CircuitId.StateTransition, {
    circuitId: CircuitId.StateTransition,
    wasm: await loader.load(`${CircuitId.StateTransition}/circuit.wasm`),
    provingKey: await loader.load(`${CircuitId.StateTransition}/circuit_final.zkey`),
    verificationKey: await loader.load(`${CircuitId.StateTransition}/verification_key.json`),
  });

  // await circuitStorage.saveCircuitData(CircuitId.AtomicQueryMTPV2, {
  //   circuitId: CircuitId.AtomicQueryMTPV2,
  //   wasm: await loader.load(`${CircuitId.AtomicQueryMTPV2}/circuit.wasm`),
  //   provingKey: await loader.load(`${CircuitId.AtomicQueryMTPV2}/circuit_final.zkey`),
  //   verificationKey: await loader.load(`${CircuitId.AtomicQueryMTPV2}/verification_key.json`),
  // });

  return circuitStorage;
}

async function initProofService(
  identityWallet: IIdentityWallet,
  credentialWallet: ICredentialWallet,
  stateStorage: IStateStorage,
  circuitStorage: ICircuitStorage
): Promise<ProofService> {
  return new ProofService(identityWallet, credentialWallet, circuitStorage, stateStorage);
}

async function initPackageManager(
  circuitData: CircuitData,
  prepareFn: AuthDataPrepareFunc,
  stateVerificationFn: StateVerificationFunc
): Promise<IPackageManager> {
  const authInputsHandler = new DataPrepareHandlerFunc(prepareFn);

  const verificationFn = new VerificationHandlerFunc(stateVerificationFn);
  const mapKey = proving.provingMethodGroth16AuthV2Instance.methodAlg.toString();
  const verificationParamMap: Map<string, VerificationParams> = new Map([
    [
      mapKey,
      {
        key: circuitData.verificationKey,
        verificationFn,
      },
    ],
  ]);

  const provingParamMap: Map<string, ProvingParams> = new Map();
  provingParamMap.set(mapKey, {
    dataPreparer: authInputsHandler,
    provingKey: circuitData.provingKey,
    wasm: circuitData.wasm,
  });

  const mgr: IPackageManager = new PackageManager();
  const packer = new ZKPPacker(provingParamMap, verificationParamMap);
  const plainPacker = new PlainPacker();
  mgr.registerPackers([packer, plainPacker]);

  return mgr;
}

async function handleAuthRequestNoIssuerStateTransition() {
  console.log("=============== handle auth request no issuer state transition ===============");

  const dataStorage = initDataStorage();
  const credentialWallet = await initCredentialWallet(dataStorage);
  const identityWallet = await initIdentityWallet(dataStorage, credentialWallet);
  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID, credential: authBJJCredentialUser } = await identityWallet.createIdentity(
    "http://wallet.com/", // this is url that will be a part of auth bjj credential identifier
    {
      method: core.DidMethod.Iden3,
      blockchain: core.Blockchain.Polygon,
      networkId: core.NetworkId.Mumbai,
      rhsUrl,
    }
  );

  console.log("=============== user did ===============");
  console.log(userDID.toString());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity(
      "http://wallet.com/", // this is url that will be a part of auth bjj credential identifier
      {
        method: core.DidMethod.Iden3,
        blockchain: core.Blockchain.Polygon,
        networkId: core.NetworkId.Mumbai,
        rhsUrl,
      }
    );

  const credentialRequest: CredentialRequest = {
    credentialSchema:
      "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCCountryOfResidenceCredential-v2.json",
    type: "KYCCountryOfResidenceCredential",
    credentialSubject: {
      id: userDID.toString(),
      countryCode: getNumericCountryCode("CA"),
      documentType: 99,
    },
    expiration: 12345678888,
  };
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest,
    "http://wallet.com/", // host url that will a prefix of credential identifier
    {
      withRHS: rhsUrl, // reverse hash service is used to check
    }
  );

  await dataStorage.credential.saveCredential(credential);

  console.log("================= generate credentialAtomicSigV2 ===================");

  const sanctionedCountries: Alpha2Code[] = [
    "AF", // Afghanistan,
    "IR", // Iran
    "KP", // North Korea
    "SS", // South Sudan
    "SY", // Syria
  ];

  const proofReqSig: ZeroKnowledgeProofRequest = {
    id: 1,
    circuitId: CircuitId.AtomicQuerySigV2,
    optional: false,
    query: {
      allowedIssuers: ["*"],
      type: credentialRequest.type,
      context:
        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
      credentialSubject: {
        countryCode: {
          $nin: sanctionedCountries.map(getNumericCountryCode),
        },
      },
    },
  };

  console.log("=================  credential auth request ===================");

  var authRequest: AuthorizationRequestMessage = {
    id: "fe6354fe-3db2-48c2-a779-e39c2dda8d90",
    thid: "fe6354fe-3db2-48c2-a779-e39c2dda8d90",
    typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
    from: issuerDID.toString(),
    type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    body: {
      callbackUrl: "http://testcallback.com",
      message: "message to sign",
      scope: [proofReqSig],
      reason: "verify country",
    },
  };
  console.log(JSON.stringify(authRequest, null, 2));

  var authRawRequest = new TextEncoder().encode(JSON.stringify(authRequest));

  // * on the user side */

  console.log("============== handle auth request ==============");
  const authV2Data = await circuitStorage.loadCircuitData(CircuitId.AuthV2);
  let pm = await initPackageManager(
    authV2Data,
    proofService.generateAuthV2Inputs.bind(proofService),
    proofService.verifyState.bind(proofService)
  );

  const authHandler = new AuthHandler(pm, proofService, credentialWallet);
  const authHandlerRequest = await authHandler.handleAuthorizationRequestForGenesisDID(
    userDID,
    authRawRequest
  );
  console.log(JSON.stringify(authHandlerRequest, null, 2));
}

handleAuthRequestNoIssuerStateTransition()
  .then(() => {
    process.exit(0);
  })
  .catch((err) => {
    console.error("ERROR:", err);
    process.exit(1);
  });
