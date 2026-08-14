import { readFileSync } from "node:fs";

import { assert, it } from "poku";

import {
  collectReachableFrames,
  constructServiceName,
  detectServicesFromUsages,
  extractEndpoints,
  parseSemanticSlices,
  sliceFileOption,
} from "./evinser.js";

it("Service detection test", () => {
  const usageSlice = JSON.parse(
    readFileSync("./test/data/usages.json", { encoding: "utf-8" }),
  );
  const objectSlices = usageSlice.objectSlices;
  const servicesMap = {};
  for (const slice of objectSlices) {
    detectServicesFromUsages("java", slice, servicesMap);
    assert.ok(servicesMap);
    const serviceName = constructServiceName("java", slice);
    assert.ok(serviceName);
  }
});

it("extract endpoints test", () => {
  assert.deepStrictEqual(
    extractEndpoints("java", '@GetMapping(value = { "/", "/home" })'),
    ["/", "/home"],
  );
  assert.deepStrictEqual(
    extractEndpoints(
      "java",
      '@PostMapping(value = "/issue", consumes = MediaType.APPLICATION_XML_VALUE)',
    ),
    ["/issue"],
  );
  assert.deepStrictEqual(extractEndpoints("java", '@GetMapping("/token")'), [
    "/token",
  ]);
  assert.deepStrictEqual(
    extractEndpoints(
      "javascript",
      'router.use("/api/v2/users",userRoutes.routes(),userRoutes.allowedMethods())',
    ),
    ["/api/v2/users"],
  );
  assert.deepStrictEqual(
    extractEndpoints(
      "javascript",
      "app.use('/encryptionkeys', serveIndexMiddleware, serveIndex('encryptionkeys', { icons: true, view: 'details' }))",
    ),
    ["/encryptionkeys"],
  );
  assert.deepStrictEqual(
    extractEndpoints(
      "javascript",
      "app.use(express.static(path.resolve('frontend/dist/frontend')))",
    ),
    ["frontend/dist/frontend"],
  );
  assert.deepStrictEqual(
    extractEndpoints(
      "javascript",
      "app.use('/ftp(?!/quarantine)/:file', fileServer())",
    ),
    ["/ftp(?!/quarantine)/:file"],
  );
  assert.deepStrictEqual(
    extractEndpoints(
      "javascript",
      "app.use('/rest/basket/:id', security.isAuthorized())",
    ),
    ["/rest/basket/:id"],
  );
  assert.deepStrictEqual(
    extractEndpoints(
      "javascript",
      "app.get(['/.well-known/security.txt', '/security.txt'], verify.accessControlChallenges())",
    ),
    ["/.well-known/security.txt", "/security.txt"],
  );
  assert.deepStrictEqual(
    extractEndpoints(
      "javascript",
      'router.post("/convert",async(ctx:Context):Promise<void>=>{constparameters=ctx.request.body;constbatchClient=newBatchClient({region:"us-west-1"});constcommand=newSubmitJobCommand({jobName:parameters?.jobName,jobQueue:"FOO-ARN",jobDefinition:"BAR-ARN",parameters,});try{constobjectsOutput=awaitbatchClient.send(command);ctx.response.body=objectsOutput;}catch(err){//Poorexceptionhandlingctx.response.body=err;}})',
    ),
    ["/convert"],
  );
  assert.deepStrictEqual(
    extractEndpoints(
      "java",
      '@RequestMapping(path = "/{name}", method = RequestMethod.GET)',
    ),
    ["/{name}"],
  );
  assert.deepStrictEqual(
    extractEndpoints("java", "@RequestMapping(method = RequestMethod.POST)"),
    [],
  );
  assert.deepStrictEqual(
    extractEndpoints(
      "java",
      '@RequestMapping(value = "/{accountName}", method = RequestMethod.GET)',
    ),
    ["/{accountName}"],
  );
});

it("parseSemanticSlices", () => {
  const semanticsSlice = JSON.parse(
    readFileSync("./test/data/swiftsem/semantics.slices.json", {
      encoding: "utf-8",
    }),
  );
  const bomJson = JSON.parse(
    readFileSync("./test/data/swiftsem/bom-hakit.json", {
      encoding: "utf-8",
    }),
  );
  const retMap = parseSemanticSlices(
    "swift",
    bomJson.components,
    semanticsSlice,
  );
  assert.ok(retMap);
});

it("names the slice-file option every slice type reads", () => {
  // The CLI declares these flags; yargs camel-cases them before evinse sees
  // them, so a hyphenated slice type has to be camel-cased to match.
  const declared = new Set([
    "usagesSlicesFile",
    "dataFlowSlicesFile",
    "reachablesSlicesFile",
    "semanticsSlicesFile",
  ]);
  for (const sliceType of ["usages", "data-flow", "reachables", "semantics"]) {
    assert.ok(
      declared.has(sliceFileOption(sliceType)),
      `${sliceType} resolves to ${sliceFileOption(sliceType)}, which no CLI flag provides`,
    );
  }
  assert.strictEqual(sliceFileOption("data-flow"), "dataFlowSlicesFile");
});

it("collectReachableFrames still resolves an OID-bearing algorithm via findCryptoAlgos", () => {
  // Real shape from atom's reachables output for AESGCM(key) -> encrypt.
  const reachablesSlice = [
    {
      flows: [
        {
          name: "AESGCM",
          code: "AESGCM(key)",
          tags: "crypto, crypto-algorithm",
          parentFileName: "primitives.py",
        },
        {
          name: "encrypt",
          code: "tmp0.encrypt(nonce, plaintext, aad)",
          tags: "crypto, crypto-generate",
          parentFileName: "primitives.py",
        },
      ],
      purls: [],
    },
  ];
  const { cryptoComponents } = collectReachableFrames("python", reachablesSlice);
  assert.ok(
    cryptoComponents.some((c) => c.name === "aes" && c.cryptoProperties?.oid),
    "expected an OID-bearing aes cryptographic-asset from the OID dictionary match",
  );
});

it("collectReachableFrames falls back to atom's own tag when no OID entry exists", () => {
  // Real shape from atom's reachables output for argon2's hash_secret_raw --
  // both crypto-generate and crypto-algorithm on the same node, since there's
  // no separate constructor step and no registered Argon2 OID to match.
  const reachablesSlice = [
    {
      flows: [
        {
          name: "hash_secret_raw",
          code: "hash_secret_raw(secret = secret, salt = salt, type = Type.ID)",
          tags: "crypto, crypto-algorithm, crypto-generate",
          parentFileName: "password.py",
        },
      ],
      purls: [],
    },
  ];
  const { cryptoComponents, cryptoGeneratePurls } = collectReachableFrames(
    "python",
    reachablesSlice,
  );
  assert.ok(
    cryptoComponents.some(
      (c) => c.name === "hash_secret_raw" && !c.cryptoProperties?.oid,
    ),
    "expected an OID-less hash_secret_raw cryptographic-asset from the tag fallback",
  );
  assert.deepStrictEqual(cryptoGeneratePurls, {});
});
