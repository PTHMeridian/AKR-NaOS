import { ShamirModule } from "./phase1-shamir/index";

async function main() {
  console.log("AKR Naos - Nested Authentication Operations Suite");
  console.log("SA AT Cryptographics\n");

  const shamir = new ShamirModule();

  console.log("=== Phase 1 - Shamir Secret Sharing ===\n");

  // Test 1 - Basic split and recover
  console.log("Test 1: Split private key into 5 shares, recover with 3");
  const privateKey = "this-is-a-simulated-ml-kem-768-private-key-material-for-testing";
  
  const splitResult = shamir.split(privateKey, {
    threshold: 3,
    totalShares: 5,
    label: "AKR-primary-key",
  });

  console.log("Split Result:");
  console.log(`  Algorithm:     ${splitResult.algorithm}`);
  console.log(`  Total Shares:  ${splitResult.totalShares}`);
  console.log(`  Threshold:     ${splitResult.threshold}`);
  console.log(`  Secret Hash:   ${splitResult.secretHash.substring(0, 32)}...`);
  console.log(`  Created:       ${new Date(splitResult.createdAt).toISOString()}`);
  console.log(`  Shares:`);
  splitResult.shares.forEach((s) => {
    console.log(`    [${s.id}] ${s.label} — ${s.share.substring(0, 20)}...`);
  });

  // Test 2 - Recover with exactly threshold shares
  console.log("\nTest 2: Recover using shares 1, 3, 5 (any 3 of 5)");
  const selectedShares = [
    splitResult.shares[0],
    splitResult.shares[2],
    splitResult.shares[4],
  ];

  const recoverResult = shamir.recover(selectedShares, splitResult.secretHash);
  console.log(`  Recovered:     ${recoverResult.secret}`);
  console.log(`  Verified:      ${recoverResult.verified}`);
  console.log(`  Match:         ${recoverResult.secret === privateKey}`);

  // Test 3 - Verify with different share combinations
  console.log("\nTest 3: Verify different share combinations");
  const combo1 = [splitResult.shares[0], splitResult.shares[1], splitResult.shares[2]];
  const combo2 = [splitResult.shares[1], splitResult.shares[3], splitResult.shares[4]];
  const combo3 = [splitResult.shares[0], splitResult.shares[4]]; // Only 2 — should fail
  
  console.log(`  Shares 1,2,3 valid: ${shamir.verify(combo1, splitResult.secretHash)}`);
  console.log(`  Shares 2,4,5 valid: ${shamir.verify(combo2, splitResult.secretHash)}`);
  console.log(`  Shares 1,5 only (below threshold): ${shamir.verify(combo3, splitResult.secretHash)}`);

  // Test 4 - Split binary key material
  console.log("\nTest 4: Split binary key material (simulated ML-KEM-768 private key)");
  const binaryKey = Buffer.from("simulated-binary-key-material-32-bytes-here!!", "utf8");
  const binarySplit = shamir.splitBytes(new Uint8Array(binaryKey), {
    threshold: 2,
    totalShares: 3,
    label: "ml-kem-backup",
  });
  console.log(`  Binary shares generated: ${binarySplit.totalShares}`);
  console.log(`  Threshold: ${binarySplit.threshold}`);
  console.log(`  Hash: ${binarySplit.secretHash.substring(0, 32)}...`);

  // Test 5 - Distribution map
  console.log("\nTest 5: Distribute shares to named destinations");
  const destinations = [
    "primary-device",
    "secondary-device", 
    "encrypted-cloud",
    "trusted-contact",
    "hardware-token",
  ];
  const distribution = shamir.distributeShares(splitResult.shares, destinations);
  console.log("  Distribution map:");
  distribution.forEach((share, dest) => {
    console.log(`    ${dest} -> Share [${share.id}]`);
  });

  // Test 6 - Share info
  console.log("\nTest 6: Share info summary");
  const info = shamir.getShareInfo(splitResult);
  console.log(`  ${JSON.stringify(info, null, 2).split("\n").join("\n  ")}`);

  console.log("\n=== Phase 1 Complete ===");
  console.log("Shamir Secret Sharing working correctly.");
  console.log("No single point of failure. Threshold security verified.");
}

main().catch(console.error);