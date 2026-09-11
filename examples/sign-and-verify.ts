/**
 * Sign and verify with the three signature families from one seeded fixture.
 *
 *   bun run build && bun examples/sign-and-verify.ts
 */
import { ecdsa, schnorr, ed25519, deriveSigningPrivateKey } from "@blockchaincommons/crypto";
import { SeededRng, randomBytes } from "@blockchaincommons/rand";

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const message = new TextEncoder().encode("Wolf McNally");

// A seeded generator makes the run reproducible; the default is the secure generator.
const rng = SeededRng.forTesting();
const keyMaterial = randomBytes(32, { rng });
const privateKey = deriveSigningPrivateKey(keyMaterial); // HKDF-SHA-256, salt "signing"

const ecdsaSig = ecdsa.sign(privateKey, message);
console.log("ecdsa   ", hex(ecdsaSig), ecdsa.verify(ecdsa.publicKey(privateKey), ecdsaSig, message));

const schnorrSig = schnorr.sign(privateKey, message, { rng }); // aux-rand drawn from `rng`
console.log("schnorr ", hex(schnorrSig), schnorr.verify(schnorr.publicKey(privateKey), schnorrSig, message));

const edPriv = ed25519.generatePrivateKey({ rng });
const edSig = ed25519.sign(edPriv, message);
console.log("ed25519 ", hex(edSig), ed25519.verify(ed25519.publicKey(edPriv), edSig, message));

// A tampered message never verifies; every verify takes (publicKey, signature, message).
const tampered = Uint8Array.from(message);
tampered[0] ^= 1;
console.log("tampered", ed25519.verify(ed25519.publicKey(edPriv), edSig, tampered));
