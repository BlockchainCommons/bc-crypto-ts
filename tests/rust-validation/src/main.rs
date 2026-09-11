//! Replays tests/vectors/vectors.json against bc-crypto 0.14.0.
//!
//!   cargo run --release -- ../vectors/vectors.json
//!
//! Outcomes are compared after normalising every failure (TS `throw:<Name>`,
//! Rust `Err`/panic) to "throw"; the harness checks WHAT succeeds and the
//! bytes it produces, not error taxonomy.
use bc_crypto::*;
use bc_crypto::hash::{crc32, crc32_data_opt, hkdf_hmac_sha512, pbkdf2_hmac_sha512};
use bc_rand::{RandomNumberGenerator, SeededRandomNumberGenerator};

/// bc-crypto's ed25519 keygen wants a rand_core 0.6 `CryptoRngCore`; bridge
/// the bc-rand generator to it. `fill_bytes` maps to `fill_random_data`, the
/// same one-draw-per-byte path TypeScript uses.
struct Bridge<'a>(&'a mut SeededRandomNumberGenerator);
impl rand_core::RngCore for Bridge<'_> {
    fn next_u32(&mut self) -> u32 { self.0.next_u64() as u32 }
    fn next_u64(&mut self) -> u64 { self.0.next_u64() }
    fn fill_bytes(&mut self, dest: &mut [u8]) { self.0.fill_random_data(dest); }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> { self.fill_bytes(dest); Ok(()) }
}
impl rand_core::CryptoRng for Bridge<'_> {}
use serde::Deserialize;
use std::panic::{catch_unwind, AssertUnwindSafe};

#[derive(Deserialize)]
struct File { count: usize, vectors: Vec<Vector> }
#[derive(Deserialize)]
struct Vector { recipe: serde_json::Value, expect: String }

fn bytes(v: &serde_json::Value) -> Vec<u8> {
    if let Some(h) = v.get("hex") { return hex::decode(h.as_str().unwrap()).unwrap(); }
    if let Some(t) = v.get("text") { return t.as_str().unwrap().as_bytes().to_vec(); }
    let n = v["cycle"].as_u64().unwrap() as usize;
    let start = v.get("start").and_then(|s| s.as_u64()).unwrap_or(0) as usize;
    (0..n).map(|i| ((start + i) & 0xff) as u8).collect()
}
fn seed(v: &serde_json::Value) -> [u64; 4] {
    let a: Vec<u64> = v.as_array().unwrap().iter().map(|s| s.as_str().unwrap().parse().unwrap()).collect();
    [a[0], a[1], a[2], a[3]]
}
fn norm(s: &str) -> String { if s.starts_with("throw") { "throw".into() } else { s.to_string() } }
/// Fixed-size view; a wrong length is what TypeScript reports as a throw.
fn fixed<const N: usize>(v: Vec<u8>) -> Option<[u8; N]> { v.try_into().ok() }

fn run(r: &serde_json::Value) -> String {
    let k = r["k"].as_str().unwrap();
    let b = |key: &str| bytes(&r[key]);
    let out: std::result::Result<Option<String>, ()> = catch_unwind(AssertUnwindSafe(|| -> Option<String> {
        Some(match k {
            "sha256" => hex::encode(sha256(b("d"))),
            "doubleSha256" => hex::encode(double_sha256(&b("d"))),
            "sha512" => hex::encode(sha512(b("d"))),
            "crc32" => crc32(b("d")).to_string(),
            "crc32Bytes" => hex::encode(crc32_data_opt(b("d"), r["le"].as_bool().unwrap())),
            "hmacSha256" => hex::encode(hmac_sha256(b("key"), b("d"))),
            "hmacSha512" => hex::encode(hmac_sha512(b("key"), b("d"))),
            "pbkdf2Sha256" => hex::encode(pbkdf2_hmac_sha256(b("pw"), b("salt"), r["iter"].as_u64().unwrap() as u32, r["len"].as_u64().unwrap() as usize)),
            "pbkdf2Sha512" => hex::encode(pbkdf2_hmac_sha512(b("pw"), b("salt"), r["iter"].as_u64().unwrap() as u32, r["len"].as_u64().unwrap() as usize)),
            "hkdfSha256" => hex::encode(hkdf_hmac_sha256(b("key"), b("salt"), r["len"].as_u64().unwrap() as usize)),
            "hkdfSha512" => hex::encode(hkdf_hmac_sha512(b("key"), b("salt"), r["len"].as_u64().unwrap() as usize)),
            "scrypt" => {
                let len = r["len"].as_u64().unwrap() as usize;
                match r.get("n").and_then(|n| n.as_u64()) {
                    None => hex::encode(scrypt(b("pw"), b("salt"), len)),
                    // recipe `n` IS log2(N) (frozen recipe semantics)
                    Some(n) => hex::encode(scrypt_opt(b("pw"), b("salt"), len, n as u8, r["r"].as_u64().unwrap() as u32, r["p"].as_u64().unwrap() as u32)),
                }
            }
            "argon2id" => hex::encode(argon2id(b("pw"), b("salt"), r["len"].as_u64().unwrap() as usize)),
            // JS-only (report A6): no reference analog; classified J1 before comparison.
            "chacha20" => return None,
            "aeadEncrypt" => {
                let (ct, tag) = match r.get("aad") {
                    None => aead_chacha20_poly1305_encrypt(b("pt"), &fixed::<32>(b("key"))?, &fixed::<12>(b("nonce"))?),
                    Some(a) => aead_chacha20_poly1305_encrypt_with_aad(b("pt"), &fixed::<32>(b("key"))?, &fixed::<12>(b("nonce"))?, bytes(a)),
                };
                let mut all = ct; all.extend_from_slice(&tag); hex::encode(all)
            }
            "aeadDecrypt" => {
                let all = b("ct");
                if all.len() < 16 { return None; }
                let (ct, tag) = all.split_at(all.len() - 16);
                let mut t = [0u8; 16]; t.copy_from_slice(tag);
                let res = match r.get("aad") {
                    None => aead_chacha20_poly1305_decrypt(ct, &fixed::<32>(b("key"))?, &fixed::<12>(b("nonce"))?, &t),
                    Some(a) => aead_chacha20_poly1305_decrypt_with_aad(ct, &fixed::<32>(b("key"))?, &fixed::<12>(b("nonce"))?, bytes(a), &t),
                };
                match res { Ok(pt) => hex::encode(pt), Err(_) => return None }
            }
            "x25519Pub" => hex::encode(x25519_public_key_from_private_key(&fixed::<32>(b("priv"))?)),
            "x25519Shared" => hex::encode(x25519_shared_key(&fixed::<32>(b("priv"))?, &fixed::<32>(b("pub"))?)),
            "deriveAgreement" => hex::encode(derive_agreement_private_key(b("km"))),
            "deriveSigning" => hex::encode(derive_signing_private_key(b("km"))),
            "ecdsaDerive" => hex::encode(ecdsa_derive_private_key(b("km"))),
            "ecdsaPub" => hex::encode(ecdsa_public_key_from_private_key(&fixed::<32>(b("priv"))?)),
            "ecdsaDecompress" => hex::encode(ecdsa_decompress_public_key(&fixed::<33>(b("pub"))?)),
            "ecdsaCompress" => hex::encode(ecdsa_compress_public_key(&fixed::<65>(b("pub"))?)),
            "ecdsaSign" => hex::encode(ecdsa_sign(&fixed::<32>(b("priv"))?, b("msg"))),
            "ecdsaVerify" => if ecdsa_verify(&fixed::<33>(b("pub"))?, &fixed::<64>(b("sig"))?, b("msg")) { "1".into() } else { "0".into() },
            "schnorrPub" => hex::encode(schnorr_public_key_from_private_key(&fixed::<32>(b("priv"))?)),
            "schnorrSignAux" => hex::encode(schnorr_sign_with_aux_rand(&fixed::<32>(b("priv"))?, b("msg"), &fixed::<32>(b("aux"))?)),
            "schnorrSignRng" => { let mut rng = SeededRandomNumberGenerator::new(seed(&r["seed"])); hex::encode(schnorr_sign_using(&fixed::<32>(b("priv"))?, b("msg"), &mut rng)) }
            "schnorrVerify" => if schnorr_verify(&fixed::<32>(b("pub"))?, &fixed::<64>(b("sig"))?, b("msg")) { "1".into() } else { "0".into() },
            "ed25519Pub" => hex::encode(ed25519_public_key_from_private_key(&fixed::<32>(b("priv"))?)),
            "ed25519Sign" => hex::encode(ed25519_sign(&fixed::<32>(b("priv"))?, &b("msg"))),
            "ed25519Verify" => if ed25519_verify(&fixed::<32>(b("pub"))?, &b("msg"), &fixed::<64>(b("sig"))?) { "1".into() } else { "0".into() },
            "newPriv" => {
                let mut rng = SeededRandomNumberGenerator::new(seed(&r["seed"]));
                match r["alg"].as_str().unwrap() {
                    "ecdsa" => hex::encode(ecdsa_new_private_key_using(&mut rng)),
                    "ed25519" => hex::encode(ed25519_new_private_key_using(&mut Bridge(&mut rng))),
                    _ => hex::encode(x25519_new_private_key_using(&mut rng)),
                }
            }
            other => panic!("unknown recipe kind {other}"),
        })
    })).map_err(|_| ());
    match out { Ok(Some(s)) => s, _ => "throw".into() }
}

/// Recipes with no reference analog (report §3): the raw ChaCha20 keystream and
/// argon2id's `t`/`m`/`p`. Classified before comparison, whatever the outcome.
fn js_only(r: &serde_json::Value) -> bool {
    let k = r["k"].as_str().unwrap();
    k == "chacha20" || (k == "argon2id" && (r.get("t").is_some() || r.get("m").is_some() || r.get("p").is_some()))
}

/// The machine-readable twin of RUST_DIVERGENCES.md §1.
///  D2: x25519 with a low-order public key — the reference derives the
///      zero-secret HKDF, TypeScript rejects (ADR 0004).
///  D3: verify on malformed input of the right length — the reference
///      panics, TypeScript returns false (ADR 0004).
///  D4–D6: KDF argument domains (RUST_DIVERGENCES.md §1).
/// Report B1 (strict Ed25519) is NOT allowlisted: those vectors mismatch
/// until W1 lands, and then match.
fn expected_divergence(r: &serde_json::Value, got: &str, want: &str) -> Option<&'static str> {
    let k = r["k"].as_str().unwrap();
    if k == "x25519Shared" && want.starts_with("throw") && got != "throw" {
        let low_order = ["00".repeat(32), format!("01{}", "00".repeat(31))];
        if r["pub"].get("hex").and_then(|h| h.as_str()).map(|h| low_order.contains(&h.to_string())).unwrap_or(false) { return Some("D2"); }
    }
    if k.ends_with("Verify") && got == "throw" && want == "0" { return Some("D3"); }
    let num = |key: &str| r.get(key).and_then(|x| x.as_f64());
    // D4: scrypt with log_n = 0 (N = 1) — the reference computes, TypeScript rejects.
    if k == "scrypt" && num("n") == Some(0.0) && want == "throw" && got != "throw" { return Some("D4"); }
    // D5: PBKDF2 with 0 iterations or a 0-byte output — the reference computes, TypeScript rejects.
    if k.starts_with("pbkdf2") && (num("iter") == Some(0.0) || num("len") == Some(0.0)) && want == "throw" && got != "throw" { return Some("D5"); }
    // D6: scrypt_opt output length outside 10..=64 — the reference's `Params::new` panics, TypeScript computes.
    if k == "scrypt" && r.get("n").is_some() && num("len").map(|l| !(10.0..=64.0).contains(&l)).unwrap_or(false) && got == "throw" && want != "throw" { return Some("D6"); }
    None
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let path = std::env::args().nth(1).expect("path");
    let file: File = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(file.count, file.vectors.len());
    let (mut ok, mut expected, mut mismatch) = (0, 0, 0);
    for v in &file.vectors {
        if js_only(&v.recipe) { expected += 1; eprintln!("js-only [J1] {}", v.recipe); continue; }
        let got = run(&v.recipe);
        let want = norm(&v.expect);
        if got == want { ok += 1; continue; }
        if let Some(id) = expected_divergence(&v.recipe, &got, &want) { expected += 1; eprintln!("expected-divergence [{id}] {}", v.recipe); continue; }
        mismatch += 1;
        eprintln!("MISMATCH {}\n  rust: {}\n  ts:   {}", v.recipe, got, v.expect);
    }
    println!("{} vectors - {ok} match, {expected} expected-divergence/js-only, {mismatch} MISMATCH", file.vectors.len());
    std::process::exit(if mismatch == 0 { 0 } else { 1 });
}
