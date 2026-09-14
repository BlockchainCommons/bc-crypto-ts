//! Replays a vectors file against the bc-crypto reference.
//!
//!   cargo run --release --offline -- ../vectors/vectors.json
//!   cargo run --release --offline -- <full corpus>     (bun scripts/generate-vectors.ts --full <path>)
//!   cargo run --release --offline -- ../vectors/heavy.json
//!
//! Every recipe is parsed into the reference's argument types before the call,
//! outside `catch_unwind`. An input the Rust signature cannot receive is
//! `js-only` (J1: no reference function; J2: a fixed-size argument of the wrong
//! length; J3: sealed data under 16 bytes; J4: a number that is not an integer
//! of the Rust width): never a match, never a mismatch. The reference call runs
//! under `catch_unwind`, so a panic is a throw. Outcomes are compared after
//! normalising every failure (TS `throw:<Name>`, Rust panic or `Err`) to
//! "throw", except `x25519Shared`, whose `Err(NonContributoryKey)` is rendered
//! `throw:NonContributoryKey|<Display>` and compared verbatim with the TS
//! adapter's `throw:<code>|<message>`. There is no exception list: any other
//! difference is a MISMATCH, and the process exits 1.
use bc_crypto::hash::{crc32, crc32_data_opt, hkdf_hmac_sha512, pbkdf2_hmac_sha512};
use bc_crypto::*;
use bc_rand::SeededRandomNumberGenerator;
use serde::Deserialize;
use serde_json::Value;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// bc-crypto's ed25519 keygen wants a rand_core 0.6 `CryptoRngCore`; bc-rand's
/// generator implements rand_core 0.9. The bridge forwards each method to the
/// generator's own — `fill_bytes` included, which on the seeded generator is
/// the packed `fill_bytes_via_next` stream the reference really draws
/// (TypeScript: `SeededRng.fillBytesPacked`).
struct Bridge<'a>(&'a mut SeededRandomNumberGenerator);
impl rand_core::RngCore for Bridge<'_> {
    fn next_u32(&mut self) -> u32 { rand::RngCore::next_u32(self.0) }
    fn next_u64(&mut self) -> u64 { rand::RngCore::next_u64(self.0) }
    fn fill_bytes(&mut self, dest: &mut [u8]) { rand::RngCore::fill_bytes(self.0, dest); }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> { self.fill_bytes(dest); Ok(()) }
}
impl rand_core::CryptoRng for Bridge<'_> {}

#[derive(Deserialize)]
struct File { count: usize, vectors: Vec<Vector> }
#[derive(Deserialize)]
struct Vector { recipe: Value, expect: String }

/// The js-only class of an input no reference call can receive.
type JsOnly = &'static str;

enum Outcome { Value(String), Throw }

fn bytes(v: &Value) -> Vec<u8> {
    if let Some(h) = v.get("hex") { return hex::decode(h.as_str().unwrap()).unwrap(); }
    if let Some(t) = v.get("text") { return t.as_str().unwrap().as_bytes().to_vec(); }
    let n = v["cycle"].as_u64().unwrap() as usize;
    let start = v.get("start").and_then(|s| s.as_u64()).unwrap_or(0) as usize;
    (0..n).map(|i| ((start + i) & 0xff) as u8).collect()
}
fn seed(v: &Value) -> [u64; 4] {
    let a: Vec<u64> = v.as_array().unwrap().iter().map(|s| s.as_str().unwrap().parse().unwrap()).collect();
    [a[0], a[1], a[2], a[3]]
}
/// A fixed-size argument; a wrong length is J2.
fn fixed<const N: usize>(v: Vec<u8>) -> std::result::Result<[u8; N], JsOnly> { v.try_into().map_err(|_| "J2") }
/// Width-checked numbers; a fraction, a negative or a value past the width is J4.
fn u8_of(v: &Value) -> std::result::Result<u8, JsOnly> { v.as_u64().and_then(|n| u8::try_from(n).ok()).ok_or("J4") }
fn u32_of(v: &Value) -> std::result::Result<u32, JsOnly> { v.as_u64().and_then(|n| u32::try_from(n).ok()).ok_or("J4") }
fn usize_of(v: &Value) -> std::result::Result<usize, JsOnly> { v.as_u64().and_then(|n| usize::try_from(n).ok()).ok_or("J4") }
fn bool_of(v: &Value) -> std::result::Result<bool, JsOnly> { v.as_bool().ok_or("J4") }
fn norm(s: &str) -> String { if s.starts_with("throw") { "throw".into() } else { s.to_string() } }

/// The reference call alone runs under `catch_unwind`: a panic is a throw.
fn attempt(f: impl FnOnce() -> Option<String>) -> Outcome {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Some(s)) => Outcome::Value(s),
        _ => Outcome::Throw,
    }
}

fn run(r: &Value) -> std::result::Result<Outcome, JsOnly> {
    let k = r["k"].as_str().unwrap();
    let b = |key: &str| bytes(&r[key]);
    Ok(match k {
        "sha256" => { let d = b("d"); attempt(move || Some(hex::encode(sha256(d)))) }
        "doubleSha256" => { let d = b("d"); attempt(move || Some(hex::encode(double_sha256(&d)))) }
        "sha512" => { let d = b("d"); attempt(move || Some(hex::encode(sha512(d)))) }
        "crc32" => { let d = b("d"); attempt(move || Some(crc32(d).to_string())) }
        "crc32Bytes" => { let d = b("d"); let le = bool_of(&r["le"])?; attempt(move || Some(hex::encode(crc32_data_opt(d, le)))) }
        "hmacSha256" => { let (key, d) = (b("key"), b("d")); attempt(move || Some(hex::encode(hmac_sha256(key, d)))) }
        "hmacSha512" => { let (key, d) = (b("key"), b("d")); attempt(move || Some(hex::encode(hmac_sha512(key, d)))) }
        "pbkdf2Sha256" => {
            let (pw, salt) = (b("pw"), b("salt"));
            let (iter, len) = (u32_of(&r["iter"])?, usize_of(&r["len"])?);
            attempt(move || Some(hex::encode(pbkdf2_hmac_sha256(pw, salt, iter, len))))
        }
        "pbkdf2Sha512" => {
            let (pw, salt) = (b("pw"), b("salt"));
            let (iter, len) = (u32_of(&r["iter"])?, usize_of(&r["len"])?);
            attempt(move || Some(hex::encode(pbkdf2_hmac_sha512(pw, salt, iter, len))))
        }
        "hkdfSha256" => { let (key, salt, len) = (b("key"), b("salt"), usize_of(&r["len"])?); attempt(move || Some(hex::encode(hkdf_hmac_sha256(key, salt, len)))) }
        "hkdfSha512" => { let (key, salt, len) = (b("key"), b("salt"), usize_of(&r["len"])?); attempt(move || Some(hex::encode(hkdf_hmac_sha512(key, salt, len)))) }
        "scrypt" => {
            let (pw, salt, len) = (b("pw"), b("salt"), usize_of(&r["len"])?);
            match r.get("n") {
                None => attempt(move || Some(hex::encode(scrypt(pw, salt, len)))),
                // recipe `n` IS log2(N) (frozen recipe semantics)
                Some(n) => {
                    let (log_n, rr, p) = (u8_of(n)?, u32_of(&r["r"])?, u32_of(&r["p"])?);
                    attempt(move || Some(hex::encode(scrypt_opt(pw, salt, len, log_n, rr, p))))
                }
            }
        }
        "argon2id" => { let (pw, salt, len) = (b("pw"), b("salt"), usize_of(&r["len"])?); attempt(move || Some(hex::encode(argon2id(pw, salt, len)))) }
        // Raw ChaCha20 has no bc-crypto function (provenance-mark's `ChaCha20::new` + `apply_keystream`).
        "chacha20" => return Err("J1"),
        "aeadEncrypt" => {
            let (key, nonce, pt) = (fixed::<32>(b("key"))?, fixed::<12>(b("nonce"))?, b("pt"));
            let aad = r.get("aad").map(bytes);
            attempt(move || {
                let (ct, tag) = match aad {
                    None => aead_chacha20_poly1305_encrypt(pt, &key, &nonce),
                    Some(a) => aead_chacha20_poly1305_encrypt_with_aad(pt, &key, &nonce, a),
                };
                let mut all = ct; all.extend_from_slice(&tag); Some(hex::encode(all))
            })
        }
        "aeadDecrypt" => {
            let (key, nonce) = (fixed::<32>(b("key"))?, fixed::<12>(b("nonce"))?);
            let all = b("ct");
            if all.len() < 16 { return Err("J3"); }
            let aad = r.get("aad").map(bytes);
            attempt(move || {
                let (ct, tag) = all.split_at(all.len() - 16);
                let mut t = [0u8; 16]; t.copy_from_slice(tag);
                let res = match aad {
                    None => aead_chacha20_poly1305_decrypt(ct, &key, &nonce, &t),
                    Some(a) => aead_chacha20_poly1305_decrypt_with_aad(ct, &key, &nonce, a, &t),
                };
                res.ok().map(hex::encode)
            })
        }
        "x25519Pub" => { let priv_ = fixed::<32>(b("priv"))?; attempt(move || Some(hex::encode(x25519_public_key_from_private_key(&priv_)))) }
        // The reference's one error value on this path, rendered `throw:<code>|<Display>` and compared verbatim.
        "x25519Shared" => {
            let (priv_, pub_) = (fixed::<32>(b("priv"))?, fixed::<32>(b("pub"))?);
            attempt(move || Some(match try_x25519_shared_key(&priv_, &pub_) {
                Ok(key) => hex::encode(key),
                Err(e) => format!("throw:NonContributoryKey|{e}"),
            }))
        }
        "deriveAgreement" => { let km = b("km"); attempt(move || Some(hex::encode(derive_agreement_private_key(km)))) }
        "deriveSigning" => { let km = b("km"); attempt(move || Some(hex::encode(derive_signing_private_key(km)))) }
        "ecdsaDerive" => { let km = b("km"); attempt(move || Some(hex::encode(ecdsa_derive_private_key(km)))) }
        "ecdsaPub" => { let priv_ = fixed::<32>(b("priv"))?; attempt(move || Some(hex::encode(ecdsa_public_key_from_private_key(&priv_)))) }
        "ecdsaDecompress" => { let pub_ = fixed::<33>(b("pub"))?; attempt(move || Some(hex::encode(ecdsa_decompress_public_key(&pub_)))) }
        "ecdsaCompress" => { let pub_ = fixed::<65>(b("pub"))?; attempt(move || Some(hex::encode(ecdsa_compress_public_key(&pub_)))) }
        "ecdsaSign" => { let (priv_, msg) = (fixed::<32>(b("priv"))?, b("msg")); attempt(move || Some(hex::encode(ecdsa_sign(&priv_, msg)))) }
        "ecdsaVerify" => {
            let (pub_, sig, msg) = (fixed::<33>(b("pub"))?, fixed::<64>(b("sig"))?, b("msg"));
            attempt(move || Some(if ecdsa_verify(&pub_, &sig, msg) { "1".into() } else { "0".into() }))
        }
        "schnorrPub" => { let priv_ = fixed::<32>(b("priv"))?; attempt(move || Some(hex::encode(schnorr_public_key_from_private_key(&priv_)))) }
        "schnorrSignAux" => {
            let (priv_, msg, aux) = (fixed::<32>(b("priv"))?, b("msg"), fixed::<32>(b("aux"))?);
            attempt(move || Some(hex::encode(schnorr_sign_with_aux_rand(&priv_, msg, &aux))))
        }
        "schnorrSignRng" => {
            let (priv_, msg, s) = (fixed::<32>(b("priv"))?, b("msg"), seed(&r["seed"]));
            attempt(move || { let mut rng = SeededRandomNumberGenerator::new(s); Some(hex::encode(schnorr_sign_using(&priv_, msg, &mut rng))) })
        }
        "schnorrVerify" => {
            let (pub_, sig, msg) = (fixed::<32>(b("pub"))?, fixed::<64>(b("sig"))?, b("msg"));
            attempt(move || Some(if schnorr_verify(&pub_, &sig, msg) { "1".into() } else { "0".into() }))
        }
        "ed25519Pub" => { let priv_ = fixed::<32>(b("priv"))?; attempt(move || Some(hex::encode(ed25519_public_key_from_private_key(&priv_)))) }
        "ed25519Sign" => { let (priv_, msg) = (fixed::<32>(b("priv"))?, b("msg")); attempt(move || Some(hex::encode(ed25519_sign(&priv_, &msg)))) }
        "ed25519Verify" => {
            let (pub_, sig, msg) = (fixed::<32>(b("pub"))?, fixed::<64>(b("sig"))?, b("msg"));
            attempt(move || Some(if ed25519_verify(&pub_, &msg, &sig) { "1".into() } else { "0".into() }))
        }
        "newPriv" => {
            let s = seed(&r["seed"]);
            let alg = r["alg"].as_str().unwrap().to_string();
            attempt(move || {
                let mut rng = SeededRandomNumberGenerator::new(s);
                Some(match alg.as_str() {
                    "ecdsa" => hex::encode(ecdsa_new_private_key_using(&mut rng)),
                    "ed25519" => hex::encode(ed25519_new_private_key_using(&mut Bridge(&mut rng))),
                    _ => hex::encode(x25519_new_private_key_using(&mut rng)),
                })
            })
        }
        other => panic!("unknown recipe kind {other}"),
    })
}

/// The resolved `bc-crypto` source, from this harness's Cargo.lock: the
/// registry version, or the `[patch.crates-io]` path with its git HEAD and a
/// dirty flag (the reference is a working tree until the release that
/// contains its edits ships).
fn provenance() -> String {
    let dir = env!("CARGO_MANIFEST_DIR");
    let lock = std::fs::read_to_string(format!("{dir}/Cargo.lock")).unwrap_or_default();
    let mut version = String::from("?");
    let mut source: Option<String> = None;
    let mut in_pkg = false;
    for line in lock.lines() {
        let line = line.trim();
        if line == "[[package]]" { in_pkg = false; continue; }
        if line == "name = \"bc-crypto\"" { in_pkg = true; continue; }
        if in_pkg {
            if let Some(v) = line.strip_prefix("version = ") { version = v.trim_matches('"').to_string(); }
            if let Some(s) = line.strip_prefix("source = ") { source = Some(s.trim_matches('"').to_string()); }
            if line.starts_with("dependencies") || line.starts_with("checksum") { in_pkg = false; }
        }
    }
    if let Some(s) = source { return format!("bc-crypto {version} ({s})"); }
    let manifest = std::fs::read_to_string(format!("{dir}/Cargo.toml")).unwrap_or_default();
    let path = manifest
        .lines()
        .find(|l| l.trim_start().starts_with("bc-crypto = { path = "))
        .and_then(|l| l.split('"').nth(1))
        .map(|p| format!("{dir}/{p}"))
        .unwrap_or_else(|| "?".into());
    let git = |args: &[&str]| {
        std::process::Command::new("git").arg("-C").arg(&path).args(args).output().ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    let head = git(&["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "?".into());
    let dirty = git(&["status", "--porcelain", "--untracked-files=all"]).map(|s| !s.is_empty()).unwrap_or(false);
    let canonical = std::fs::canonicalize(&path).map(|p| p.display().to_string()).unwrap_or(path);
    format!("bc-crypto {version} patched from {canonical} (HEAD {head}{})", if dirty { ", dirty" } else { "" })
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let path = std::env::args().nth(1).expect("path to a vectors file");
    let file: File = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(file.count, file.vectors.len());
    eprintln!("reference: {}", provenance());
    let (mut ok, mut js, mut mismatch) = (0, 0, 0);
    let mut classes = std::collections::BTreeMap::<&str, usize>::new();
    for v in &file.vectors {
        let (got, want) = match run(&v.recipe) {
            Err(class) => {
                js += 1;
                *classes.entry(class).or_default() += 1;
                eprintln!("js-only [{class}] {}", v.recipe);
                continue;
            }
            Ok(Outcome::Throw) => ("throw".to_string(), norm(&v.expect)),
            // A value, or the error value of `x25519Shared`: compared verbatim.
            Ok(Outcome::Value(s)) => (s, v.expect.clone()),
        };
        if got == want { ok += 1; continue; }
        mismatch += 1;
        eprintln!("MISMATCH {}\n  rust: {}\n  ts:   {}", v.recipe, got, v.expect);
    }
    let tallies: Vec<String> = classes.iter().map(|(c, n)| format!("{c} {n}")).collect();
    eprintln!("js-only classes: {}", if tallies.is_empty() { "none".into() } else { tallies.join(", ") });
    println!("{} vectors - {ok} match, {js} js-only, {mismatch} MISMATCH", file.vectors.len());
    std::process::exit(if mismatch == 0 { 0 } else { 1 });
}
