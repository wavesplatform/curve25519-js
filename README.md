Axlsign
=======

Ed25519-like signatures with X25519 keys, Axolotl-style.

## Functions

Functions accept and return bytes as `Uint8Array`s.

### generateKeyPair(seed) -> keyPair

Generates a new key pair from the given 32-byte secret seed (which should be
generated with a CSPRNG) and returns it as object:

```
keyPair = {
    private: Uint8Array // 32-byte private key
    public: Uint8Array  // 32-byte public key
}
```

The returned keys can be used for signing and key agreement.

### sign(privateKey, message, [random]) -> signature

Signs the given message using the private key and returns signature.

Optional random data argument (which must have 64 random bytes) turns on
hash separation and randomization to make signatures non-deterministic.

### verify(publicKey, message, signature) -> true | false

Verifies the given signature for the message using the given private key.
Returns `true` if the signature is valid, `false` otherwise.

### signMessage(privateKey, message, [random]) -> signedMessage

Signs the given message using the private key and returns
a signed message (signature concatenated with the message copy).

Optional random data argument (which must have 64 random bytes) turns on
hash separation and randomization to make signatures non-deterministic.

### openMessage(publicKey, signedMessage) -> message | null

Verifies signed message with the public key and returns the original message
without signature if it's correct or `null` if verification fails.

### sharedKey(privateKey, publicKey) -> rawSharedKey

Returns a raw shared key between own private key and peer's public key (in
other words, this is an ECC Diffie-Hellman function X25519, performing
scalar multiplication).

The result should not be used directly as a key, but should be processed with a
one-way function (e.g. *HSalsa20* as in NaCl, or any secure cryptographic hash
function, such as *SHA-256*, or key derivation function, such as *HKDF*).

## How is it different from Ed25519?

Axlsign allows calculating key agreement and signing using just a single
X25519 key instead of two different X25519 and Ed25519 keys.

It uses keys in X25519 format (Montgomery), while Ed25519 uses keys in a
different representation (Twisted Edwards). Internally, it converts keys to the
correct format, but since such conversion would lose a sign bit, it also embeds
the sign bit from public key into signature during signing, and puts it back
into the key during verification.

Note: if signing and performing key agreement with a single key is needed, but
using keys in X25519 format is not a requrement, a better choice is to use
Ed25519 keys, and then convert them to X25519 keys for key agreement (e.g.
using <https://github.com/dchest/ed2curve-js>). This allows using only an
external conversion functions without changing signature algorithms and
formats.

## Credits

Written in 2016 by Dmitry Chestnykh.
You can use it under MIT or CC0 license.

Curve25519 signatures idea and math by Trevor Perrin
<https://moderncrypto.org/mail-archive/curves/2014/000205.html>

Derived from TweetNaCl.js <https://tweetnacl.js.org>.
Ported in 2014 by Dmitry Chestnykh and Devi Mandiri. Public domain.
Implementation derived from TweetNaCl version 20140427
<http://tweetnacl.cr.yp.to>
