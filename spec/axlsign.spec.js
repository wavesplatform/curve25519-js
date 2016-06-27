var crypto = require('crypto');
var axlsign = require('../axlsign.js');

describe('axlsign', function () {
    it('should generate keys', function () {
        var seed = crypto.randomBytes(32);
        var keys = axlsign.generateKeyPair(seed);
        expect(keys.private.length).toBe(32);
        expect(keys.public.length).toBe(32);
    });

    it('should sign and verify', function () {
        var seed = crypto.randomBytes(32);
        var keys = axlsign.generateKeyPair(seed);
        var msg = new Uint8Array([1, 2, 3, 4, 5]);
        var sig = axlsign.sign(keys.private, msg);

        // console.log('secret', new Buffer(keys.private).toString('hex'));
        // console.log('public', new Buffer(keys.public).toString('hex'));
        // console.log('signat', new Buffer(sig).toString('hex'));

        expect(sig.length).toBe(64);
        expect(axlsign.verify(keys.public, msg, sig)).toBe(true);
    });

    it('should generate deterministic signatures if not randomized', function () {
        var seed = crypto.randomBytes(32);
        var keys = axlsign.generateKeyPair(seed);
        var msg = new Uint8Array([1, 2, 3, 4, 5]);
        var sig1 = axlsign.sign(keys.private, msg);
        var sig2 = axlsign.sign(keys.private, msg);
        expect(sig1).toEqual(sig2);
    });

    it('should generate different signatures if randomized', function () {
        var seed = crypto.randomBytes(32);
        var keys = axlsign.generateKeyPair(seed);
        var msg = new Uint8Array([1, 2, 3, 4, 5]);
        var sig0 = axlsign.sign(keys.private, msg); // not randomized
        var sig1 = axlsign.sign(keys.private, msg, crypto.randomBytes(64));
        var sig2 = axlsign.sign(keys.private, msg, crypto.randomBytes(64));
        expect(sig1).not.toEqual(sig2);
        expect(sig0).not.toEqual(sig1);
        expect(sig0).not.toEqual(sig2);
    });

    it('should sign (randomized) and verify', function () {
        var seed = crypto.randomBytes(32);
        var random = crypto.randomBytes(64);
        var keys = axlsign.generateKeyPair(seed);
        var msg = new Uint8Array([1, 2, 3, 4, 5]);
        var sig = axlsign.sign(keys.private, msg, random);

        expect(sig.length).toBe(64);
        expect(axlsign.verify(keys.public, msg, sig)).toBe(true);
    });

    it('should not verify bad signature', function () {
        var seed = crypto.randomBytes(32);
        var keys = axlsign.generateKeyPair(seed);
        var msg = new Uint8Array([1, 2, 3, 4, 5]);
        var sig = axlsign.sign(keys.private, msg);

        expect(axlsign.verify(keys.public, msg, sig)).toBe(true);

        sig[0] ^= sig[0]; sig[1] ^= sig[1]; sig[2] ^= sig[2]; sig[3] ^= sig[3];

        expect(axlsign.verify(keys.public, msg, sig)).toBe(false);
    });

    it('should not verify bad message', function () {
        var seed = crypto.randomBytes(32);
        var keys = axlsign.generateKeyPair(seed);
        var msg = new Uint8Array([1, 2, 3, 4, 5]);
        var sig = axlsign.sign(keys.private, msg);

        expect(axlsign.verify(keys.public, msg, sig)).toBe(true);

        msg = new Uint8Array([1, 2, 3, 4]);

        expect(axlsign.verify(keys.public, msg, sig)).toBe(false);
    });

    it('should signMessage and openMessage', function () {
        var seed = crypto.randomBytes(32);
        var keys = axlsign.generateKeyPair(seed);
        var msg = new Uint8Array([1, 2, 3, 4, 5]);
        var signedMsg = axlsign.signMessage(keys.private, msg);

        expect(signedMsg.length).toBe(msg.length + 64);
        expect(axlsign.openMessage(keys.public, signedMsg)).toEqual(msg);
    });

    it('should calculate key agreement', function() {
        var seed1 = crypto.randomBytes(32);
        var seed2 = crypto.randomBytes(32);

        var k1 = axlsign.generateKeyPair(seed1);
        var k2 = axlsign.generateKeyPair(seed2);

        var sk1 = axlsign.sharedKey(k2.private, k1.public);
        var sk2 = axlsign.sharedKey(k1.private, k2.public);

        expect(sk1).toEqual(sk2);
    });
});
