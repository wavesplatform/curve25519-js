var crypto = require('crypto');
var axlsign = require('../axlsign.js');

var seed = crypto.randomBytes(32);
var random = crypto.randomBytes(64);
var keys = axlsign.generateKeyPair(seed);
var msg = new Uint8Array(256);
var sig = axlsign.sign(keys.private, msg);

// Benchmark signing.
report('sign', benchmark(function () {
  axlsign.sign(keys.private, msg);
}));

// Benchmark randomized signing.
report('sign (randomized)', benchmark(function () {
  axlsign.sign(keys.private, msg, random);
}));

// Benchmark verifying.
report('verify', benchmark(function () {
  axlsign.verify(keys.public, msg, sig);
}));

// Benchmark key generation.
report('generateKeyPair', benchmark(function () {
  axlsign.generateKeyPair(seed);
}));

// Benchmark calculating shared key.
report('sharedKey', benchmark(function () {
  axlsign.sharedKey(keys.public, keys.private);
}));


// Helper functions for benchmarking.

function benchmark(fn, bytes) {
  var elapsed = 0;
  var iterations = 1;
  while (true) {
    var startTime = Date.now();
    fn();
    elapsed += Date.now() - startTime;
    if (elapsed > 500 && iterations > 2) {
      break;
    }
    iterations++;
  }
  return {
    iterations: iterations,
    msPerOp: elapsed / iterations,
    opsPerSecond: 1000 * iterations / elapsed,
    bytesPerSecond: bytes ? 1000 * (bytes * iterations) / elapsed : undefined
  };
}

function report(name, results) {
  var ops = results.iterations + ' ops';
  var msPerOp = results.msPerOp.toFixed(2) + ' ms/op';
  var opsPerSecond = results.opsPerSecond.toFixed(2) + ' ops/sec';
  var mibPerSecond = results.bytesPerSecond
    ? (results.bytesPerSecond / 1024 / 1024).toFixed(2) + ' MiB/s'
    : '';
  console.log(pad(name, 30, true) + ' ' +
    pad(ops, 20) + ' ' +
    pad(msPerOp, 20) + ' ' +
    pad(opsPerSecond, 20) + ' ' +
    pad(mibPerSecond, 15));
}

function pad(s, upto, end) {
  if (end === void 0) { end = false; }
  var padlen = upto - s.length;
  if (padlen <= 0) {
    return s;
  }
  // XXX: in ES2015 we can use ' '.repeat(padlen)
  var padding = new Array(padlen + 1).join(' ');
  if (end) {
    return s + padding;
  }
  return padding + s;
}
