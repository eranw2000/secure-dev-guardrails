// SEC-AUTH-03 fixture with SPLIT expectations, and it exists to make a limit visible
// rather than to hide it.
//
//   semgrep MUST stay silent here. It parses, so it can see that the receiver is not a JWT
//   library and that the option belongs to something else entirely.
//
//   the shell hook IS expected to fire here. It greps a line, so `algorithms: ["none"]` is
//   the same text whatever object it belongs to. That is the price of a check that needs no
//   toolchain and runs on every write, and it is why the hook only ever warns while semgrep
//   is the one wired into the gate.
//
// If a future change makes the hook silent here, that is an improvement, and this file will
// fail until somebody moves it and says so on purpose.
function unrelatedVerifyWithTheSameOptionName(blob, key) {
  return archive.verify(blob, key, { algorithms: ["none"] });
}

function unrelatedCacheOption(cache, key) {
  return cache.get(key, { ignoreExpiration: true });
}
