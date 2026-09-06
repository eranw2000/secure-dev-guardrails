// SEC-AUTH-03 fixture: every function here MUST be reported.
// Measured against jsonwebtoken 9.0.3. An algorithms list containing none is refused while
// a real key is passed and accepts an attacker-minted unsigned token the moment the key is
// empty, null or undefined, so it is safe only by accident and is reported either way.
// ignoreExpiration was confirmed to accept an expired token.
const jwt = require("jsonwebtoken");

function noneOnly(token, key) {
  return jwt.verify(token, key, { algorithms: ["none"] }); // EXPECT SEC-AUTH-03
}

// none is not the first element. The first version of this rule matched the array exactly
// and missed this, which is the shape that actually ships.
function noneAmongOthers(token, key) {
  return jwt.verify(token, key, { algorithms: ["RS256", "none"] }); // EXPECT SEC-AUTH-03
}

function quotedProperty(token, key) {
  return jwt.verify(token, key, { "algorithms": ["none"] }); // EXPECT SEC-AUTH-03
}

function expiryIgnored(token, key) {
  return jwt.verify(token, key, { algorithms: ["RS256"], ignoreExpiration: true }); // EXPECT SEC-AUTH-03
}

// The library accepts both quote styles. semgrep matches a string literal regardless of its
// quotes, so the one double-quoted pattern has to report this line too; this case proves it.
function noneSingleQuoted(token, key) {
  return jwt.verify(token, key, { algorithms: ['none'] }); // EXPECT SEC-AUTH-03
}

// The receiver is a parameter, so nothing resolves it to the library; the rule's name filter
// has to accept it on the word "token" alone.
function viaInjectedService(tokenService, token, key) {
  return tokenService.verify(token, key, { ignoreExpiration: true }); // EXPECT SEC-AUTH-03
}
