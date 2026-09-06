// SEC-AUTH-03 fixture: nothing here may be reported, by either tool.
const jwt = require("jsonwebtoken");

function verified(token, key) {
  return jwt.verify(token, key, {
    algorithms: ["RS256"],
    audience: "api",
    issuer: "https://idp.example",
  });
}

function verifiedThenTyped(token, key) {
  const claims = jwt.verify(token, key, { algorithms: ["RS256"], audience: "api" });
  if (claims.typ !== "access") {
    throw new Error("wrong token type for this endpoint");
  }
  return claims;
}

// The literal matters: false is the safe value, and a rule that matched any value would
// report this line.
function expiryChecked(token, key) {
  return jwt.verify(token, key, { algorithms: ["RS256"], ignoreExpiration: false });
}
