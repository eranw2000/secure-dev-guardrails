// Pins ONE widening: the option is set by assignment rather than inside an object literal.
const jwt = require("jsonwebtoken");
function f(token, key, opts) {
  opts.ignoreExpiration = true;
  return jwt.verify(token, key, opts);
}
