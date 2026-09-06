// Pins ONE widening: the option name is quoted.
const jwt = require("jsonwebtoken");
function f(token, key) {
  return jwt.verify(token, key, { "algorithms": ["none"] });
}
