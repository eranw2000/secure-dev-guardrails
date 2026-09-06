// One case per file, deliberately. The hook reports per FILE, so a case sharing a file with
// another reported case cannot pin anything: narrow the pattern and the file still fires.
// This file pins ONE widening: `none` is not the first element of the algorithm list.
const jwt = require("jsonwebtoken");
function f(token, key) {
  return jwt.verify(token, key, { algorithms: ["RS256", "none"] });
}
