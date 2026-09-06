// Pins ONE hook alternation: an "alg": "none" header, with no algorithms list anywhere in the
// file, so only that alternation can report it.
function unsignedHeader() {
  return { "alg": "none", typ: "JWT" };
}
