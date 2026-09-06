// Pins ONE hook alternation: jjwt 0.12's unsecured(), the replacement for parseClaimsJwt.
class UnsecuredParser {
    Object claims(String token) {
        return Jwts.parser().unsecured().build().parseUnsecuredClaims(token).getPayload();
    }
}
