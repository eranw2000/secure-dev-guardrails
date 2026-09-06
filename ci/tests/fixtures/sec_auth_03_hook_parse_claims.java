// Pins ONE hook alternation: jjwt's parseClaimsJwt, which reads an UNSIGNED token's claims.
class UnsignedParse {
    Object claims(String token) {
        return Jwts.parser().parseClaimsJwt(token).getBody();
    }
}
