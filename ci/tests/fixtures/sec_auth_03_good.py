# SEC-AUTH-03 fixture: nothing here may be reported.
# The last one is the interesting one. It LOOKS like a bypass and is not: measured against
# PyJWT 2.13.0 with a tampered token, the legacy `verify` argument is a documented no-op and
# the library still raised InvalidSignatureError. The first version of this rule reported it,
# which is a false positive, and it also collided with SEC-CRYPTO-01, putting a TLS finding
# on a line about a token. SEC-CRYPTO-01 still matches that text and this file does not
# assert otherwise: it asserts only about SEC-AUTH-03.
import jwt


def verified(token, key):
    return jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        audience="api",
        issuer="https://idp.example",
    )


def verified_then_typed(token, key):
    claims = jwt.decode(token, key, algorithms=["RS256"], audience="api")
    if claims.get("typ") != "access":
        raise ValueError("wrong token type for this endpoint")
    return claims


def legacy_verify_argument_is_a_no_op(token, key):
    # PyJWT 2 ignores this argument. The signature is still checked.
    return jwt.decode(token, key, algorithms=["RS256"], verify=False)

# The other PyJWT shape that looks like a bypass and is not, an algorithms list of none,
# lives in sec_auth_03_ast_only.py, because the two tools disagree about it on purpose.
