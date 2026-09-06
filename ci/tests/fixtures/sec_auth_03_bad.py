# SEC-AUTH-03 fixture: every function here MUST be reported.
# Each case was checked against PyJWT 2.13.0 by decoding a tampered token: these are the
# calls that accepted it. The two shapes that LOOK like bypasses and are not live elsewhere,
# because PyJWT 2 still raises on both: the legacy `verify` argument is in the good fixture,
# and an algorithms list of none is in the ast_only fixture, where the two tools disagree.
import jwt


def signature_check_off(token, key):
    return jwt.decode(token, key, options={"verify_signature": False})  # EXPECT SEC-AUTH-03


def audience_check_off(token, key):
    return jwt.decode(token, key, audience="api", options={"verify_aud": False})  # EXPECT SEC-AUTH-03


def expiry_check_off(token, key):
    return jwt.decode(token, key, algorithms=["RS256"], options={"verify_exp": False})  # EXPECT SEC-AUTH-03


def issuer_check_off(token, key):
    return jwt.decode(token, key, algorithms=["RS256"], options={"verify_iss": False})  # EXPECT SEC-AUTH-03


def signature_check_off_via_decode_complete(token, key):
    return jwt.decode_complete(token, key, options={"verify_signature": False})  # EXPECT SEC-AUTH-03
