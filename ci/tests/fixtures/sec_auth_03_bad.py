# SEC-AUTH-03 fixture: every function here MUST be reported.
# Each case was checked by decoding a tampered token. The options-dict switches accepted it on
# PyJWT 2.13.0. The legacy `verify` argument accepted it on PyJWT 1.7.1 and is ignored on 2.x,
# so it is reported by its own rule with a message that says both. The one shape that LOOKS
# like a bypass and is not, an algorithms list of none, lives in the ast_only fixture, because
# the two tools disagree about it on purpose.
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


# decode_complete takes the same options dict as decode, so the claim switches are a bypass
# there too. The first version of the rule covered only verify_signature on this call.
def audience_check_off_via_decode_complete(token, key):
    return jwt.decode_complete(token, key, audience="api", options={"verify_aud": False})  # EXPECT SEC-AUTH-03


def expiry_check_off_via_decode_complete(token, key):
    return jwt.decode_complete(token, key, algorithms=["RS256"], options={"verify_exp": False})  # EXPECT SEC-AUTH-03


def issuer_check_off_via_decode_complete(token, key):
    return jwt.decode_complete(token, key, algorithms=["RS256"], options={"verify_iss": False})  # EXPECT SEC-AUTH-03


# Measured on PyJWT 1.7.1: this ACCEPTED a tampered token. PyJWT 2 ignores the argument and
# still checks the signature, so there it is dead code that reads like a bypass. Reported
# either way, because the rule cannot see which major the consumer pins.
def legacy_verify_argument(token, key):
    return jwt.decode(token, key, algorithms=["RS256"], verify=False)  # EXPECT SEC-AUTH-03
