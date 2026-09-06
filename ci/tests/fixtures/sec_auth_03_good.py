# SEC-AUTH-03 fixture: nothing here may be reported.
# Two shapes that look like a bypass are deliberately NOT here. The legacy `verify` argument
# set to False is in the bad fixture, because on PyJWT 1.x it really is one. An algorithms list
# of none lives in sec_auth_03_ast_only.py, because the two tools disagree about it on purpose.
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
