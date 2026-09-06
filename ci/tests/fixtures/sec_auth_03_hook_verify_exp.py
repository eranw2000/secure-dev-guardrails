# Pins ONE hook alternation: a claim check (verify_exp) switched off, signature check left on.
import jwt


def f(token, key):
    return jwt.decode(token, key, algorithms=["RS256"], options={"verify_exp": False})
