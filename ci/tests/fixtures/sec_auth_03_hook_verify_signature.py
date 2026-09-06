# Pins ONE hook alternation: verify_signature switched off, with no other switch in the file, so
# deleting that alternation from the hook has nowhere to hide.
import jwt


def f(token, key):
    return jwt.decode(token, key, options={"verify_signature": False})
