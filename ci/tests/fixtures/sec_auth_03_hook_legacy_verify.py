# Pins ONE hook alternation: the legacy `verify` argument set to False on a decode call. It must
# be reported as SEC-AUTH-03 and NOT as SEC-CRYPTO-01, which is what the first version of the
# hook did: the same text on an HTTP call is a certificate switch with a different fix. (The
# hook greps comments too, which is why this comment does not spell the switch out.)
import jwt


def f(token, key):
    return jwt.decode(token, key, algorithms=["RS256"], verify=False)
