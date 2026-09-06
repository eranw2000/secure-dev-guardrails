# Nothing here may be reported. A list NAMED insecure_algorithms that contains "none" is a
# denylist, and the first version of the hook read it as an accepted list because the
# `algorithms` pattern had no left boundary.
import jwt

insecure_algorithms = ["none", "HS256"]


def f(token, key, alg):
    assert alg not in insecure_algorithms
    return jwt.decode(token, key, algorithms=[alg], audience="api")
