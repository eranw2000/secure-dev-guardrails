# Pins ONE hook alternation: flask-jwt-extended's allow_expired=True, an expiry check switched
# off by keyword rather than by an options dict.
from flask_jwt_extended import decode_token


def f(token):
    return decode_token(token, allow_expired=True)
