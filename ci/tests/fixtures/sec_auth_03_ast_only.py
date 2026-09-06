# SEC-AUTH-03 fixture with SPLIT expectations, same idea as the .js one.
#
#   semgrep MUST stay silent. Measured against PyJWT 2.13.0: an algorithms list of none
#   raises InvalidAlgorithmError rather than accepting a tampered token, so on Python this
#   is not a bypass and reporting it would be crying wolf.
#
#   the shell hook IS expected to fire. It greps a line, and `algorithms=["none"]` is the
#   same text in a .py file as in a .js file, where the same option genuinely does accept an
#   attacker-minted token once the key is empty. One line cannot carry which library it is.
#
# So the two tools disagree here on purpose, and the disagreement is the point: the hook
# warns and never blocks, semgrep is the one wired into the gate.
import jwt


def none_algorithm_is_refused_by_pyjwt(token, key):
    return jwt.decode(token, key, algorithms=["none"])
