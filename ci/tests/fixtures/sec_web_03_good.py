# Must stay quiet: fixed URLs, request values in a non-URL position, and values passed through a
# helper whose name says it validates them (a reviewer reads that helper instead).
import requests
from flask import request

from .net import allowlisted_url, validate_outbound


def fixed():
    return requests.get("https://api.example.com/status", timeout=5)


def allowlisted():
    url = allowlisted_url(request.args.get("url"))
    return requests.get(url, timeout=5)


def validated():
    return requests.get(validate_outbound(request.args["u"]), timeout=5)


def as_query_parameter():
    q = request.args.get("q")
    return requests.get("https://api.example.com/search", params={"q": q}, timeout=5)


def as_header():
    return requests.get("https://api.example.com/x", headers={"X-Trace": request.args["t"]})


def guarded_by_host_check():
    return requests.get(ensure_public_host(request.args["u"]), timeout=5)


def cache_lookup():
    return cache.get(request.args["key"])
