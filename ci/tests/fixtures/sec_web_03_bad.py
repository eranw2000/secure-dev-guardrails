# Insecure on purpose: every marked line sends a request value to an outgoing request.
import urllib.request

import httpx
import requests
from flask import request


def preview():
    url = request.args.get("url")
    return requests.get(url, timeout=5)  # EXPECT SEC-WEB-03


def preview_keyword():
    target = request.json["target"]
    return httpx.post(url=target)  # EXPECT SEC-WEB-03


def django_view(req):
    return urllib.request.urlopen(request.GET["u"])  # EXPECT SEC-WEB-03


def with_verb():
    return requests.request("GET", request.form["u"])  # EXPECT SEC-WEB-03


def built_from_parts():
    base = "https://" + request.args["host"] + "/status"
    return requests.get(base)  # EXPECT SEC-WEB-03


def requests_keyword():
    return requests.get(url=request.values["u"], timeout=5)  # EXPECT SEC-WEB-03
