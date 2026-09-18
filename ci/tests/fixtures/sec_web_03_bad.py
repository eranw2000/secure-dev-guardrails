# Insecure on purpose: every marked line sends a request value to an outgoing request.
import urllib.request

import aiohttp
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


def django_named_req(req):
    return requests.get(req.GET.get("url"), timeout=5)  # EXPECT SEC-WEB-03


def session_client():
    s = requests.Session()
    return s.get(request.args["u"], timeout=5)  # EXPECT SEC-WEB-03


def session_inline():
    return requests.Session().get(request.args["u"], timeout=5)  # EXPECT SEC-WEB-03


def httpx_client():
    with httpx.Client() as client:
        return client.get(request.args["u"])  # EXPECT SEC-WEB-03


async def aiohttp_session():
    async with aiohttp.ClientSession() as session:
        return await session.get(request.args["u"])  # EXPECT SEC-WEB-03


def helper_named_check_but_not_a_url_guard():
    return requests.get(check_output(request.args["url"]), timeout=5)  # EXPECT SEC-WEB-03


def helper_named_safe_but_not_a_url_guard():
    return requests.get(safe_join("https://", request.args["host"]), timeout=5)  # EXPECT SEC-WEB-03
