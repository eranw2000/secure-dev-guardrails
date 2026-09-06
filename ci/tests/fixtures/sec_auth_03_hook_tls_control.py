# Control for the verify=False split: on an HTTP call it is still SEC-CRYPTO-01, and it is NOT a
# SEC-AUTH-03 finding. Without this file, narrowing the TLS pattern to nothing would pass.
import requests


def fetch(url):
    return requests.get(url, verify=False)
