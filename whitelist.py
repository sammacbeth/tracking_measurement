
import requests
import json
from hashlib import md5

# CLIQZ token whitelists
trackers = set(json.loads(requests.get('https://cdn.cliqz.com/anti-tracking/whitelist/tracker_domains.json').text).keys())
safekeys = json.loads(requests.get('https://cdn.cliqz.com/anti-tracking/whitelist/domain_safe_key.json').text)
safetokens = json.loads(requests.get('https://cdn.cliqz.com/anti-tracking/whitelist/whitelist_tokens.json').text)


def is_tracker(domain):
    return md5(domain).hexdigest()[:16] in trackers


def is_safe_key(domain, key):
    domain_hash = md5(domain).hexdigest()[:16]
    key_hash = md5(key).hexdigest()
    return domain_hash in safekeys and key_hash in safekeys[domain_hash].keys()


def is_safe_token(token):
    return md5(token).hexdigest() in safetokens


# Manual exclusion of common values which are not uids
not_uids = set(['.doubleclick.net', 'CheckForPermission', 'HttpOnly', 'httponly', 'secure',
               'en,de'])
common_resolutions = set(["1600", "900", "1440", "1024"])

def is_manual_safe(domain, key, value):
    return value.strip() in not_uids or value.strip() in common_resolutions
