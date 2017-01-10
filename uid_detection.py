import fileinput
import json
import math
import itertools
import tldextract
from urllib.parse import urlparse, parse_qs, unquote
from collections import defaultdict
from operator import itemgetter

def iter_multi_dict(d):
    for item in d:
        if hasattr(item[1], '__iter__'):
            for i2 in item[1]:
                yield item[0], i2
        else:
            yield item[0], item[2]


BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"


def shannon_entropy(data, iterator):
    """
    Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    if not data:
        return 0
    entropy = 0
    for x in (ord(c) for c in iterator):
        p_x = float(data.count(chr(x)))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy


def entropy(val):
    return {
        'b64': shannon_entropy(val, BASE64_CHARS),
        'hex': shannon_entropy(val, HEX_CHARS)
    }


def find_third_parties(req):
    for header in req['req_headers']:
        if header[0] == 'Referer':
            yield header[1]
            for url in find_embedded_urls(header[1]):
                yield url


def find_embedded_urls(url):
    url_parts = urlparse(url)
    for part in [url_parts.query, url_parts.params]:
        for _, v in iter_multi_dict(parse_qs(part).items()):
            v = unquote(v)
            for search in ['http://', 'https://', 'www.']:
                ind = v.find(search)
                if ind > -1:
                    yield v[ind:]

def reduce_request_group(requestList, requestIndices):
    requests = [requestList[i] for i in requestIndices]
    uniques_seen = set(itertools.chain.from_iterable(map(find_third_parties, requests)))
    return {
        'uniques_seen': uniques_seen,
        'unique_domains': set(map(lambda url: urlparse(url).netloc, filter(lambda s: s is not None, uniques_seen)))
    }

def iterate_uids(req):

    for cookie in iter_multi_dict(req['req_cookies']):
        yield 'cookie', cookie[0], cookie[1]

    for k, v in iter_multi_dict(req['res_headers']):
        if k == 'Set-Cookie':
            for cookie in v.split(';'):
                if '=' in cookie:
                    c_name, c_value = cookie.split('=', 1)
                else:
                    c_name = ''
                    c_value = cookie
                yield 'cookie', c_name, c_value

    url_parts = urlparse(req['url'])
    for part, kv in [('qs', url_parts.query), ('ps', url_parts.params)]:
        qs_kv = parse_qs(kv, keep_blank_values=True)
        for qs in iter_multi_dict(qs_kv.items()):
            yield part, qs[0], qs[1]


ENTROPY_THRESHOLD = 1.0

def load_requests(*files):
    # load requests into a list
    requests = []
    index = 0

    for filename in files:
        with open(filename, 'r') as fp:
            for line in fp:
                try:
                    req = json.loads(line)
                    req['index'] = index
                    req['tld'] = tldextract.extract(req['host']).registered_domain
                    requests.append(req)
                    index += 1
                except:
                    continue

    print('Requests seen: ', index)
    return requests


def group_by_uid(requests):
    linked_requests = defaultdict(lambda: defaultdict(dict))

    for req in requests:
        host = req['tld']
        tracker = linked_requests[host]

        for uid in iterate_uids(req):
            if not uid in tracker:
                # skip short values
                if len(uid[2]) <= 4:
                    continue
                ent = entropy(uid[2])
                if not max(ent.values()) > ENTROPY_THRESHOLD:
                    continue
                ent['reqs'] = set()
                tracker[uid] = ent

            linked = tracker[uid]
            linked['reqs'].add(req['index'])

    return linked_requests


def gather_cooccuring_uids(uid_meta_pair, other_uid_pairs, skip=set()):
    uid, meta = uid_meta_pair
    requests_seen = meta['reqs']
    combined_uid = [uid]
    skip.add(uid)
    for other_uid, other_meta in other_uid_pairs:
        if other_uid in skip:
            continue
            
        other_requests_seen = other_meta['reqs']
        if requests_seen.issubset(other_requests_seen):
            combined_uid += gather_cooccuring_uids((other_uid, other_meta), other_uid_pairs, 
                                                   skip=set(combined_uid) | skip)
            skip.update(combined_uid)
    return combined_uid
    

def reduced_uids(linked_domain):
    linked_reduced = dict()
    uid_pairs = list(linked_domain.items())
    for pair in uid_pairs:
        uid = gather_cooccuring_uids(pair, uid_pairs)
        ent = entropy(''.join([u[2] for u in uid]))
        ent['reqs'] = linked_domain[uid[0]]['reqs']
        linked_reduced[tuple(set(uid))] = ent
    return linked_reduced


# linked_sorted = sorted(tracked_reduces.items(), key=lambda i: len(i[1]['unique_domains']), reverse=True)

# for k, v in linked_sorted:
#     print(k, len(v['uniques_seen']), v['unique_domains'])
# for k, _ in linked_sorted:
#     uniques_seen = set(map(find_third_parties, linked_requests[k]))
#     unique_domains = set(map(lambda url: urlparse(url).netloc, filter(lambda s: s is not None, uniques_seen)))
#     print(k, 'requests:', len(linked_requests[k]), 'uniques:', len(uniques_seen), 'domains:', unique_domains)