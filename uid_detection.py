import fileinput
import ujson as json
import math
import itertools
import tldextract
from urllib.parse import urlparse, parse_qs, unquote
from collections import defaultdict
from operator import itemgetter

def iter_multi_dict(d):
    for item in d:
        if item[1] is None:
            continue
        elif not isinstance(item[1], str):
            for i2 in item[1]:
                yield item[0], i2            
        else:
            yield item[0], item[1]


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
            yield ('referer', header[1])
            for url in find_embedded_urls(header[1]):
                yield 'referer_url', url

    for url in find_embedded_urls(req['url']):
        yield 'url', url

    # find urls in post data
    post_data_sources = [('form', iter_multi_dict(req['urlencoded_form']))]
    if 'text' in req and req['text'] is not None:
        post_data_sources.append(('post-json', iterate_json_post_data(req['text'])))
        post_data_sources.append(('form', iterate_form_post_data(req['text'])))

    for source, gen in post_data_sources:
        for k, v in gen:
            for url in find_url_in_string(v):
                yield source, url


def find_url_in_string(s):
    for search in ['http://', 'https://', 'www.']:
        ind = s.find(search)
        prefix = 'http://' if search == 'www.' else ''
        if ind > -1:
            yield prefix + s[ind:]

def find_embedded_urls(url):
    url_parts = urlparse(url)
    for part in [url_parts.query, url_parts.params]:
        for _, v in iter_multi_dict(parse_qs(part).items()):
            v = unquote(v)
            for url in find_url_in_string(v):
                yield url

def reduce_request_group(requestList, requestIndices):
    requests = [requestList[i] for i in requestIndices]
    uniques_seen = set(itertools.chain.from_iterable(map(find_third_parties, requests)))
    return {
        'uniques_seen': uniques_seen,
        'unique_domains': set(map(lambda url: urlparse(url).netloc, filter(lambda s: s is not None, uniques_seen)))
    }


def _flatten_dict(d, sep='_', prefix=None):
    if isinstance(d, list):
        d = {str(i): v for i, v in enumerate(d)}
    if not hasattr(d, 'items'):
        yield prefix or '', str(d)
        return

    for k, v in d.items():
        sub_prefix = prefix + sep + k if prefix else k
        if hasattr(v, 'items') or isinstance(v, list):
            for kv in _flatten_dict(v, sep=sep, prefix=sub_prefix):
                yield kv
        else:
            yield sub_prefix, str(v)
    return

def iterate_json_post_data(data):
    if data[0] == '{' or data[0] == '[':
        try:
            # json data
            json_data = json.loads(data)
            return iter(_flatten_dict(json_data, sep='.'))
        except:
            pass

    return iter([])


def iterate_form_post_data(data):
    for pair in data.split('&'):
        try:    
            k, v = map(unquote, pair.split('=', 1))
            yield k, v
        except:
            continue
    return


def iterate_cookie_string(cookiedata):
    for cookie in cookiedata.split(';'):
        if '=' in cookie:
            c_name, c_value = cookie.split('=', 1)
        else:
            c_name = ''
            c_value = cookie
        yield c_name, c_value

# values longer than this from post data are probably real uploaded data and should be ignored
LONG_UID_CUTOFF = 500

def iterate_uids(req):

    for cookie in iter_multi_dict(req['req_cookies']):
        yield 'cookie', cookie[0], cookie[1]

    # for k, v in iter_multi_dict(req['res_headers']):
    #     if k == 'Set-Cookie':
    #         for c_name, c_value in iterate_cookie_string(v):
    #             yield 'set-cookie', c_name, c_value

    url_parts = urlparse(req['url'])
    for part, kv in [('qs', url_parts.query), ('ps', url_parts.params)]:
        qs_kv = parse_qs(kv, keep_blank_values=True)
        for qs in iter_multi_dict(qs_kv.items()):
            yield part, qs[0], qs[1]

    # post data
    if req['method'] == 'POST':
        value_length_filter = lambda e: len(e[1]) < LONG_UID_CUTOFF
        # form entries should be deduped because we have to ways to extract
        form_kv = set(filter(value_length_filter, iter_multi_dict(req['urlencoded_form'])))
        if 'text' in req:
            form_kv.update(filter(value_length_filter, iterate_form_post_data(req['text'])))
        for k, v in form_kv:
                yield 'form', k, v

        if 'text' in req:
            for k, v in iterate_json_post_data(req['text']):
                if len(v) < LONG_UID_CUTOFF:
                    yield 'post-json', k, v


def list_uids(req):
    return req['tld'], list(set(iterate_uids(req)))


ENTROPY_THRESHOLD = 1.0

def load_requests(*files):
    # load requests into a list
    index = 0

    for filename in files:
        with open(filename, 'r') as fp:
            for line in fp:
                try:
                    req = json.loads(line)
                    req['index'] = index
                    req['tld'] = tldextract.extract(req['host']).registered_domain
                    yield req
                    index += 1
                except:
                    continue

    print('Requests seen: ', index)

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
                ent = {}
                # if not max(ent.values()) > ENTROPY_THRESHOLD:
                #     continue
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
        # ent = entropy(''.join([u[2] for u in uid]))
        ent = {}
        ent['reqs'] = linked_domain[uid[0]]['reqs']
        linked_reduced[tuple(set(uid))] = ent
    return linked_reduced


def merge(a, b):
    c = dict(a.items())
    for k, v in b.items():
        c[k] = v
    return c

def rm_reqs(d):
    del d['reqs']
    return d

def annotate_reach(requests, linked_requests):
    return {k: rm_reqs(merge(v, reduce_request_group(requests, v['reqs']))) for k, v in linked_requests.items()}

