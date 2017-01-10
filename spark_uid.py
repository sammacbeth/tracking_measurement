import json
from uid_detection import *
from pyspark import SparkContext
from operator import itemgetter
from urllib.parse import urlparse

"""Parse json, ignoring lines with errors"""
def safe_json_decode(s):
    try:
        yield json.loads(s)
    except:
        pass


"""
    Add index 'rid' to request dictionary; extract request TLD and any urls contained in the request
"""
def prepare_request_dict(req_with_index):
    req, rid = req_with_index
    req['rid'] = rid
    req['tld'] = tldextract.extract(req['host']).registered_domain
    req['found_urls'] = set(find_third_parties(req))
    return req


"""Extract uids from a request and emit them with the host and request id"""
def uid_pairs(req):
    rid = req['rid']
    host = req['tld']
    return [((host, uid), rid) for uid in iterate_uids(req)]


def groupByDomain(uid_row):
    (domain, uid), requests = uid_row
    return domain, (uid, requests)


"""Compress uids with ones which occur on the same requests"""
def compress_uids(row):
    domain, uids = row
    uids = sorted(uids, key=lambda pair: len(pair[1]))
    
    for uid, reqs in uids:
        combined_key = [uid]
        for other_uid, other_reqs in uids:
            if uid == other_uid:
                continue
            if reqs.issubset(other_reqs):
                combined_key.append(other_uid)
                
        yield (domain, tuple(sorted(set(combined_key))), reqs)


"""Extract domains seen from list of seen urls"""
def urls_seen_info(uniques_seen):
    domains_seen = set(map(lambda url: urlparse(url).netloc, map(itemgetter(1), uniques_seen)))
    return {
        'uniques_seen': uniques_seen,
        'unique_domains': domains_seen
    }


""" Extract uids from requests and find set of requests with the same uid
    then combine uids which always occur together (see compress_uids)
    output: ((domain, uid), set(request_id)) """
def link_requests_by_uid(requests):
    return requests.flatMap(uid_pairs).groupByKey().mapValues(set)\
        .map(groupByDomain).groupByKey().flatMap(compress_uids)


def calculate_uid_reach(requests, linked_uids):
    """Make a new row for each request id, with the request id as the key"""
    def expand_requests(row):
        domain, uid, requests = row
        for req in requests:
            yield req, (domain, uid)

    # make request id the key
    uid_requests = linked.flatMap(expand_requests)
    # extract id and seen urls for each request
    reqs_urls_seen = requests.map(lambda req: (req['rid'], req['found_urls']))\
        .filter(lambda pair: len(pair[1]) > 0)
    # join rdds on request id, then swap (domain, uid) to key and combined found urls
    uid_reach = uid_requests.join(reqs_urls_seen)\
        .map(lambda tup: (tup[1][0], tup[1][1]))\
        .reduceByKey(lambda a, b: a.union(b))\
        .mapValues(urls_seen_info)
    return uid_reach

if __name__ == '__main__':
    sc = SparkContext()

    # load request logs, decode and and an index
    requests = sc.textFile('./logs/').flatMap(safe_json_decode).zipWithIndex().map(prepare_request_dict).cache()

    # find uids and the requests they saw
    linked = link_requests_by_uid(requests).cache()

    uid_reach = calculate_uid_reach(requests, linked)
    uid_reach.sortBy(lambda row: len(row[1]['unique_domains']), ascending=False).coalesce(50).saveAsTextFile('./uid_reach')
    requests.saveAsTextFile('./requests')
