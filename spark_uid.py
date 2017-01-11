import json
from uid_detection import *
from pyspark import SparkContext
from operator import itemgetter
from urllib.parse import urlparse
import datetime

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
    # for requests without ts, make up something feasible
    if not 'ts' in req:
        req['ts'] = (datetime.datetime(year=2016, month=1, day=1) + datetime.timedelta(seconds=rid)).timestamp()
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

    def combine_req_data(acc, req):
        acc['urls'].update(req['urls'])
        acc['from_ts'] = min(acc['from_ts'], req['from_ts'])
        acc['to_ts'] = max(acc['to_ts'], req['to_ts'])
        return acc

    def uid_output(agg_reqs):
        out = urls_seen_info(agg_reqs['urls'])
        out['from_ts'] = agg_reqs['from_ts']
        out['to_ts'] = agg_reqs['to_ts']
        return out

    # make request id the key
    uid_requests = linked_uids.flatMap(expand_requests)
    # extract id and seen urls for each request
    reqs_urls_seen = requests.map(lambda req: (req['rid'], {'urls': req['found_urls'], 'from_ts': req['ts'], 'to_ts': req['ts']}))\
        .filter(lambda pair: len(pair[1]['urls']) > 0)
    # join rdds on request id, then swap (domain, uid) to key and combined found urls
    uid_reach = uid_requests.join(reqs_urls_seen)\
        .map(lambda tup: (tup[1][0], tup[1][1]))\
        .foldByKey({'urls': set(), 'from_ts': datetime.datetime.now().timestamp(), 'to_ts': 0}, 
            combine_req_data)\
        .mapValues(uid_output)
    return uid_reach


def run_analysis(sc):
    # load request logs, decode and and an index
    requests = sc.textFile('./logs/').flatMap(safe_json_decode).zipWithIndex().map(prepare_request_dict).cache()

    # find uids and the requests they saw
    linked = link_requests_by_uid(requests).cache()

    uid_reach = calculate_uid_reach(requests, linked)
    uid_reach.sortBy(lambda row: len(row[1]['unique_domains']), ascending=False)\
        .coalesce(50).saveAsTextFile('./data/uid_reach')

    def sanitise_request_obj(req):
        req['found_urls'] = list(req['found_urls'])
        return req

    requests.map(sanitise_request_obj).map(json.dumps).saveAsTextFile('./data/requests')


if __name__ == '__main__':
    sc = SparkContext()
    run_analysis(sc)
