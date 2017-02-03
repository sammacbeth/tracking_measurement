import ujson as json
from uid_detection import *
from pyspark import SparkContext
from operator import itemgetter
from urllib.parse import urlparse
from datetime import datetime, timedelta
from pyspark.sql import Row
from whitelist import is_safe_key, is_safe_token, is_manual_safe
from collections import defaultdict
import itertools
from functools import reduce

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
    req['found_urls'] = frozenset(find_third_parties(req))
    # for requests without ts, make up something feasible
    if not 'ts' in req:
        req['ts'] = (datetime(year=2016, month=1, day=1) + timedelta(seconds=rid)).timestamp()
    return req


"""Extract uids from a request and emit them with the host and request id"""
def uid_pairs(req):
    rid = req['rid']
    host = req['tld']
    return [((host, uid), rid) for uid in iterate_uids(req)]


def groupByDomain(uid_row):
    (domain, uid), requests = uid_row
    return domain, (uid, requests)


max_len = 0

"""Compress uids with ones which occur on the same requests"""
def compress_uids(row):
    global max_len
    domain, uids = row
    n_uids = len(uids)
    uids = sorted(uids, key=lambda pair: len(pair[1]))

    for uid, reqs in uids:
        combined_key = [uid]
        for other_uid, other_reqs in uids:
            if uid == other_uid:
                continue
            if reqs.issubset(other_reqs):
                combined_key.append(other_uid)

        yield domain, frozenset(combined_key), frozenset(reqs)


def compress_uids2(row):
    domain, uids = row
    # read dict of req: set(uid)
    # for each uid: intersection of each uid at reqs
    req_mat = defaultdict(set)
    indexed_uids = dict()

    for i, (uid, reqs) in enumerate(uids):
        indexed_uids[i] = uid
        for req in reqs:
            req_mat[req].add(i)

    keys = set()

    for uid, reqs in uids:
        #combined_key = reduce(lambda a, b: a.intersection(b), [req_mat[req] for req in reqs])
        uids_for_reqs = [req_mat[req] for req in reqs]
        combined_key = uids_for_reqs[0].intersection(*uids_for_reqs[1:])
        keys.add((frozenset(combined_key), frozenset(reqs)))

    for uid_ids, reqs in keys:
        key = frozenset([indexed_uids[i] for i in uid_ids])
        yield domain, key, reqs

def url_parse_or_none(url):
    try:
        return urlparse(url).netloc
    except ValueError:
        return '<invalid>'


"""Extract domains seen from list of seen urls"""
def urls_seen_info(uniques_seen):

    domains_seen = set(map(url_parse_or_none, map(itemgetter(1), uniques_seen)))
    return {
        'uniques_seen': uniques_seen,
        'unique_domains': domains_seen
    }


""" Extract uids from requests and find set of requests with the same uid
    then combine uids which always occur together (see compress_uids)
    output: ((domain, uid), set(request_id)) """
def link_requests_by_uid(requests):
    return requests.flatMap(uid_pairs).groupByKey().mapValues(set)\
        .map(groupByDomain).groupByKey().filter(lambda r: r[0] != 'mozilla.org').flatMap(compress_uids2)


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
        .foldByKey({'urls': set(), 'from_ts': datetime.now().timestamp(), 'to_ts': 0}, 
            combine_req_data)\
        .mapValues(uid_output)
    return uid_reach


def load_mitm_data(sc, input_dir='./logs'):
    return sc.textFile(input_dir).flatMap(safe_json_decode).zipWithIndex()\
        .map(prepare_request_dict)

def run_analysis(sc, input_data):

    def sanitise_request_obj(req):
        req['found_urls'] = list(req['found_urls'])
        return req

    # load request logs, decode and and an index
    requests = input_data.map(sanitise_request_obj).cache()

    # find uids and the requests they saw
    linked = link_requests_by_uid(requests).cache()

    uid_reach = calculate_uid_reach(requests, linked)

    return requests, uid_reach


def save_analysis_rdds(requests, uid_reach, output_dir='./data'):
    # save sorted version for convenience
    uid_reach.sortBy(lambda row: len(row[1]['unique_domains']), ascending=False)\
        .coalesce(50).saveAsTextFile('{}/uid_reach'.format(output_dir))
    requests.map(json.dumps).saveAsTextFile('{}/requests'.format(output_dir))


def get_uid_class(host, source, key, val):
    if val is None or len(val) <= 3:
        return 'short'
    elif is_safe_key(host.encode('utf-8'), key.encode('utf-8')):
        return 'safekey'
    elif is_safe_token(val.encode('utf-8')):
        return 'safetoken'
    elif host in val or is_manual_safe(host, key, val):
        return 'manual'
    else:
        return 'uid'


""" Takes uid_reach rdd (from run_analysis) and converts it into a dict of spark Dataframes
"""
def uid_reach_as_dataframes(uid_reach, sqlContext, visited_domains=set()):

    def uid_dict(tup):
        (domain, uid), meta = tup
        meta['domain'] = domain
        meta['uid'] = uid
        # extra processing
        meta['non_fp_uniques'] = [elem for elem in meta['uniques_seen'] if not domain in elem[1]]
        meta['tp_domains'] = set([url_parse_or_none(elem[1]) for elem in meta['non_fp_uniques']])
        meta['visited_domains'] = set(filter(lambda d: d in visited_domains, meta['tp_domains']))
        return meta

    def add_id(tup):
        d, id = tup
        d['id'] = id
        return d

    """Splits subfields of uid_data into seperate Rows"""
    def split_uid_tables(uid_data):
        uid_id = uid_data['id']
        uid_domain = uid_data['domain']
        for col in ['non_fp_uniques', 'uniques_seen']:
            for elem in uid_data[col]:
                yield col, Row(uid_id=uid_id, source=elem[0], url=elem[1])
        
        for col in ['tp_domains', 'unique_domains', 'visited_domains']:
            for domain in uid_data[col]:
                row = Row(uid_id=uid_id, domain=domain)
                yield col, row
                
        for uid_part in uid_data['uid']:
            source, key, value = uid_part
            yield 'uid_parts', Row(uid_id=uid_id, domain=uid_domain, source=source, key=key, value=value,
                            classification=get_uid_class(uid_domain, source, key, value))
        
        uid_duration = (uid_data['to_ts'] - uid_data['from_ts'])/(60*60)
        yield 'uid', Row(uid_id=uid_id, domain=uid_domain, uid=str(uid_data['uid']),
                         duration=uid_duration, start=datetime.fromtimestamp(uid_data['from_ts']),
                         end=datetime.fromtimestamp(uid_data['to_ts']),
                        **{k: len(uid_data[k]) for k in ['non_fp_uniques', 'uniques_seen', 'tp_domains', 'unique_domains', 'visited_domains']})

    # index uid entries then split into different Rows
    uid_table_data = uid_reach.map(uid_dict).zipWithIndex().map(add_id)\
        .flatMap(split_uid_tables)
    uid_tables = {k: sqlContext.createDataFrame(uid_table_data.filter(lambda r: r[0] == k).values().cache())
          for k in ['uid', 'non_fp_uniques', 'uniques_seen', 'tp_domains', 'unique_domains', 'uid_parts', 'visited_domains']}
    return uid_tables


def register_tables(tables):
    for k, v in tables.items():
        v.registerTempTable(k)


def query_top_uids(sqlContext):
    return sqlContext.sql("""SELECT \
        u.uid_id, first(u.domain) as domain, first(u.duration) as duration, \
        first(u.non_fp_uniques) as non_fp_uniques, \
        first(u.tp_domains) AS tp_domains, \
        COUNT(p.key) AS uids, \
        COUNT(CASE WHEN p.source = 'cookie' THEN 1 ELSE NULL END) AS cookies, \
        COUNT(CASE WHEN p.source = 'qs' THEN 1 ELSE NULL END) AS qs, \
        COUNT(CASE WHEN p.source = 'ps' THEN 1 ELSE NULL END) AS ps, \
        COUNT(CASE WHEN p.source = 'form' THEN 1 ELSE NULL END) AS form, \
        COUNT(CASE WHEN p.source = 'post-json' THEN 1 ELSE NULL END) AS json \
        FROM uid AS u \
        LEFT JOIN uid_parts AS p ON u.uid_id = p.uid_id AND p.classification = 'uid' \
        GROUP BY u.uid_id \
        ORDER BY tp_domains DESC""").where('uids > 0')


def query_uid_id(tables, uid_id, from_table='uid_parts'):
    return tables[from_table].where('uid_id = {}'.format(uid_id))


def requests_as_dataframes(requests, sqlContext):
    kv_types = ['req_cookies', 'req_headers', 'res_headers', 'urlencoded_form']
    table_names = kv_types + ['found_urls', 'request']
    request_cols = ['rid', 'method', 'scheme', 'host', 'path', 'port', 'res_status', 'text', 'tld', 'url', 'ts']

    def split_sub_tables(request):
        rid = request['rid']

        for url in request['found_urls']:
            yield 'found_urls', Row(rid=rid, source=url[0], url=url[1])
        for kv_type in kv_types:
            for kv in request[kv_type]:
                yield kv_type, Row(rid=rid, key=kv[0], value=kv[1])
        
        request_flat = {k: request.get(k, '') for k in request_cols}
        yield 'request', Row(**request_flat)

    table_data = requests.flatMap(split_sub_tables).cache()
    tables = {k: sqlContext.createDataFrame(table_data.filter(lambda r: r[0] == k).values().cache())
          for k in table_names}
    return tables


if __name__ == '__main__':
    from pyspark.sql import SparkSession

    sc = SparkContext()
    sqlContext = SparkSession.builder.appName("Anti-tracking analysis").getOrCreate()

    requests, uid_reach = run_analysis(sc, load_mitm_data(input_dir='./logs/'))
    save_analysis_rdds(requests, uid_reach)
    # uid_tables = uid_reach_as_dataframes(uid_reach, sqlContext)
    # register_tables(uid_tables)
    # print(query_top_uids(sqlContext).limit(20).toPandas())
