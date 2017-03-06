import sqlite3
import ujson as json
import pandas as pd
from datetime import datetime
from urllib.parse import urlparse
from uid_detection import iterate_cookie_string
from spark_uid import prepare_request_dict

def load_crawl_db(crawl_dir):
    return sqlite3.connect('{}/crawl-data.sqlite'.format(crawl_dir))


def get_crawled_urls(db, crawl_id):
    return pd.read_sql("SELECT site_url FROM site_visits WHERE crawl_id = {}".format(crawl_id), db)

def get_crawls(db):
    for row in db.execute('SELECT crawl_id, browser_params FROM crawl'):
        crawl_id = row[0]
        params = json.loads(row[1])
        yield crawl_id, params

def filtered_config(params):
    keys = ['cliqz', 'privacy-badger', 'https-everywhere', 'ghostery', 'donottrack', 'adblock-plus', 'tp_cookies']
    return {k: v for k, v in params.items() if k in keys}

def to_requests_dict(db, crawl_id):

    def iterate_requests(db, crawl_id):
        query = """\
        SELECT req.id, req.url, req.top_level_url, req.method, req.referrer, req.headers, \
        req.triggering_origin, req.content_policy_type, req.post_body, req.time_stamp, \
        res.response_status, res.is_cached, res.headers AS res_headers \
        FROM http_responses AS res JOIN http_requests AS req ON req.id = res.id \
        WHERE req.crawl_id={} \
        """.format(crawl_id)

        curr = db.cursor()
        for row in curr.execute(query):
            yield row_to_dict(row)


    def sanitise_request_obj(req):
        req['found_urls'] = list(req['found_urls'])
        return req


    def row_to_dict(row):
        d = dict()
        d['url'] = row[1]
        d['top_level_url'] = row[2]
        d['method'] = row[3]
        d['referrer'] = row[4]
        d['req_headers'] = json.loads(row[5])
        d['triggering_origin'] = row[6]
        d['content_policy_type'] = row[7]
        if row[8] is not None and len(row[8]) > 0:
            d['text'] = row[8]
        d['urlencoded_form'] = []
        d['ts'] = datetime.strptime(row[9], '%Y-%m-%dT%H:%M:%S.%fZ').timestamp()

        d['req_cookies'] = []
        for k, v in d['req_headers']:
            if k == 'Cookie':
                d['req_cookies'].extend(iterate_cookie_string(v))
        
        d['res_headers'] = json.loads(row[12])
        d['res_status'] = row[10]
        d['is_cached'] = row[11]
        
        parsed_url = urlparse(d['url'])
        d['host'] = parsed_url.netloc
        d['scheme'] = parsed_url.scheme
        d['path'] = parsed_url.path
        d['port'] = parsed_url.port
        return d

    return iterate_requests(db, crawl_id)
