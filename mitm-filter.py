import json
from mitmproxy.script import concurrent

@concurrent
def response(flow):
    req_data = dict()

    req_data['req_cookies'] = flow.request.cookies.collect()
    if len(flow.request.text) > 0:
        req_data['text'] = str(flow.request.text)
    req_data['req_headers'] = flow.request.headers.collect()
    req_data['host'] = flow.request.host
    req_data['method'] = flow.request.method
    # multipart_form
    req_data['path'] = flow.request.path
    req_data['path_components'] = flow.request.path_components
    req_data['port'] = flow.request.port
    req_data['scheme'] = flow.request.scheme
    req_data['url'] = flow.request.url
    req_data['urlencoded_form'] = flow.request.urlencoded_form.collect()

    #req_data['res_cookies'] = flow.response.cookies.collect()
    req_data['res_headers'] = flow.response.headers.collect()
    req_data['res_status'] = flow.response.status_code
    print(json.dumps(req_data))

@concurrent
def websocket_end(flow):
    pass