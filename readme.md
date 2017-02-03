## Tracking Measurement

This code aims to measure third-party tracking over a recorded browsing session but searching for data points which can be used to link requests.

### Usage

First, start the mitmproxy with logging enabled

```mitmdump -q -s mitm-filter.py | python3 logger.py /path/to/logdir```

Point your browser at the proxy (default `localhost:8080`) and install the mitmproxy certificate to allow inspection of https traffic by browsing to http://mitm.it.

### Analysis

The provided scripts and notebook can be used to analyse the generated logs for tracked sessions (requires pyspark).
