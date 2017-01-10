import fileinput
import json
import argparse
import sys
from logging.handlers import TimedRotatingFileHandler

class NoFormatter():

    def format(self, record):
        return record.strip()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("logdir")
    args = parser.parse_args()
    logger = TimedRotatingFileHandler(args.logdir + '/reqlog.jl', when='h', utc=True)
    formatter = NoFormatter()
    logger.setFormatter(formatter)

    for line in sys.stdin:
        logger.emit(line)

    logger.flush()
