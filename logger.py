import fileinput
import json
from logging.handlers import TimedRotatingFileHandler

class NoFormatter():

    def format(self, record):
        return record.strip()

if __name__ == '__main__':
    logger = TimedRotatingFileHandler('reqlog.jl', when='h', utc=True)
    formatter = NoFormatter()
    logger.setFormatter(formatter)

    for line in fileinput.input():
        logger.emit(line)

    logger.flush()
