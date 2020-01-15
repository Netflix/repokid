from datetime import datetime
import json
import logging
from socket import gethostname
import traceback


class ContextFilter(logging.Filter):
    """Logging Filter for adding hostname to log entries."""

    hostname = gethostname()

    def filter(self, record):
        record.hostname = ContextFilter.hostname
        return True


class JSONFormatter(logging.Formatter):
    """Custom formatter to output log records as JSON."""

    def format(self, record):
        """Format the given record into JSON."""
        message = {
            'time': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'name': record.name,
            'message': record.getMessage(),
            'process': record.process,
            'thread': record.threadName
        }

        if record.exc_info:
            message['exception'] = f'{record.exc_info[0].__name__}: {record.exc_info[1]}'
            message['traceback'] = traceback.format_exc()

        return json.dumps(message, ensure_ascii=False)
