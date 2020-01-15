import json
import logging
import traceback
from datetime import datetime
from socket import gethostname


class ContextFilter(logging.Filter):
    """Logging Filter for adding hostname to log entries."""

    hostname = gethostname()

    def filter(self, record):
        record.hostname = ContextFilter.hostname
        return True


class JSONFormatter(logging.Formatter):
    """Custom formatter to output log records as JSON."""

    def __init__(self, *args, **kwargs):
        """Initialize the JSONFormatter."""
        dummy = logging.LogRecord(None, None, None, None, None, None, None)
        self.default_attributes = dummy.__dict__.keys()
        super().__init__(*args, **kwargs)

    def format(self, record):
        """Format the given record into JSON."""
        # Extract all extra attributes
        extra = {k: v for k, v in record.__dict__.items() if k not in self.default_attributes}

        message = {
            'time': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'name': record.name,
            'message': record.getMessage(),
            'process': record.process,
            'thread': record.threadName
        }
        message.update(extra)

        if record.exc_info:
            message['exception'] = f'{record.exc_info[0].__name__}: {record.exc_info[1]}'
            message['traceback'] = traceback.format_exc()

        return json.dumps(message, ensure_ascii=False)
