from datetime import datetime
import json
import logging
from socket import gethostname
import traceback


class JSONFormatter(logging.Formatter):
    """Custom formatter to output log records as JSON."""

    hostname = gethostname()

    def format(self, record):
        """Format the given record into JSON."""
        message = {
            "time": datetime.utcfromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
            "process": record.process,
            "thread": record.threadName,
            "hostname": self.hostname,
            "filename": record.filename,
            "function": record.funcName,
            "lineNo": record.lineno,
        }

        if record.exc_info:
            message[
                "exception"
            ] = f"{record.exc_info[0].__name__}: {record.exc_info[1]}"
            message["traceback"] = traceback.format_exc()

        return json.dumps(message, ensure_ascii=False)
