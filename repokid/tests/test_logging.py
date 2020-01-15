from mock import patch

from repokid.utils.logging import JSONFormatter


class MockRecord(object):
    def __init__(self, message):
        self.created = 1579129029
        self.levelname = "INFO"
        self.name = "repokid_test"
        self.message = message
        self.process = 12345
        self.threadName = "MainThread"
        self.exc_info = None

    def getMessage(self):
        return self.message

class MockTraceback(object):
    def format_exc(self):
        return "this is totally a traceback"


class TestLogging(object):
    formatter = JSONFormatter()
    formatter.hostname = "test_host"

    def test_format(self):
        record = MockRecord("Hi there!")
        result = self.formatter.format(record)
        expected = """{"time": "2020-01-15T14:57:09", "level": "INFO", "name": "repokid_test", "message": "Hi there!", "process": 12345, "thread": "MainThread", "hostname": "test_host"}"""
        assert result == expected

    def test_format_with_exception(self):
        record = MockRecord("Hi there!")
        record.exc_info = (AttributeError, AttributeError("you did a wrong thing"), MockTraceback())
        with patch("traceback.format_exc", return_value="this is totally a traceback"):
            result = self.formatter.format(record)
        expected = """{"time": "2020-01-15T14:57:09", "level": "INFO", "name": "repokid_test", "message": "Hi there!", "process": 12345, "thread": "MainThread", "hostname": "test_host", "exception": "AttributeError: you did a wrong thing", "traceback": "this is totally a traceback"}"""
        assert result == expected
