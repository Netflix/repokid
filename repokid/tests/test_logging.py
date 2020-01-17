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
        self.filename = "hack_the_planet.py"
        self.funcName = "exploit"
        self.lineno = 42

    def getMessage(self):
        return self.message


class TestLogging(object):
    formatter = JSONFormatter()
    formatter.hostname = "test_host"

    def test_format(self):
        record = MockRecord("Hi there!")
        result = self.formatter.format(record)
        expected = """{"time": "2020-01-15T22:57:09", "level": "INFO", "name": "repokid_test", "message": "Hi there!", "process": 12345, "thread": "MainThread", "hostname": "test_host", "filename": "hack_the_planet.py", "function": "exploit", "lineNo": 42}"""  # noqa: E501
        assert result == expected

    def test_format_with_exception(self):
        record = MockRecord("Hi there!")
        record.exc_info = (
            AttributeError,
            AttributeError("you did a wrong thing"),
            None,
        )
        with patch("traceback.format_exc", return_value="this is totally a traceback"):
            result = self.formatter.format(record)
        expected = """{"time": "2020-01-15T22:57:09", "level": "INFO", "name": "repokid_test", "message": "Hi there!", "process": 12345, "thread": "MainThread", "hostname": "test_host", "filename": "hack_the_planet.py", "function": "exploit", "lineNo": 42, "exception": "AttributeError: you did a wrong thing", "traceback": "this is totally a traceback"}"""  # noqa: E501
        assert result == expected
