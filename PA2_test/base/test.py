from functools import partial
from Queue import Queue, Empty
from logger import logger
import time, imp, inspect, sys
from scapy.all import *

class TestExecuter:
    def __init__(self, client_manager, partov_server, mock_server):
        self.client_manager = client_manager
        self.partov_server = partov_server
        self.mock_server = mock_server

    def load_tests(self, test_module):
        is_test_class = lambda x: inspect.isclass(x) and issubclass(x, Test) and x != Test
        test_classes = inspect.getmembers(test_module, is_test_class)
        test_instances = map(lambda x: x[1](self.client_manager, self.partov_server, self.mock_server), test_classes)
        self.tests = test_instances
        self.categorize_tests(test_instances)

    def categorize_tests(self, test_instances):
        self.categories = {}
        for test in test_instances:
            try:
                category = getattr(test, "category")
            except AttributeError:
                category = "Uncategorized"
            self.categories.setdefault(category, []).append(test)

        def key(test):
            try: return test.order
            except AttributeError: return 1000
        for category in self.categories:
            self.categories[category].sort(key=key)

    def execute_tests(self):
        is_test_method = lambda x: inspect.ismethod(x) and x.__name__.startswith("test_")
        for category in sorted(self.categories):
            logger.start_category(category)

            for test in self.categories[category]:
                if not getattr(test, 'enabled', True):
                    continue
                test_methods = map(lambda x: x[1], inspect.getmembers(test, is_test_method))
                # def foo(x):
                # 	print(x)
                # inspect.getmembers(test, foo)
                # print(test.__dict__)

                def key(meth):
                    try:
                        if getattr(test, 'test_order', None):
                            return test.test_order.index(meth.__name__)
                        return 0
                    except ValueError:
                        return len(test_methods)
                test_methods.sort(key=key)

                logger.start_test(test.description)
                if getattr(test, "init", None):
                    test.init()

                for test_method in test_methods:
                    try:
                        test.start_test_method()
                        if getattr(test, "before", None):
                            test.before()
                        test_method()
                        if getattr(test, "after", None):
                            test.after()
                    except EndTestMethodException:
                        continue
                    except EndTestException:
                        break
                    except Exception as e:
                        import traceback
                        traceback.print_exc()
                        test.add_exception(e)
                    finally:
                        test.end_test_method()

                    f = open("%s.log" %test_method.__name__, 'w')

                    for exception in test.method_exceptions:
                        if isinstance(exception, AssertionError):
                            f.write("#Assertion Error: " + exception.message + "\n")
                    f.close()
                    if len(self.partov_server.packets) > 0:
                        wrpcap("%s.cap" %test_method.__name__ ,self.partov_server.packets)
                    self.partov_server.packets = []
                    self.method_exceptions = []

                for exception in test.exceptions:
                    if isinstance(exception, AssertionError):
                        logger.end_test(" " + exception.message, "red")
                        break
                    else:
                        logger.end_test(" [EXCEPTION] " + str(exception), "red")
                        break

                else:
                    logger.end_test("", "green")

                if getattr(test, "end", None):
                    test.end()

        logger.line_break()


class Test(object):
    def __init__(self, client_manager, partov_server, mock_server):
        self.client_manager = client_manager
        self.partov_server = partov_server
        self.mock_server = mock_server

        self.clients = self.client_manager.clients
        self.log = self.log_status
        self.grade_sum = 0
        self.grade_current = 0

        self.exceptions = []
        self.method_exceptions =[]

    def free_map(self):
        self.client_manager.free_map()

    def new_map(self):
        counter = 10
        while not self.client_manager.new_map():
            logger.log("Failed to create new map", break_after=True, color="error")
            time.sleep(1)
            self.client_manager.free_map()
            time.sleep(1)
            counter -=1
            if counter == 0 :
                sys.exit(1)
        time.sleep(1)

    def disable_capturing(self):
        self.client_manager.disable_capturing()

    def enable_capturing(self):
        self.client_manager.enable_capturing()

    def clear_clients(self):
        self.client_manager.clear()

    def start_clients(self, types, count=1, mock=False):
        server = self.mock_server if mock else self.partov_server
        self.client_manager.start_clients(count=count, server=server, types=types)

    def kill_clients(self):
        self.client_manager.clean_clients()

    def log_status(self, status, color="dim"):
        logger.set_test_status(status, color)

    def wait(self, seconds):
        time.sleep(seconds)

    def current_time(self):
        return int(round(time.time() * 1000))

    def assert_equals(self, expected, actual, message="", end=True, grade=0):
        if message: message += '; '
        message = message + "Expected %s but got %s" % (str(expected), str(actual))

        return self.assert_true(expected == actual, message=message, end=end, grade=grade)

    def assert_false(self, condition, message="", end=True, grade=0):
        return self.assert_true(not condition, message=message, end=end, grade=grade)

    def assert_true(self, condition, message="", end=True, grade=0):
        if not condition:
            self.add_exception(AssertionError(message))
            if end:
                raise EndTestMethodException()
            return False
        elif grade > 0:
            self.grade(grade)
        return True

    def add_exception(self, exception):
        self.test_method_success = False
        self.exceptions.append(exception)
        self.method_exceptions.append(exception)

    def start_test_method(self):
        self.grade_current = 0
        self.test_method_success = True

    def end_test_method(self):
        self.grade_sum += self.grade_current
        self.grade_current = 0

    def set_current_test_grade(self, amount):
        self.grade_current = amount
        logger.set_test_grade(self.grade_current + self.grade_sum)

    def end_if_failed(self):
        if len(self.exceptions) > 0:
            raise EndTestException()

    def grade(self, amount):
        self.set_current_test_grade(self.grade_current + amount)

class EndTestException(Exception):
    pass
class EndTestMethodException(Exception):
    pass

def grade(amount):
    def wrapper(func):
        def inner(self, *args, **kwargs):
            func(self, *args, **kwargs)
            if self.test_method_success:
                self.set_current_test_grade(amount)
        inner.__name__ = func.__name__
        return inner
    return wrapper

