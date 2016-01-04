from threading import Thread, Condition
from cStringIO import StringIO
from Queue import Queue, Empty
import sys, signal


class PrettyLogger:
    def __init__(self, outfile):
        self.current_test = None
        self.log_queue = Queue()
        self.breaked = True
        self.last_line_length = 0
        self.line_length = 0
        self.grade = 0
        self.outfile = outfile

    def start_print_thread(self):
        def print_thread():
            m = ""
            while self.is_alive:
                m = self.log_queue.get()
                self.outfile.write(m)
                self.outfile.flush()

        t = Thread(target=print_thread)
        t.daemon = True
        t.start()

    def flush(self):
        try:
            while True:
                m = self.log_queue.get(block=False)
                sys.stdout.write(m)
                sys.stdout.flush()
        except Empty: pass

    def start(self):
        self.is_alive = True
        self.start_print_thread()

    def stop(self):
        self.is_alive = False

    def start_category(self, category):
        self.log(colorize(category, 'bold', 'blue'))

    def start_test(self, test_name):
        self.current_test = test_name
        self.log(colorize(self.current_test, 'test'), break_after=False)
        self.grade = 0

    def set_test_grade(self, grade):
        self.grade = grade
        self.refresh_line()

    def set_test_status(self, status, status_color="dim"):
        self.status = status
        self.status_color = status_color
        self.refresh_line()

    def refresh_line(self):
        if not self.current_test:
            return
        line = "    %s %s %s" % (
            colorize("%6s" % ("[%d%%]" % self.grade), "magneta"),
            colorize(self.current_test + ": ", 'test', 'bold'),
            colorize(self.status, self.status_color)
        )
        self.log(line, break_before=False, break_after=False, clear=True, clear_rest=True)

    def end_test(self, message="", message_color="white"):
        grade_color = 'red' if self.grade < 50 else 'yellow' if self.grade < 100 else 'green'
        line = "    %s %s %s" % (
            colorize("%6s" % ("[%d%%]" % self.grade), 'bold', grade_color),
            colorize(self.current_test, 'test', 'bold'),
            colorize(str(message), message_color)
        )
        self.log(line, break_before=False, break_after=True, clear=True, clear_rest=True)

        self.current_test = None
        self.status = ""
        self.grade = 0

    def log(self, msg, color=None, break_before=True, break_after=True, clear=False, clear_rest=False):
        if clear:
            self.log_queue.put("\r")
            self.last_line_length = self.line_length
            self.line_length = 0

        if break_before and not self.breaked:
            self.log_queue.put("\n")
            self.line_length = 0
            self.last_line_length = 0

        message = str(msg)
        if color:
            message = colorize(message, color)
        self.line_length += len(message)

        if clear_rest and self.last_line_length > self.line_length - 10:
            message =  message + (" " * (self.last_line_length - self.line_length + 10))
        self.log_queue.put(message)

        if break_after:
            self.log_queue.put("\n")
            self.line_length = 0
            self.last_line_length = 0

        self.breaked = break_after

    def line_break(self):
        if not self.breaked:
            self.log_queue.put("\n")
            self.breaked = True

    def print_packet(self, p):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        p.show()
        sys.stdout = old_stdout
        self.log(mystdout.getvalue())

class PlainLogger:
    def __init__(self, outfile):
        self.outfile = outfile

    def start_test(self, *args, **kwargs):
        self.grade = 0

    def set_test_grade(self, grade, *args, **kwargs):
        self.grade = grade

    def end_test(self, *args, **kwargs):
        self.outfile.write("%.2f " % (self.grade/100.0))

    def stop(self, *args, **kwargs):
        self.outfile.write("\n")

class LoggerProxy:
    def __init__(self):
        self.handlers = []

    def add_handler(self, handler):
        self.handlers.append(handler)

    def __getattr__(self, call):
        def inner(*args, **kwargs):
            for handler in self.handlers:
                try:
                    getattr(handler, call)(*args, **kwargs)
                except AttributeError: pass
        return inner

color_map = {
    'bold': '\x1b[1m',
    'dim': '\x1b[2m',
    'test': '\033[37m',
    'white': '\033[37m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'red': '\033[91m',
    'blue': '\033[94m',
    'magneta': '\033[95m',
    'cyan': '\033[96m',
    'error': '\033[91m',
    'end': '\033[0m'
}


def colorize(txt, *color_names):
    if color_names:
        for color in color_names:
            if color:
                txt = color_map[color] + txt
        txt += color_map['end']
    return txt

logger = LoggerProxy()