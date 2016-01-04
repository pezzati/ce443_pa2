from subprocess import Popen, call, check_output, PIPE, STDOUT
from threading import Thread, Condition
from Queue import Queue,Empty
from logger import logger
from config import config
import os, re, time, signal, sys


class ClientRun:
    def __init__(self, client_number, cwd, server):
        self.client_number = client_number
        self.cwd = cwd
        self.server = server

        self.net_send_queues = {}
        self.net_recv_queues = {}
        self.io_read_queue = Queue()
        self.started = False
        self.start_cond = Condition()
        self.is_alive = True

    def initialize_for_use(self):
        self.find_process_pid()
        self.find_process_port()
        self.start_io_read_thread()

    def set_status(self, status, color="dim"):
        logger.set_test_status("client #%d %s" % (self.client_number, status), color)

    def start_process(self, client_type):
        DEVNULL = open(os.devnull, 'wb')
        self.set_status("Starting process")
        command = self.server.get_client_run_command(cwd=self.cwd, client_number=self.client_number, client_type=client_type)
        # print(command)
        self.process = Popen(command, shell=True, executable="/bin/bash", stdin=PIPE,
                              stdout=PIPE, stderr=DEVNULL, preexec_fn=os.setsid)


    def find_process_pid(self):
        self.pid = self.process.pid
        # # No need anymore since we're running run.out directly
        # parent_pid = self.process.pid
        # output = check_output(["ps", "--ppid", str(parent_pid)])
        # output = output.split("\n")[1]
        # pid = output.strip().split(" ")[0]
        # self.pid = int(pid.strip())

    def find_process_port(self):
        lsof = check_output(["lsof", "-i4TCP", "-n", "-P" ])
        lsof = lsof.split("\n")
        for line in lsof:
            parts = line.split()
            if '->' in line and parts[1] == str(self.pid):
                if not str(self.server.server_port) in parts[8]:
                    continue
                ports = map(lambda x: x[x.index(":")+1:], parts[8].split("->"))
                self.port = int(ports[0])
                return
        raise ClientRunError("Failed to extract port number for process")

    def start_io_read_thread(self):
        def read_loop():
            while self.is_alive and self.io_read_thread.is_alive():
                s = self.process.stdout.readline()
                if not self.is_alive: break

                if self.started and s is not None:
                    self.io_read_queue.put(s)
                    # if len(s.strip()) > 0:
                    # 	print(s)
                elif not self.started and s is not None:
                    stats = filter(lambda x: s.startswith(x), checkpoint_status_lines)
                    if len(stats) != 0:
                        self.set_status(stats[0])
                    if s.startswith("Simulation started"):
                        self.process.stdout.readline() # Read extra "====" line
                        self.started = True
                        self.start_cond.acquire()
                        self.start_cond.notifyAll()
                        self.start_cond.release()
        self.io_read_thread = Thread(target=read_loop)
        self.io_read_thread.daemon = True
        self.io_read_thread.start()

    def wait_for_start(self, timeout=None):
        if not self.started:
            self.start_cond.acquire()
            self.start_cond.wait(timeout)
            self.start_cond.release()

    def kill(self):
        self.is_alive = False
        os.killpg(self.process.pid, signal.SIGINT)
        self.server.disconnect_client(self)

    def write_io(self, command):
        self.process.stdin.write(command + '\n')
        self.process.stdin.flush()

    def read_io(self, block=True, timeout=None):
        try:
            return self.io_read_queue.get(block=block, timeout=timeout)
        except Empty:
            return None

    def clear_read_queue(self):
        with self.io_read_queue.mutex:
            self.io_read_queue.queue.clear()
        try:
            while True:
                s = self.io_read_queue.get(block=False)
        except Empty: pass

    def put_frame(self, queue_list, frame, iface):
        if iface not in queue_list:
            queue_list[iface] = Queue()
        queue_list[iface].put(frame)

    def get_frame(self, queue_list, iface, block, timeout):
        if iface not in queue_list:
            queue_list[iface] = Queue()
        try:
            return queue_list[iface].get(block=block, timeout=timeout)
        except Empty:
            return None

    def clear_queue(self, queue_list, iface):
        if type(iface) != list:
            iface = [iface]
        for i in iface:
            if i not in queue_list:
                return
            try:
                while True:
                    s = queue_list[i].get(block=False)
            except Empty: pass

    def put_send_frame(self, frame, iface):
        self.put_frame(self.net_send_queues, frame, iface)

    def put_recv_frame(self, frame, iface):
        self.put_frame(self.net_recv_queues, frame, iface)

    def get_send_frame(self, iface, block=True, timeout=None):
        return self.get_frame(self.net_send_queues, iface, block, timeout)

    def get_recv_frame(self, iface, block=True, timeout=None):
        return self.get_frame(self.net_recv_queues, iface, block, timeout)

    def clear_send_queue(self, iface):
        self.clear_queue(self.net_send_queues, iface)

    def clear_recv_queue(self, iface):
        self.clear_queue(self.net_recv_queues, iface)

    def send_fake_frame(self, iface, frame):
        try:
            self.server.send_frame(client=self, iface=iface, frame=frame)
        except AttributeError:
            error = "Server type '%s' does not support sending frames. Try using the MockServer instead"
            raise ClientRunError(error % type(self.server))

class ClientManager:
    def __init__(self, cwd):
        self.clients = []
        self.cwd = cwd
        self.config = config['partov_server']

    def set_monitor(self , network_monitor):
        self.network_monitor = network_monitor

    def clear(self):
        self.network_monitor.clear()
        for client in self.clients:
            client.net_recv_queues = {}
            client.net_send_queues = {}
            client.io_read_queues = {}

    def clean_clients(self):
        while self.clients:
            self.clients.pop().kill()

    def start_clients(self, server, types, count=1):
        new_clients = []
        for i in range(count):
            client = ClientRun(len(self.clients) + i, cwd=self.cwd, server=server)
            client.start_process(client_type=types[i])
            new_clients.append(client)

        # Give time for process creation
        time.sleep(0.5)

        for client in new_clients:
            client.initialize_for_use()
            self.clients.append(client)


    def disable_capturing(self):
        self.network_monitor.disable_capturing()

    def enable_capturing(self):
        self.network_monitor.enable_capturing()


    def restart_clients(self, count=1):
        self.clean_clients()
        self.start_clients(count)

    def find_client_by_port(self, port):
        for client in self.clients:
            if client.port == port:
                return client
        return None

    def get_free_command(self):
        target = os.path.join(self.cwd, config['my_router_target'])
        command = "%s --ip %s --port %d --map %s --user %s --pass %s --free" % \
                (target, self.config['ip'],
                 self.config['port'], self.config['map'],
                 self.config['user'], self.config['pass'])
        return command


    def get_new_command(self):
        target = os.path.join(self.cwd, config['my_router_target'])
        command = "%s --ip %s --port %d --map %s --user %s --pass %s --new" % \
                (target, self.config['ip'],
                 self.config['port'], self.config['map'],
                 self.config['user'], self.config['pass'])
        return command

    def new_map(self):
        command = self.get_new_command()
        # print(command)
        # print(self.cwd)
        res = call(command, shell=True, executable="/bin/bash", stdout=PIPE, stderr=PIPE)

        return  res == 0

    def free_map(self):
        command = self.get_free_command()
        # print(command)
        return call(command, shell=True, executable="/bin/bash", stdout=PIPE, stderr=PIPE) == 0

    def check_cwd(self):
        directory = os.listdir(self.cwd)
        files = ['info.sh']
        for f in files:
            if f not in directory:
                return False
        return True

    def check_exec(self):
        directory = os.listdir(self.cwd)
        exist = (config['router_target'] in directory)
        return exist


class ClientRunError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


checkpoint_status_lines = [
    "Signing in...",
    "Selecting map...",
    "Connecting to node...",
    "Synchronizing information...",
    "Simulation started",
]

