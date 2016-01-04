import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *



from config import config
from threading import Thread, Condition
import os, socket, SocketServer as socketserver
import time, struct, imp, inspect, select

def add_new_tcp_data(seq, packet_data, expected_seq, out_of_order_data, recv_buff):
    if expected_seq < seq:
        if seq in out_of_order_data:
            if len(out_of_order_data[seq]) < len(packet_data):
                out_of_order_data[seq] = packet_data
        else:
            out_of_order_data[seq] = packet_data
        return (expected_seq, out_of_order_data, recv_buff)
    if seq < expected_seq:
        overlap = expected_seq - seq
        packet_data = packet_data[overlap:]
    recv_buff += packet_data
    expected_seq += len(packet_data)
    for s in sorted(out_of_order_data):
        if expected_seq < s:
            break
        pktdata = out_of_order_data[s]
        if s < expected_seq:
            overlap = expected_seq - s
            pktdata = pktdata[overlap:]
        recv_buff += pktdata
        expected_seq += len(pktdata)
        del out_of_order_data[s]
    return (expected_seq, out_of_order_data, recv_buff)


class PartovServer:
    def __init__(self, client_manager):
        self.config = config['partov_server']
        self.server_port = self.config['port']
        self.client_manager = client_manager
        self.client_states = {}

        self.packets = []

    def start(self):
        def sniff_loop():
            conf.iface=str(self.config['iface'])
            sniff(iface=str(self.config['iface']), filter=("tcp and port %d" % self.server_port),
                  prn=lambda x: self.handle_frame(x))

        self.is_alive = True
        self.sniff_thread = Thread(target=sniff_loop)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def stop(self):
        self.is_alive = False

    def disconnect_client(self, client):
        if client in self.client_states:
            del self.client_states[client]

    def get_client(self, port):
        client = self.client_manager.find_client_by_port(port)
        if client in self.client_states:
            client_state = self.client_states[client]
        else:
            client_state = ClientState()
            self.client_states[client] = client_state
        return (client, client_state)

    def handle_frame(self, frame):
        if not self.is_alive: return

        tcp = frame.payload.payload
        if type(tcp.payload) == NoPayload:
            return
        if tcp.sport == self.server_port:
            client_port = tcp.dport
        elif tcp.dport == self.server_port:
            client_port = tcp.sport
        else:
            return

        client, client_state = self.get_client(client_port)

        if client == None or not client.started:
            return
        if tcp.sport == self.server_port:
            self.handle_receive_data(client, client_state, tcp.seq, list(tcp.load))
        elif tcp.dport == self.server_port:
            self.handle_send_data(client, client_state, tcp.seq, list(tcp.load))

    def handle_receive_data(self, client, state, seq = -1, packet_data = None):
        if packet_data != None:
            if state.expected_recv_seq == -1: # first packet determines the initial sequence number
                state.expected_recv_seq = seq
            state.expected_recv_seq, state.recv_out_of_order, state.recv_buff =\
                    add_new_tcp_data(seq, packet_data,
                            state.expected_recv_seq, state.recv_out_of_order, state.recv_buff)

        if len(state.recv_buff) >= state.recv_pending:
            packet = ''.join(state.recv_buff[:state.recv_pending])
            state.recv_buff = state.recv_buff[state.recv_pending:]
            state.recv_pending = 0

            if state.recv_state == Const.StateInRecv:
                interface = struct.unpack("!I", packet[0:4])[0]
                frame = Ether(packet[4:])
                client.put_recv_frame(frame, interface)
                # self.packets.append(frame)
                state.recv_state = Const.Nothing
                state.recv_pending = Const.RecvCommandLength
            else:
                command, size = struct.unpack("!IH", packet[0:6])
                if command == Const.RawFrameReceivedNotificationType:
                    state.recv_state = Const.StateInRecv
                    state.recv_pending = size
                else:
                    state.recv_pending = Const.RecvCommandLength
            self.handle_receive_data(client, state)

    def handle_send_data(self, client, state, seq = -1, packet_data = None):
        if packet_data != None:
            if state.expected_send_seq == -1: # first packet determines the initial sequence number
                state.expected_send_seq = seq
            state.expected_send_seq, state.send_out_of_order, state.send_buff =\
                    add_new_tcp_data(seq, packet_data,
                            state.expected_send_seq, state.send_out_of_order, state.send_buff)

        if len(state.send_buff) >= state.send_pending:
            packet = ''.join(state.send_buff[:state.send_pending])
            state.send_buff = state.send_buff[state.send_pending:]
            state.send_pending = 0

            if state.send_state == Const.StateInSendFrame:
                frame = Ether(packet)
                client.put_send_frame(frame, state.send_iface)
                self.packets.append(frame)
                state.send_state = Const.Nothing
                state.send_pending = Const.SendCommandLength
            elif state.send_state == Const.StateInSendData:
                length, iface = struct.unpack("!HI", packet)
                length -= 4
                state.send_state = Const.StateInSendFrame
                state.send_iface = iface
                state.send_pending = length
            else:
                command = struct.unpack("!I", packet[0:4])[0]
                if command == Const.SendFrameCommand:
                    state.started = True
                    state.send_state = Const.StateInSendData
                    state.send_pending = 6
                else:
                    state.send_pending = Const.SendCommandLength

            self.handle_send_data(client, state)

            # THIS
    def get_client_run_command(self, cwd, client_number=0, client_type='my'):
        # node = self.config['node_prefix'] + str(client_number)
        node = "node" + str(client_number)
        target = ""

        if client_type == 'my':
            target = os.path.join(cwd, config['my_router_target'])
        else:
            target = os.path.join(cwd, config['router_target'])
        command = "%s --ip %s --port %d --map %s --node %s --user %s --pass %s --id %s" % \
                (target, self.config['ip'],
                 self.config['port'], self.config['map'], node,
                 self.config['user'], self.config['pass'], self.config['user'])
        # HEREEEEE
        #print(command)
        return command






class Const:
    SendFrameCommand = 1
    RawFrameReceivedNotificationType = 4

    RecvCommandLength = 6
    SendCommandLength = 4

    StateInSendData = 1
    StateInSendFrame = 2
    StateInRecv = 1

    Nothing = -1

class ClientState:
    def __init__(self):
        self.send_buff = []
        self.recv_buff = []
        self.send_out_of_order = {}
        self.recv_out_of_order = {}
        self.send_pending = 4
        self.recv_pending = 6
        self.recv_state = -1
        self.send_state = -1
        self.send_iface = 0
        self.expected_recv_seq = -1
        self.expected_send_seq = -1
        self.started = False

class MockServer:
    def __init__(self, client_manager, custom_info=None, port=None):
        self.config = config.get("mock_server", {})
        self.client_manager = client_manager
        self.custom_info = custom_info or "\n".join(self.config.get("custom_info", [])).strip()
        self.port = self.config.get("port", 7891)
        self.server_port = self.port
        self.client_sockets = {}

    def get_client_run_command(self, cwd, client_number=0):
        nodes = self.config['iface'].keys()
        if len(nodes) <= client_number:
            raise MockServerError("Can't run client %d with Mock Server, iface information not given" % client_number)
        return "%s --ip 127.0.0.1 --port %d --map dummymap --node %s --user dummyuser --pass dummypass --id dummyid" % \
                (os.path.join(cwd, config['processor_target']), self.port, nodes[client_number])

    def start(self):
        self.is_alive = True
        self.server_thread = Thread(target=self.listen_for_clients)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop(self):
        self.is_alive = False

    def disconnect_client(self, client):
        pass
        # sock = self.client_sockets.get(client.port, None)
        # if sock:
            # del self.client_sockets[client.port]
            # sock.close()

    def remove_client(self, client_port):
        if client_port in self.client_sockets:
            del self.client_sockets[client_port]

    def send_frame(self, client, iface, frame):
        if client.port not in self.client_sockets:
            raise MockServerError("No client connected with port '%d'", client.port)
        try:
            sock = self.client_sockets[client.port]
            frame_data = str(frame)
            sock.sendall(struct.pack("!IHI", 4, len(frame_data) + 4, iface))
            sock.sendall(frame_data)
        except socket.error:
            self.remove_client(client.port)
            raise MockServerError("Connection lost with client '%d'", client.port)

    def handle_read_data(self, sock):
        address, port = sock.getpeername()
        data = sock.recv(10)
        if len(data) == 0:
            self.remove_client(port)
            return False
        com, size, iface = struct.unpack("!IHI", data)
        frame = sock.recv(size - 4)

        client = self.client_manager.find_client_by_port(port)
        if client == None:
            self.remove_client(port)
            return False

        client.put_send_frame(Ether(frame), iface)
        return True

    def do_initial_negotiations(self, req):
        self.do_signing_in_negotiations(req)
        self.do_map_selecting_negotiations(req)
        node_name = self.do_node_selecting_negotiations(req).strip().replace("\0", "")
        self.do_information_synchronization_negotiations(req, node_name)

    def do_signing_in_negotiations(self, req):
        size = struct.unpack("!H", req.recv(2))[0]
        req.recv(size)
        req.sendall(struct.pack("!II", 0, 1))

    def do_map_selecting_negotiations(self, req):
        size = struct.unpack("!H", req.recv(2))[0]
        req.recv(size)
        req.sendall(struct.pack("!II", 1, 2))

    def do_node_selecting_negotiations(self, req):
        size = struct.unpack("!H", req.recv(2))[0]
        node_name = req.recv(size)
        req.sendall(struct.pack("!II", 1, 4))
        return node_name

    def do_information_synchronization_negotiations(self, req, node_name):
        self.do_interfaces_information_synchronization_negotiations(req, node_name)
        self.do_custom_information_synchronization_negotiations(req)

    def do_interfaces_information_synchronization_negotiations(self, req, node_name):
        req.recv(4)
        req.sendall(struct.pack("!II", 2, 1))
        iface_string = "edu::sharif::partov::nse::map::interface::EthernetInterface\0"

        if node_name not in self.config.get("iface", {}):
            raise MockServerError("No iface information found for node '%s'" % node_name)
        ifaces = self.config["iface"][node_name]

        req.sendall(struct.pack("!I", len(ifaces)))
        for iface in ifaces:
            req.sendall(struct.pack("!H", len(iface_string) + 16))
            req.sendall(iface_string)

            mac_bytes = map(lambda x: int(x, 16), iface['mac'].split(":"))
            mac_bytes.append(0)
            mac_bytes.append(0)
            req.sendall(struct.pack("BBBBBBBB", *mac_bytes))
            req.sendall(socket.inet_aton(iface['ip']))
            req.sendall(socket.inet_aton(iface['mask']))

    def do_custom_information_synchronization_negotiations(self, req):
        req.recv(4)
        custom_info = self.custom_info + '\0'
        req.sendall(struct.pack("!IIH", 2, 2, len(custom_info)))
        req.sendall(custom_info)

    def start_simulation(self, req):
        req.recv(4)
        req.sendall(struct.pack("!I", 3))

    def handle_connection(self, req):
        self.do_initial_negotiations(req)
        self.start_simulation(req)
        address, port = req.getpeername()
        self.client_sockets[port] = req

    def listen_for_clients(self):
        serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        serversocket.bind(("127.0.0.1", self.port))
        serversocket.listen(5)
        # serversocket.setblocking(0)

        connections = [serversocket]
        while self.is_alive:
            readable, writable, exceptional = select.select(connections, [], [])
            if not self.is_alive: break
            for s in readable:
                if s is serversocket:
                    connection, client_address = s.accept()
                    connections.append(connection)
                    connection.setblocking(True)
                    self.handle_connection(connection)
                else:
                    if not self.handle_read_data(s):
                        s.shutdown(1)
                        connections.remove(s)

class MockServerError(Exception):
    pass
