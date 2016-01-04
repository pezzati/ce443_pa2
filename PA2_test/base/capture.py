from scapy.all import *
from threading import Thread, Condition

import time, struct, imp, inspect


class NetworkMonitor:
    def __init__(self, client_manager, partov_port):
        self.partov_port = partov_port
        self.client_manager = client_manager
        self.client_states = {}
        self.enable = False

    def start(self):
        def sniff_loop():
            sniff(iface="wlan0", store=0, filter="tcp and port %d" %self.partov_port, prn=lambda x: self.handle_frame(x))

        self.sniff_thread = Thread(target=sniff_loop)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
        time.sleep(4)


    def clear(self):
        self.client_states = {}

    def disable_capturing(self):
        self.enable = False
        self.clear()

    def enable_capturing(self):
        self.clear()
        self.enable = True



    def get_client(self, port):
        client = self.client_manager.find_client_by_port(port)
        if client in self.client_states:
            client_state = self.client_states[client]
        else:
            client_state = ClientState()
            self.client_states[client] = client_state
        return (client, client_state)

    def handle_frame(self, frame):
        tcp = frame.payload.payload
        if type(tcp.payload) == NoPayload:
            return
        if tcp.sport == self.partov_port:
            client_port = tcp.dport
        elif tcp.dport == self.partov_port:
            client_port = tcp.sport
        else:
            return

        client, client_state = self.get_client(client_port)

        if client == None or not client.started:
            return
        if tcp.sport == self.partov_port:
            self.handle_receive_data(str(tcp.payload), client, client_state)
        elif tcp.dport == self.partov_port:
            self.handle_send_data(str(tcp.payload), client, client_state)

    def handle_receive_data(self, packet_data, client, state):
        if packet_data != None:
            state.recv_buff += packet_data

        if len(state.recv_buff) >= state.recv_pending:
            packet = ''.join(state.recv_buff[:state.recv_pending])
            state.recv_buff = state.recv_buff[state.recv_pending:]
            state.recv_pending = 0

            if state.recv_state == Const.StateInRecv:
                interface = struct.unpack("!I", packet[0:4])[0]
                frame = Ether(packet[4:])
                client.put_recv_frame(frame, interface)

                state.recv_state = Const.Nothing
                state.recv_pending = Const.RecvCommandLength
            else:
                command, size = struct.unpack("!IH", packet[0:6])
                if command == Const.RawFrameReceivedNotificationType:
                    state.recv_state = Const.StateInRecv
                    state.recv_pending = size
                else:
                    state.recv_pending = Const.RecvCommandLength

            self.handle_receive_data(None, client, state)


    def handle_send_data(self, packet_data, client, state):
        if packet_data != None:
            state.send_buff += packet_data
        if len(state.send_buff) >= state.send_pending:
            packet = ''.join(state.send_buff[:state.send_pending])
            state.send_buff = state.send_buff[state.send_pending:]
            state.send_pending = 0

            if state.send_state == Const.StateInSendFrame:
                frame = Ether(packet)
                client.put_send_frame(frame, state.send_iface)
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

            self.handle_send_data(None, client, state)
            return

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
        self.send_pending = 4
        self.recv_pending = 6
        self.recv_state = -1
        self.send_state = -1
        self.send_iface = 0
        self.started = False

