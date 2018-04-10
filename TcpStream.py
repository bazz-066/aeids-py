from impacket import ImpactPacket, ImpactDecoder

import binascii
import threading
import time
from pprint import pprint
from inspect import getmembers

STATE_JUST_EST = 0
STATE_DATA = 1
STATE_WAIT_FIN1 = 2
STATE_WAIT_FIN2 = 3
STATE_CLOSE = 4
STATE_TIMEOUT = 5
STATE_RESET = 6

end_states = (STATE_CLOSE, STATE_RESET, STATE_TIMEOUT)

def generate_id(ether):
    packet = ether.child()
    segment = packet.child()

    src_addr = packet.get_ip_src()
    dst_addr = packet.get_ip_dst()

    if isinstance(segment, ImpactPacket.TCP):
        protocol = "tcp"
        src_port = segment.get_th_sport()
        dst_port = segment.get_th_dport()
        return ("{}-{}-{}-{}-{}".format(src_addr, src_port, dst_addr, dst_port, protocol), (src_addr, src_port, dst_addr, dst_port))
    else:
        return False


def generate_reverse_id(ether):
    packet = ether.child()
    segment = packet.child()

    src_addr = packet.get_ip_src()
    dst_addr = packet.get_ip_dst()

    if isinstance(segment, ImpactPacket.TCP):
        protocol = "tcp"
        src_port = segment.get_th_sport()
        dst_port = segment.get_th_dport()
        return ("{}-{}-{}-{}-{}".format(dst_addr, dst_port, src_addr, src_port, protocol), (src_addr, src_port, dst_addr, dst_port))
    else:
        return False


def __calculate_byte_frequency__(payload, length):
    byte_frequency = [0] * 256

    if length > 0:
        for i in range(0, 256):
            byte_frequency[i] = float(payload.count(chr(i))) / length

    return byte_frequency


class TcpStream(threading.Thread):
    def __init__(self, id, start_time, reader_thread):
        threading.Thread.__init__(self)
        info = id.split("-")
        self.tcp_tuple = (info[0], info[1], info[2], info[3])
        self.reader_thread = reader_thread
        self.id = id
        self.start_time = start_time
        self.stop_time = -1
        self.client_buffer = []
        self.server_buffer = []
        self.last_packet_time = start_time
        self.state = STATE_JUST_EST
        self.client_data = ""
        self.server_data = ""
        self.client_last_seq = -1
        self.server_last_seq = -1
        self.ready = False
        self.client_data_len = -1
        self.server_data_len = -1
        self.client_bf = None
        self.server_bf = None
        self.read = False

    def run(self):
        while self.state not in end_states:
            if self.reader_thread.is_timeout(self.last_packet_time) and self.state not in end_states:
                self.state = STATE_TIMEOUT
            else:
                time.sleep(0.0001)
                # continue

        # self.finish()
        # print(threading.current_thread().name + "move-in")
        self.reader_thread.move_stream(self.id)
        # print(threading.current_thread().name + "move-out")


    # TODO: consider IP fragmentation
    def add_packet(self, ts, to_server, ether):
        packet = ether.child()
        segment = packet.child()

        # pprint(getmembers(segment))
        # identify TCP flags
        if segment.get_SYN() and to_server:
            # print("syn")
            self.server_last_seq = segment.get_th_seq()
            # print("syn: ", self.server_last_seq)
            return
        elif segment.get_SYN() and segment.get_ACK() and not to_server:
            # print("syn-ack")
            self.client_last_seq = segment.get_th_seq()
            self.state = STATE_DATA
            return
        elif segment.get_FIN() and self.state < STATE_WAIT_FIN1:
            # print("fin", segment.get_ACK(), to_server, self.id)
            if to_server:
                self.server_last_seq = segment.get_th_seq()
            else:
                self.client_last_seq = segment.get_th_seq()
            self.state = STATE_WAIT_FIN1
            self.last_packet_time = ts
            self.stop_time = ts
            return
        elif segment.get_FIN() and self.state == STATE_WAIT_FIN1:
            if to_server:
                self.server_last_seq = segment.get_th_seq()
            else:
                self.client_last_seq = segment.get_th_seq()
            self.state = STATE_WAIT_FIN2
            self.last_packet_time = ts
            self.stop_time = ts
            # print("wait fin")
            return
        elif segment.get_ACK() and self.state == STATE_WAIT_FIN2 and to_server and segment.get_th_seq() > self.server_last_seq:
            # print("close1")
            self.last_packet_time = ts
            self.stop_time = ts
            self.state = STATE_CLOSE
            return
        elif segment.get_ACK() and self.state == STATE_WAIT_FIN2 and not to_server and segment.get_th_seq() > self.client_last_seq:
            # print("close2")
            self.last_packet_time = ts
            self.stop_time = ts
            self.state = STATE_CLOSE
            return
        else: # data
            if self.state not in end_states:
                # print("data")
                if len(segment.get_data_as_string()) > 0:
                    # print(5)
                    self.last_packet_time = ts
                    self.stop_time = ts
                    if to_server:
                        if self.server_last_seq < segment.get_th_seq():
                            self.server_last_seq = segment.get_th_seq()
                            self.server_buffer.append((segment.get_th_seq(), segment.get_th_ack(), segment.get_data_as_string()))
                            # print(segment.get_data_as_string())
                            return
                        else:
                            # print(8)
                            for i in range(0, len(self.server_buffer)):  # check for retransmission
                                segment_tuple = self.server_buffer[i]
                                if segment_tuple[0] == segment.get_th_seq() and segment_tuple[1] == segment.get_th_ack() and len(segment_tuple[2]) == len(segment.get_data_as_string()): # a retransmitted packet
                                    # print("retransmitted")
                                    # print(segment_tuple, segment.get_th_seq(), segment.get_th_ack(), len(segment.get_data_as_string()))
                                    return

                            for i in range(0, len(self.server_buffer)):  # check for out of order
                                segment_tuple = self.server_buffer[i]
                                if segment_tuple[0] < segment.get_th_seq():  # an out of order packet
                                    self.server_buffer.insert(i, (segment.get_th_seq(), segment.get_th_ack(), segment.get_data_as_string()))
                                    # print(2)
                                    return

                    else:
                        # print(7)
                        if self.client_last_seq < segment.get_th_seq():
                            self.client_last_seq = segment.get_th_seq()
                            self.client_buffer.append((segment.get_th_seq(), segment.get_th_ack(), segment.get_data_as_string()))
                            # print(segment.get_data_as_string())
                            # print(3)
                            return
                        else:
                            # print(9)
                            for i in range(0, len(self.client_buffer)):  # check for retransmission
                                segment_tuple = self.client_buffer[i]
                                if segment_tuple[0] == segment.get_th_seq() and segment_tuple[1] == segment.get_th_ack() and len(segment_tuple[2]) == len(segment.get_data_as_string()): # a retransmitted packet
                                    # print("retransmitted")
                                    # print(segment_tuple, segment.get_th_seq(), segment.get_th_ack(), len(segment.get_data_as_string()))
                                    return

                            for i in range(0, len(self.client_buffer)):  # check for out of order
                                segment_tuple = self.client_buffer[i]
                                if segment_tuple[0] < segment.get_th_seq(): # an out of order packet
                                    self.client_buffer.insert(i, (segment.get_th_seq(), segment.get_th_ack(), segment.get_data_as_string()))
                                    # print(4)
                                    return

    def finish(self):
        for segment_tuple in self.server_buffer:
            self.server_data += segment_tuple[2]

        del self.server_buffer

        for segment_tuple in self.client_buffer:
            self.client_data += segment_tuple[2]

        del self.client_buffer
        self.ready = True

        self.client_data_len = len(self.client_data)
        self.server_data_len = len(self.server_data)
        self.client_bf = __calculate_byte_frequency__(self.client_data, self.client_data_len)
        self.server_bf = __calculate_byte_frequency__(self.server_data, self.server_data_len)

    def get_payload(self, dest):
        if dest == "client":
            return self.client_data
        elif dest == "server":
            return self.server_data

    def get_hexlify_payload(self, dest):
        payload = self.get_payload(dest)
        return binascii.hexlify(payload)

    def get_byte_frequency(self, dest):
        if dest == "client":
            return self.client_bf
        elif dest == "server":
            return self.server_bf

    def get_payload_length(self, dest):
        if dest == "client":
            return self.client_data_len
        elif dest == "server":
            return self.server_data_len

    def get_start_time(self):
        return self.start_time

    def get_stop_time(self):
        return self.stop_time
