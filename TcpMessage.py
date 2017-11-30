#!/usr/bin/python
import binascii

class TcpMessage():
    def __init__(self, client_data, server_data, tcp_tuple, start_ts, stop_ts):
        self.client_data = client_data
        self.server_data = server_data
        self.tcp_tuple = tcp_tuple
        self.read = False
        self.client_data_len = len(client_data)
        self.server_data_len = len(server_data)
        self.client_bf = self.__calculate_byte_frequency(self.client_data, self.client_data_len)
        self.server_bf = self.__calculate_byte_frequency(self.server_data, self.server_data_len)
        self.id = "{}-{}-{}-{}-tcp".format(self.tcp_tuple[0], self.tcp_tuple[1], self.tcp_tuple[2], self.tcp_tuple[3])
        self.start_ts = start_ts
        self.stop_ts = stop_ts

    def get_payload(self, dest):
        if dest == "client":
            return self.client_data
        elif dest == "server":
           return self.server_data

    def get_hexlify_payload(self, dest):
        payload = self.get_payload(dest)
        return binascii.hexlify(payload)

    def __calculate_byte_frequency(self, payload, length):
        byte_frequency = [0] * 256

        if length > 0:
            for i in range(0, 256):
                byte_frequency[i] = float(payload.count(chr(i))) / length

        return byte_frequency

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
        return self.start_ts

    def get_stop_time(self):
        return self.stop_ts