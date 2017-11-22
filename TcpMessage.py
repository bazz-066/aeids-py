#!/usr/bin/python

class TcpMessage():
    def __init__(self, client_data, server_data, tcp_tuple):
        self.client_data = client_data
        # self.server_data = server_data
        self.tcp_tuple = tcp_tuple
        self.read = False
        self.client_data_len = len(client_data)
        # self.server_data_len = len(server_data)
        self.client_bf = self.__calculate_byte_frequency(self.client_data, self.client_data_len)
        # self.server_bf = self.__calculate_byte_frequency(self.server_data, self.server_data_len)

    def get_payload(self, source):
        if source == "client":
            return self.client_data
        # elif source == "server":
        #    return self.server_data

    def __calculate_byte_frequency(self, payload, length):
        byte_frequency = [0] * 256

        if length > 0:
            for i in range(0, 256):
                byte_frequency[i] = float(payload.count(chr(i))) / length

        return byte_frequency

    def get_byte_frequency(self, source):
        if source == "client":
            return self.client_bf
        # elif source == "server":
        #    return self.server_bf

    def get_payload_length(self, source):
        if source == "client":
            return self.client_data_len
        # elif source == "server":
        #    return self.server_data_len