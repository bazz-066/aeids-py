class TcpMessage():
    def __init__(self, client_data, server_data, tcp_tuple):
        self.client_data = client_data
        self.server_data = server_data
        self.tcp_tuple = tcp_tuple
        self.read = False

    def get_payload(self, source):
        if source == "client":
            return self.client_data
        elif source == "server":
            return self.server_data

    def get_byte_frequency(self, source):
        byte_frequency = [0] * 256
        payload = self.get_payload(source)
        length = float(self.get_payload_length(source))

        for i in range(0, 256):
            byte_frequency[i] = float(payload.count(chr(i))) / length

        return byte_frequency

    def get_payload_length(self, source):
        payload = self.get_payload(source)
        return len(payload)