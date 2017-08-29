from BufferedPackets import BufferedPackets
from impacket import ImpactDecoder, ImpactPacket

import pcapy
import threading


class OnlinePcapReaderThread(threading.Thread):
    def __init__(self, protocol, port):
        threading.Thread.__init__(self)

        snaplen = 65535
        promiscious = False
        read_timeout = 0

        self.pcap = pcapy.open_live("any", snaplen, promiscious, read_timeout)
        self.connection_list = []
        self.ready_connection_list = []
        self.last_read_index = -1
        self.done = False
        self.port = port
        self.protocol = protocol
        self.lock = threading.Lock()
        self.delete_read_connections = False

        print "{} dst port {}".format(self.protocol, self.port)
        self.pcap.setfilter("{} dst port {}".format(self.protocol, self.port))
        #self.pcap.setfilter("{}".format(self.protocol))

    def run(self):
        #for i in range (0, 1000):
        while not self.done:
            (header, frame) = self.pcap.next()
            if not header:
                break

            self.parse_packet(header, frame)
            #self.clean_no_payload()

        ready_indices = range(0, len(self.connection_list))
        self.move_ready_packets(ready_indices)

        #self.clean_no_payload()

        print "Num of connections : " + str(len(self.connection_list))
        self.done = True

    def clean_no_payload(self):
        try:
            self.lock.acquire()
            for i in range(len(self.connection_list) - 1, -1, -1):
                if len(self.connection_list) == 0:
                    break
                if self.connection_list[i].get_payload_length() == 0 and self.connection_list[i].ready:
                    del self.connection_list[i]
        finally:
            self.lock.release()

    def parse_packet(self, header, frame):
        decoder = ImpactDecoder.LinuxSLLDecoder()
        ether = decoder.decode(frame)

        ready_indices = []

        if ether.get_ether_type() == ImpactPacket.IP.ethertype:
            self.lock.acquire()
            for i in range(0, len(self.connection_list)):
                buffered_packets = self.connection_list[i]
                if buffered_packets.add_frame(ether): #if there's an existing flow
                    self.lock.release()
                    if len(ready_indices) > 0:
                        self.move_ready_packets(ready_indices)
                    return

                if buffered_packets.ready:
                    ready_indices.append(i)

            buffered_packets = BufferedPackets(ether)
            self.connection_list.append(buffered_packets)
            self.lock.release()
            if len(ready_indices) > 0:
                self.move_ready_packets(ready_indices)

    def move_ready_packets(self, ready_indices):
        self.lock.acquire()

        for i in range(len(ready_indices)-1, -1, -1):
            if self.connection_list[i].get_payload_length() > 0:
                self.ready_connection_list.append(self.connection_list[i])
            del self.connection_list[i]

        self.lock.release()

    def has_ready_message(self):
        self.lock.acquire()

        if not self.delete_read_connections:
            if len(self.ready_connection_list)-1 == self.last_read_index:
                self.lock.release()
                return False
            else:
                self.lock.release()
                return True
        else:
            if len(self.ready_connection_list) > 0:
                self.lock.release()
                return True
            else:
                self.lock.release()
                return False

    def has_unread_message(self):
        self.lock.acquire()
        if len(self.ready_connection_list) > 0:
            for buffered_packets in self.connection_list:
                if not buffered_packets.read:
                    self.lock.release()
                    return True

        self.lock.release()
        return False

    def pop_connection(self):
        self.lock.acquire()
        # for id in range(0, len(self.connection_list)):
        #     if self.connection_list[id].ready and not self.connection_list[id].read:
        #         bp = self.connection_list[id]
        #         # del self.connection_list[id]
        #         bp.read = True
        #         self.lock.release()
        #         return bp

        if not self.delete_read_connections:
            if len(self.ready_connection_list)-1 == self.last_read_index:
                self.lock.release()
                return None
            else:
                self.last_read_index += 1
                buffered_packets = self.ready_connection_list[self.last_read_index]
                buffered_packets.read = True
                self.lock.release()
                return buffered_packets
        else:
            if len(self.ready_connection_list) <= 0:
                self.lock.release()
                return None
            else:
                buffered_packets = self.ready_connection_list[0]
                del self.ready_connection_list[0]
                self.lock.release()
                return buffered_packets

    def reset_read_status(self):
        for buffered_packets in self.connection_list:
            buffered_packets.read = False

    def forced_pop_connection(self):
        bp = self.connection_list[0]
        del self.connection_list[0]
        return bp