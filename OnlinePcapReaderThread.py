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
        self.done = False
        self.port = port
        self.protocol = protocol

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
            self.clean_no_payload()

        for buffered_packets in self.connection_list:
            if not buffered_packets.ready:
                buffered_packets.ready = True

        #self.clean_no_payload()

        print "Num of connections : " + str(len(self.connection_list))
        self.done = True

    def clean_no_payload(self):
        for i in range(len(self.connection_list) - 1, -1, -1):
            #print "i: " + str(i)
            #print "len: " + str(len(self.connection_list))
            if len(self.connection_list) == 0:
                break
            if self.connection_list[i].get_payload_length() == 0 and self.connection_list[i].ready:
                del self.connection_list[i]

    def parse_packet(self, header, frame):
        decoder = ImpactDecoder.LinuxSLLDecoder()
        ether = decoder.decode(frame)

        if ether.get_ether_type() == ImpactPacket.IP.ethertype:
            for buffered_packets in self.connection_list:
                if buffered_packets.add_frame(ether): #if there's an existing flow
                    return

            buffered_packets = BufferedPackets(ether)
            self.connection_list.append(buffered_packets)
            #print buffered_packets.get_payload()

    def has_ready_message(self):
        for buffered_packets in self.connection_list:
            if buffered_packets.ready and not buffered_packets.read:
                return True

        return False

    def has_unread_message(self):
        if len(self.connection_list) == 0:
            return True

        for buffered_packets in self.connection_list:
            if not buffered_packets.read:
                return True

        return False

    def pop_connection(self):
        removed_id = None

        for id in range(0, len(self.connection_list)):
            if self.connection_list[id].ready and not self.connection_list[id].read:
                bp = self.connection_list[id]
                # del self.connection_list[id]
                bp.read = True
                return bp

        return None

    def reset_read_status(self):
        for buffered_packets in self.connection_list:
            buffered_packets.read = False

    def forced_pop_connection(self):
        bp = self.connection_list[0]
        del self.connection_list[0]
        return bp