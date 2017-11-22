from collections import deque
from TcpMessage import TcpMessage

import nids
import threading

end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)


class LibNidsReaderThread(threading.Thread):
    def __init__(self, filename, protocol, port):
        threading.Thread.__init__(self)

        self.port = port
        self.protocol = protocol
        self.done = False
        self.connection_list = deque()
        self.lock = threading.Lock()
        self.delete_read_connections = False
        self.last_read_index = -1

        nids.param("filename", filename)
        nids.chksum_ctl([('0.0.0.0/0', False)])
        nids.param("pcap_filter", "{} port {}".format(self.protocol, self.port))

    def run(self):
        nids.init()
        nids.register_tcp(self.handle_tcp)

        try:
            nids.run()
            print("DONE")
            self.done = True
        except nids.error, e:
            print "[-] Error: %s" % (e)
        except Exception, e:
            print "[-] Exception: %s" % (e)

    def handle_tcp(self, tcp):
        if tcp.nids_state == nids.NIDS_JUST_EST:
            ((src, sport), (dst, dport)) = tcp.addr
            tcp.client.collect = 1
            tcp.server.collect = 1

        elif tcp.nids_state == nids.NIDS_DATA:
            tcp.discard(0)

        elif tcp.nids_state in end_states:
            ((src, sport), (dst, dport)) = tcp.addr
            # print "[+] %s:%s - %s:%s (CTS: %dB | STC: %dB)" % (src, sport, dst, dport,
            #                                                    len(tcp.server.data[:tcp.server.count]),
            #                                                    len(tcp.client.data[:tcp.client.count]))

            msg = TcpMessage(tcp.client.data, tcp.server.data, (src, sport, dst, dport))
            self.lock.acquire()
            self.connection_list.append(msg)
            self.lock.release()

    def pop_connection(self):
        self.lock.acquire()

        if self.delete_read_connections and len(self.connection_list) > 0:
            msg = self.connection_list.pop()
            self.lock.release()
            return msg
        elif len(self.connection_list) > 0:
            if self.last_read_index == len(self.connection_list) - 1:
                self.lock.release()
                return None
            else:
                self.last_read_index += 1
                msg = self.connection_list[self.last_read_index]
                msg.read = True
                self.lock.release()
                return msg
        else:
            self.lock.release()
            return None

    def has_ready_message(self):
        self.lock.acquire()

        if self.delete_read_connections and len(self.connection_list) > 0:
            self.lock.release()
            return True
        elif len(self.connection_list) > 0:
            if self.last_read_index >= len(self.connection_list) - 1:
                self.lock.release()
                return False
            else:
                self.lock.release()
                return True
        else:
            self.lock.release()
            return False

    def reset_read_status(self):
        self.lock.acquire()
        print "Resetting read status"
        for msg in self.connection_list:
            msg.read = False

        self.last_read_index = -1
        self.lock.release()
