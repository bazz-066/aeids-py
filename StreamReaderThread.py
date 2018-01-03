# There's bug when an ACK packet is read after FIN has received. The new packet is considered to be part of a new stream not the existing one.

from TcpStream import *
from impacket import ImpactDecoder, ImpactPacket

import pcapy
import threading


TIMEOUT = 10
end_states = (STATE_CLOSE, STATE_RESET, STATE_TIMEOUT)


class StreamReaderThread(threading.Thread):
    def __init__(self, filename, protocol, port):
        threading.Thread.__init__(self)
        self.pcap = pcapy.open_offline(filename)
        self.tcp_buffer = {}
        self.ready_tcp_buffer = []
        self.last_read_index = -1
        self.done = False
        self.port = port
        self.protocol = protocol
        self.lock = threading.Lock()
        self.condition_lock = threading.Condition()
        self.delete_read_connections = False
        self.last_timestamp = -1
        self.buffer_watcher = BufferWatcher(self)
        self.packet_counter = 0

        print "{} dst port {}".format(self.protocol, self.port)
        self.pcap.setfilter("{} port {}".format(self.protocol, self.port))

    def run(self):
        # self.buffer_watcher.start()

        while not self.done:
            (header, frame) = self.pcap.next()
            if not header:
                break

            self.parse_packet(header, frame)

        # self.buffer_watcher.done = True
        self.buffer_watcher.empty_buffer()
        print "waiting for all threads to finish"
        while len(self.tcp_buffer) > 0:
            time.sleep(0.0001)
        print "main loop finished"
        self.done = True

    def parse_packet(self, header, frame):
        # TODO: automatically check what the underlying decoder is
        decoder = ImpactDecoder.EthDecoder()
        # decoder = ImpactDecoder.LinuxSLLDecoder()
        ether = decoder.decode(frame)
        ts = float(str(header.getts()[0]) + "." + str(header.getts()[1]))
        self.last_timestamp = ts

        if ether.get_ether_type() == ImpactPacket.IP.ethertype:
            (id, tcp_tuple) = generate_id(ether)
            if id == False:
                return

            (rev_id, tcp_tuple) = generate_reverse_id(ether)

            # print("Buffer", self.tcp_buffer)
            # print(threading.current_thread().name + "in",)
            self.lock.acquire()
            # print(threading.current_thread().name + "out")
            if id in self.tcp_buffer:
                tcp_stream = self.tcp_buffer[id]
                to_server = True
                # print("[fwd] ID: " + id + ";" + str(ts))
            elif rev_id in self.tcp_buffer:
                tcp_stream = self.tcp_buffer[rev_id]
                to_server = False
                # print("[rev] ID: " + id + ";" + str(ts))
            else:
                # a new stream has appeared
                tcp_stream = TcpStream(id, ts, self)
                self.tcp_buffer[id] = tcp_stream
                to_server = True
                packet = ether.child()
                segment = packet.child()
                tcp_stream.start()
                # print("[new] ID: " + id + ";" + str(ts))

            tcp_stream.add_packet(ts, to_server, ether)
            # if tcp_stream.state in end_states:
            #     tcp_stream.finish()
            #     self.move_stream(tcp_stream.id)

            self.packet_counter += 1
            self.lock.release()
            # print(threading.current_thread().name + "out2")

    def move_stream(self, id):
        # print("[del] ID: " + id + ";" + str(self.tcp_buffer[id].client_data_len) + ";" + str(self.tcp_buffer[id].server_data_len))
        self.lock.acquire()
        if self.tcp_buffer[id].client_data_len > 0 or self.tcp_buffer[id].server_data_len > 0:
            self.ready_tcp_buffer.append(self.tcp_buffer[id])
        # else:
        #     print("------------------------------")
        #     print(self.tcp_buffer[id].get_hexlify_payload("server"))
        #     print(self.tcp_buffer[id].get_hexlify_payload("client"))
        #     print("------------------------------")
        del(self.tcp_buffer[id])
        self.lock.release()
        self.condition_lock.acquire()
        # print("notify")
        self.condition_lock.notify()
        # print("done notifying")
        self.condition_lock.release()

    def has_ready_message(self):
        # self.lock.acquire()

        if not self.delete_read_connections:
            if len(self.ready_tcp_buffer)-1 == self.last_read_index:
                # self.lock.release()
                return False
            else:
                # self.lock.release()
                return True
        else:
            if len(self.ready_tcp_buffer) > 0:
                # self.lock.release()
                return True
            else:
                # self.lock.release()
                return False

    def pop_connection(self):
        # print(threading.current_thread().name + "pop in")
        self.lock.acquire()

        if not self.delete_read_connections:
            if len(self.ready_tcp_buffer)-1 == self.last_read_index:
                self.lock.release()
                # print(threading.current_thread().name + "pop out1")
                return None
            else:
                self.last_read_index += 1
                tcp_stream = self.ready_tcp_buffer[self.last_read_index]
                tcp_stream.read = True
                self.lock.release()
                # print(threading.current_thread().name + "pop out2")
                return tcp_stream
        else:
            if len(self.ready_tcp_buffer) <= 0:
                self.lock.release()
                # print(threading.current_thread().name + "pop out3")
                return None
            else:
                tcp_stream = self.ready_tcp_buffer[0]
                del self.ready_tcp_buffer[0]
                self.lock.release()
                # print(threading.current_thread().name + "pop out4")
                return tcp_stream

    def wait_for_data(self):
        self.condition_lock.acquire()
        # print("wait")
        self.condition_lock.wait(0.1)
        # print("notified")
        self.condition_lock.release()

    def reset_read_status(self):
        self.lock.acquire()
        # print "Resetting read status"
        for tcp_stream in self.ready_tcp_buffer:
            tcp_stream.read = False

        self.last_read_index = -1
        self.lock.release()

    def forced_pop_connection(self):
        bp = self.ready_tcp_buffer[0]
        del self.ready_tcp_buffer[0]
        return bp

    def is_timeout(self, stream_last_ts):
        # self.lock.acquire()
        if self.last_timestamp - stream_last_ts  > TIMEOUT:
            # self.lock.release()
            return True
        else:
            # self.lock.release()
            return False

    def acquire_lock(self, caller):
        print(caller + "-try")
        self.lock.acquire()
        print(caller + "-get")

    def release_lock(self, caller):
        print(caller + "-out")
        self.lock.release()
        print(caller + "-bye")



class BufferWatcher(threading.Thread):
    def __init__(self, srt):
        threading.Thread.__init__(self)
        self.srt = srt
        self.done = False

    def run(self):
        while not self.done:
            self.cleanup_buffer()

    def cleanup_buffer(self):
        ready_indices = []
        # print(self.srt.tcp_buffer)
        self.srt.lock.acquire()
        for id, stream in self.srt.tcp_buffer.iteritems():
            # print("{}: time: {} - {} = {}".format(id, self.srt.last_timestamp, stream.last_packet_time, self.srt.last_timestamp - stream.last_packet_time))
            if self.srt.last_timestamp - stream.last_packet_time > TIMEOUT and stream.state not in end_states:
                # mark stream as timeout
                # print("TIMEOUT", stream.state, stream.id)
                # print(self.srt.tcp_buffer)
                stream.state = STATE_TIMEOUT
                # print(stream.id)

            if stream.state in end_states:
                stream.finish()
                # print("move:" + stream.id)
                ready_indices.append(stream.id)

        for id in ready_indices:
            self.srt.move_stream(id)

        self.srt.lock.release()

    def empty_buffer(self):
        ready_indices = []

        self.srt.lock.acquire()
        for id, stream in self.srt.tcp_buffer.iteritems():
            stream.state = STATE_TIMEOUT
            # stream.finish()
            # ready_indices.append(id)
        self.srt.lock.release()

        # for id in ready_indices:
        #    self.srt.move_stream(id)
