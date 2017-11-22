from LibNidsReaderThread import LibNidsReaderThread
from TcpMessage import TcpMessage

import sys


def main(argv):
    try:
        filename = argv[1]
        protocol = "tcp"
        prt = LibNidsReaderThread(filename, protocol)
        prt.start()
        fcsv = open("csv/test.csv", "w")
        counter = 0

        while not prt.done or prt.has_ready_message():
            buffered_packets = prt.pop_connection()
            if buffered_packets is not None:
                #print(buffered_packets.get_byte_frequency("client"))
                counter += 1
                byte_frequency = ",".join(str(buffered_packets.get_byte_frequency("client")))
                fcsv.write("{},{},{},{},{}\n".format(buffered_packets.tcp_tuple[0], buffered_packets.tcp_tuple[1], buffered_packets.tcp_tuple[2], buffered_packets.tcp_tuple[3], byte_frequency))
                sys.stdout.write("\r{} flows.".format(counter))
                sys.stdout.flush()

        fcsv.close()

    except IndexError:
        print("Usage: python pcap_to_csv.py <pcap_filename>")


if __name__ == '__main__':
	main(sys.argv)