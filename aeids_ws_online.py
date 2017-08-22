from BufferedPackets import BufferedPackets
from OnlinePcapReaderThread import OnlinePcapReaderThread
from BaseHTTPServer import BaseHTTPRequestHandler
from aeids import load_mean_stdev, load_autoencoder, decide

import binascii
import json
import numpy
import sys
import web


counter = 1
prt = None
protocol = "tcp"
port = "80"
autoencoder = None
mean = 0
stdev = 0
counter = 0


class AeidsWSOnline():
    def __init__(self):
        urls = (
            '/next', 'GetMessage',
            '/reset', 'ResetReader'
        )
        self.app = web.application(urls, globals())
        global prt
        global protocol
        global port
        global autoencoder
        global mean
        global stdev

        autoencoder = load_autoencoder(protocol, port)
        (mean, stdev) = load_mean_stdev(protocol, port)

    def run(self):
        self.app.run()


class GetMessage:
    def GET(self):
        global autoencoder
        global mean
        global stdev
        global counter

        msg = {}
        #web.header("Access-Control-Allow-Origin", "http://localhost:63342")
        global prt
        if prt.done and not prt.has_ready_message():
            msg['error'] = "No more message"
            print "Connections : " + str(counter)
            return json.dumps(msg)
        elif not prt.done and not prt.has_ready_message():
            msg['error'] = "Waiting for data"
            return json.dumps(msg)
        else:
            buffered_packets = prt.pop_connection()
            if buffered_packets is None:
                msg['error'] = "BP is none"
                return json.dumps(msg)
            else:
                byte_frequency = buffered_packets.get_byte_frequency()
                input_bf_json = []
                output_bf_json = []
                payload_hex = binascii.hexlify(buffered_packets.get_payload())
                msg['payload'] = payload_hex
                for i in range(0, 256):
                    input_bf_json.append({'Letter' : i, 'Freq' : byte_frequency[i]})

                data_x = numpy.reshape(byte_frequency, (1, 256))
                decoded_x = autoencoder.predict(data_x)
                error = numpy.sqrt(numpy.mean((decoded_x - data_x) ** 2, axis=1))

                decision = decide(error[0], mean, stdev)
                threshold = float(mean) + 2 * float(stdev)
                status = []
                status.append({'Letter': 'Threshold', 'Freq': threshold})
                status.append({'Letter': 'MSE', 'Freq': error[0]})
                #decoded_x = numpy.reshape(decoded_x, (256))

                for i in range(0, 256):
                    output_bf_json.append({'Letter': i, 'Freq': float(decoded_x[0][i])})

                msg["input"] = input_bf_json
                msg["output"] = output_bf_json
                msg["decision"] = decision
                msg["status"] = status

                counter += 1
                return json.dumps(msg)


class ResetReader:
    def GET(self):
        global prt
        global protocol
        global port

        web.header("Access-Control-Allow-Origin", "http://localhost:63342")

        if not prt.done:
            prt.done = True

        prt = OnlinePcapReaderThread(protocol, port)
        prt.start()

        msg = {}
        msg['status'] = "Resetting PCAP reader..."
        return json.dumps(msg)


def main(argv):
    try:
        global prt
        global protocol
        global port
        prt = OnlinePcapReaderThread(protocol, port)
        prt.start()

        aeids_ws_online = AeidsWSOnline()
        aeids_ws_online.run()
    except IndexError:
        print "Usage : python aeids_ws.py"
    except KeyboardInterrupt:
        prt.done = True
        print "Service stopped ..."


if __name__ == '__main__':
    main(sys.argv)




