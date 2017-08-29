from BufferedPackets import BufferedPackets
from keras.callbacks import TensorBoard
from keras.models import load_model
from keras.models import Model
from keras.layers import Dense, Input, Dropout
from keras.models import model_from_json
from PcapReaderThread import PcapReaderThread
from tensorflow import Tensor

import binascii
import math
import numpy
import sys
import thread
import time
import traceback

import csv

# def main(argv):
#     try:
#         root_directory = "/home/baskoro/Documents/Dataset/ISCX12/without retransmission/"
#         filename = root_directory + sys.argv[1]
#         prt = PcapReaderThread(filename)
#         prt.run()
#
#         while not prt.done:
#             print "sleeping"
#             time.sleep(1)
#
#         while prt.has_ready_message():
#             bp = prt.pop_connection()
#             print bp.get_payload()
#
#         print "DIE YOU!!!"
#
#     except IndexError:
#         print "Usage : python aeids.py filename [training|testing]"
#     except KeyboardInterrupt:
#         print "Good bye to you my trusted friend"
root_directory = "/home/baskoro/Documents/Dataset/ISCX12/without retransmission/"
# root_directory = "/home/baskoro/Documents/Dataset/HTTP-Attack-Dataset/morphed-shellcode-attacks/"
# root_directory = "/home/baskoro/Documents/Dataset/HTTP-Attack-Dataset/shellcode-attacks/"
tensorboard_log_enabled = False
backend = "tensorflow"
done = False
prt = None

# possible values: mean, median, zscore
threshold = "median"


def main(argv):
    try:
        filename = argv[2]
        protocol = argv[3]
        port = argv[4]

        if argv[1] == "training":
            numpy.random.seed(666)

            autoencoder = init_model()

            if tensorboard_log_enabled and backend == "tensorflow":
                tensorboard_callback = TensorBoard(log_dir="./logs", batch_size=10000, write_graph=True, write_grads=True, histogram_freq=1)
                autoencoder.fit_generator(byte_freq_generator(filename, protocol, port), steps_per_epoch=100,
                                          epochs=100, verbose=1, callbacks=[tensorboard_callback])
                autoencoder.save("models/aeids-with-log-{}.hdf5".format(protocol + port), overwrite=True)
            else:
                autoencoder.fit_generator(byte_freq_generator(filename, protocol, port), steps_per_epoch=10000,
                                          epochs=10, verbose=1)
                autoencoder.save("models/aeids-{}.hdf5".format(protocol + port), overwrite=True)

            print "Training autoencoder finished. Calculating threshold..."
            predict_byte_freq_generator(autoencoder, filename, protocol, port, argv[1])
            done = True
            print "\nFinished."
        elif argv[1] == "testing":
            autoencoder = load_autoencoder(protocol, port)
            predict_byte_freq_generator(autoencoder, filename, protocol, port, argv[1])
            print "\nFinished."
        else:
            raise IndexError
    except IndexError as e:
        print "Usage : python aeids.py [training|testing] filename [tcp|udp] port"
        print traceback.print_exc()
        exit(0)
    except KeyboardInterrupt:
        print "Interrupted"
        if prt is not None:
            prt.done = True
    except BaseException as e:
        print traceback.print_exc()
        if prt is not None:
            prt.done = True


def init_model():
    input_dimension = 256
    hidden_dimension = [200, 100]
    input = Input(shape=(input_dimension,))
    encoded = Dense(hidden_dimension[0], activation="relu")(input)
    encoded = Dropout(0.2)(encoded)
    encoded = Dense(hidden_dimension[1], activation="relu")(encoded)
    encoded = Dropout(0.2)(encoded)
    decoded = Dense(hidden_dimension[0], activation="relu")(encoded)
    decoded = Dropout(0.2)(decoded)
    decoded = Dense(input_dimension, activation="sigmoid")(decoded)
    # autoencoder = Model(input=input, output=decoded)
    autoencoder = Model(outputs=decoded, inputs=input)

    autoencoder.compile(loss="binary_crossentropy", optimizer="adadelta")
    return autoencoder


def load_autoencoder(protocol, port):
    autoencoder = load_model("models/aeids-{}.hdf5".format(protocol + port))
    return autoencoder


def byte_freq_generator(filename, protocol, port):
    global prt
    prt = PcapReaderThread(root_directory + filename, protocol, port)
    prt.start()

    while not done:
        while not prt.done or prt.has_ready_message():
            if not prt.has_ready_message():
                time.sleep(0.0001)
                print "waiting"
                continue
            else:
                buffered_packets = prt.pop_connection()
                if buffered_packets is None:
                    time.sleep(0.0001)
                    print "waiting none"
                    continue
                if buffered_packets.get_payload_length() > 0:
                    byte_frequency = buffered_packets.get_byte_frequency()
                    dataX = numpy.reshape(byte_frequency, (1, 256))
                    yield dataX, dataX

        prt.reset_read_status()


def predict_byte_freq_generator(autoencoder, filename, protocol, port, state="training"):
    global prt
    global threshold

    if prt is None:
        prt = PcapReaderThread(root_directory + filename, protocol, port)
        prt.start()
    else:
        prt.reset_read_status()
        prt.delete_read_connections = True

    errors_list = []
    counter = 0
    print "predict"

    if state == "testing":
        t1, t2 = load_threshold(protocol, port, threshold)
        fresult = open("results/result-{}{}{}.csv".format(filename, protocol, port), "w")

    # ftemp = open("results/data.txt", "wb")
    # fcsv = open("results/data.csv", "wb")
    # a = csv.writer(fcsv, quoting=csv.QUOTE_ALL)
    # time.sleep(2)
    i_counter = 0
    # for i in range(0,10):
    while not prt.done or prt.has_ready_message():
        if not prt.has_ready_message():
            time.sleep(0.0001)
        else:
            buffered_packets = prt.pop_connection()
            if buffered_packets is None:
                continue
            if buffered_packets.get_payload_length() == 0:
                continue

            i_counter += 1
            #print "{}-{}: {}".format(i_counter, buffered_packets.id, buffered_packets.get_payload()[:100])
            byte_frequency = buffered_packets.get_byte_frequency()
            # ftemp.write(buffered_packets.get_payload())
            # a.writerow(byte_frequency)
            data_x = numpy.reshape(byte_frequency, (1, 256))
            decoded_x = autoencoder.predict(data_x)
            # a.writerow(decoded_x[0])

            # fcsv.close()
            error = numpy.mean((decoded_x - data_x) ** 2, axis=1)
            # ftemp.write("\r\n\r\n{}".format(error))
            # ftemp.close()
            if state == "training":
                errors_list.append(error)
            elif state == "testing":
                decision = decide(error[0], threshold, t1, t2)
                fresult.write("{},{},{}\n".format(buffered_packets.id, error[0], decision))

            counter += 1
            sys.stdout.write("\rCalculated {} connections.".format(counter))
            sys.stdout.flush()

    errors_list = numpy.reshape(errors_list, (1, len(errors_list)))
    if state == "training":
        if threshold == "mean":
            mean = numpy.mean(errors_list)
            stdev = numpy.std(errors_list)
            save_mean_stdev(protocol, port, mean, stdev)
        elif threshold == "median":
            save_q3_iqr(protocol, port, errors_list)
        elif threshold == "zscore":
            save_median_mad(protocol, port, errors_list)
    elif state == "testing":
        fresult.close()


def save_mean_stdev(protocol, port, mean, stdev):
    fmean = open("models/mean-{}{}.txt".format(protocol, port), "w")
    fmean.write("{},{}".format(mean, stdev))
    fmean.close()


def save_q3_iqr(protocol, port, errors_list):
    qs = numpy.percentile(errors_list, [100, 75, 50, 25, 0])
    iqr = qs[1] - qs[3]
    MC = ((qs[0]-qs[2])-(qs[2]-qs[4]))/(qs[0]-qs[4])
    if MC >= 0:
        constant = 3
    else:
        constant = 4
    iqrplusMC = 1.5 * math.pow(math.e, constant * MC) * iqr
    print "IQR: {}\nMC: {}\nConstant: {}".format(iqr, MC, constant)
    fmean = open("models/median-{}{}.txt".format(protocol, port), "w")
    fmean.write("{},{}".format(qs[2], iqrplusMC))
    fmean.close()


def save_median_mad(protocol, port, errors_list):
    median = numpy.median(errors_list)
    mad = numpy.median([numpy.abs(error - median) for error in errors_list])

    fmean = open("models/mad-{}{}.txt".format(protocol, port), "w")
    fmean.write("{},{}".format(median, mad))
    fmean.close()


def load_threshold(protocol, port, threshold):
    if threshold == "mean":
        fmean = open("models/mean-{}{}.txt".format(protocol, port), "r")
    elif threshold == "median":
        fmean = open("models/median-{}{}.txt".format(protocol, port), "r")
    elif threshold == "zscore":
        fmean = open("models/mad-{}{}.txt".format(protocol, port), "r")
    line = fmean.readline()
    split = line.split(",")
    fmean.close()
    return split[0], split[1]


def get_threshold(threshold_method, t1, t2):
    if threshold_method == "mean":
        return (float(t1) + 2 * float(t2))
    elif threshold_method == "median":
        return (float(t1) + float(t2))
    elif threshold_method == "zscore":
        return 3.5


def decide(mse, threshold_method, t1, t2):
    if threshold_method == "mean":
        if mse > (float(t1) + 2 * float(t2)):
            return 1
        else:
            return 0
    elif threshold_method == "median":
        if mse > (float(t1) + float(t2)):
            return 1
        else:
            return 0
    elif threshold_method == "zscore":
        zscore = 0.6745 * (mse - float(t1)) / float(t2)
        if zscore > 3.5:
            return 1
        else:
            return 0


if __name__ == '__main__':
	main(sys.argv)
