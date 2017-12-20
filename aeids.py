from BufferedPackets import WINDOW_SIZE
from keras.callbacks import TensorBoard
from keras.models import load_model
from keras.models import Model
from keras.layers import Dense, Input, Dropout
from keras.models import model_from_json
# from LibNidsReaderThread import LibNidsReaderThread
# from PcapReaderThread import PcapReaderThread
from StreamReaderThread import StreamReaderThread
from tensorflow import Tensor

import binascii
import math
import numpy
import os
import psycopg2
import psycopg2.extras
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
# root_directory = "/home/baskoro/Documents/Dataset/ISCX12/without retransmission/"
# root_directory = "/home/baskoro/Documents/Dataset/HTTP-Attack-Dataset/morphed-shellcode-attacks/"
# root_directory = "/home/baskoro/Documents/Dataset/HTTP-Attack-Dataset/shellcode-attacks/"
tensorboard_log_enabled = False
backend = "tensorflow"
done = False
prt = None
conf = {}
activation_functions = ["elu", "selu", "softplus", "softsign", "relu", "tanh", "sigmoid", "hard_sigmoid", "linear", "softmax"]
conn = None

# possible values: mean, median, zscore
threshold = "median"


def main(argv):
    try:
        # validate command line arguments
        if sys.argv[1] != "training" and sys.argv[1] != "predicting" and sys.argv[1] != "testing" and sys.argv[1] != "counting":
            raise IndexError("Phase {} does not exist.".format(sys.argv[1]))
        else:
            phase = sys.argv[1]

        if sys.argv[2] != "tcp" and sys.argv[2] != "udp":
            raise IndexError("Protocol {} is not supported.".format(sys.argv[3]))
        else:
            protocol = sys.argv[2]

        if not sys.argv[3].isdigit():
            raise IndexError("Port must be numeric.")
        else:
            port = sys.argv[3]

        # must be in form of comma separated, representing half of the layers (e.g. 200,100 means there are 3 layers,
        # with 200, 100, and 200 neurons respectively)
        if phase != "counting":
            try:
                hidden_layers = sys.argv[4].split(",")
                for neurons in hidden_layers:
                    if not neurons.isdigit():
                        raise IndexError("Hidden layers must be comma separated numeric values")
            except ValueError:
                raise IndexError("Hidden layers must be comma separated numeric values")

            if sys.argv[5] not in activation_functions:
                raise IndexError("Activation function must be one of the following list")
            else:
                activation_function = sys.argv[5]

            try:
                dropout = float(sys.argv[6])
            except ValueError:
                raise IndexError("Dropout must be numeric.")

            if phase == "training" and not sys.argv[8].isdigit():
                raise IndexError("Batch size must be numeric.")
            elif phase == "training" or phase == "predicting":
                batch_size = int(sys.argv[8])

            filename = argv[7]
            if phase == "testing":
                aeids(phase, filename, protocol, port, hidden_layers, activation_function, dropout, sys.argv[8])
            else:
                aeids(phase, filename, protocol, port, hidden_layers, activation_function, dropout, batch_size=batch_size)
        else:
            count_byte_freq(argv[4], protocol, port)

    except IndexError as e:
        print("Usage: python aeids.py <training|predicting|testing|counting> <tcp|udp> <port> <hidden_layers> <activation_function> <dropout> <training filename> [batch_size] [testing filename]")
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


def aeids(phase = "training", filename = "", protocol="tcp", port="80", hidden_layers = [200,100], activation_function = "relu", dropout = 0.0, testing_filename = "", batch_size = 1):
    global done
    read_conf()

    if phase == "training":
        numpy.random.seed(666)

        autoencoder = init_model(hidden_layers, activation_function, dropout)

        if "{}-{}".format(filename, port) in conf["training_filename"]:
            steps_per_epoch = conf["training_filename"]["{}-{}".format(filename, port)] / batch_size
        else:
            steps_per_epoch = conf["training_filename"]["default-80"] / batch_size

        if tensorboard_log_enabled and backend == "tensorflow":
            tensorboard_callback = TensorBoard(log_dir="./logs", batch_size=10000, write_graph=True, write_grads=True,
                                               histogram_freq=1)
            autoencoder.fit_generator(byte_freq_generator(filename, protocol, port, batch_size), steps_per_epoch=100,
                                      epochs=100, verbose=1, callbacks=[tensorboard_callback])
            check_directory(filename, "models")
            autoencoder.save("models/{}/aeids-with-log-{}-hl{}-af{}-do{}.hdf5".format(filename, protocol + port, ",".join(hidden_layers), activation_function, dropout), overwrite=True)
        else:
            autoencoder.fit_generator(byte_freq_generator(filename, protocol, port, batch_size), steps_per_epoch=steps_per_epoch,
                                      epochs=20, verbose=1)
            check_directory(filename, "models")
            autoencoder.save("models/{}/aeids-{}-hl{}-af{}-do{}.hdf5".format(filename, protocol + port, ",".join(hidden_layers), activation_function, dropout), overwrite=True)

        print "Training autoencoder finished. Calculating threshold..."
        predict_byte_freq_generator(autoencoder, filename, protocol, port, hidden_layers, activation_function, dropout, phase)
        done = True
        print "\nFinished."
    elif phase == "predicting":
        autoencoder = load_autoencoder(filename, protocol, port, hidden_layers, activation_function, dropout)
        predict_byte_freq_generator(autoencoder, filename, protocol, port, hidden_layers, activation_function, dropout, phase)
        done = True
        print "\nFinished."
    elif phase == "testing":
        autoencoder = load_autoencoder(filename, protocol, port, hidden_layers, activation_function, dropout)
        predict_byte_freq_generator(autoencoder, filename, protocol, port, hidden_layers, activation_function, dropout, phase, testing_filename)
        print "\nFinished."
    else:
        raise IndexError


def read_conf():
    global conf

    fconf = open("aeids.conf", "r")
    if not fconf:
        print "File aeids.conf does not exist."
        exit(-1)

    conf["root_directory"] = []
    conf["training_filename"] = {"default-80": 100000}
    lines = fconf.readlines()
    for line in lines:
        if line.startswith("#"):
            continue
        split = line.split("=", 2)
        print split
        if split[0] == "root_directory":
            conf["root_directory"].append(split[1].strip())
        elif split[0] == "training_filename":
            tmp = split[1].split(":")
            conf["training_filename"]["{}-{}".format(tmp[0], tmp[1])] = int(tmp[2])

    fconf.close()


def init_model(hidden_layers = [200, 100], activation_function ="relu", dropout = 0):
    input_dimension = 256
    input = Input(shape=(input_dimension,))

    for i in range(0, len(hidden_layers)):
        if i == 0:
            encoded = Dense(int(hidden_layers[i]), activation=activation_function)(input)
        else:
            encoded = Dense(int(hidden_layers[i]), activation=activation_function)(encoded)

        encoded = Dropout(dropout)(encoded)

    for i in range(len(hidden_layers) - 1, -1, -1):
        if i == len(hidden_layers) - 1:
            decoded = Dense(int(hidden_layers[i]), activation=activation_function)(encoded)
        else:
            decoded = Dense(int(hidden_layers[i]), activation=activation_function)(decoded)

        decoded = Dropout(0.2)(decoded)

    if len(hidden_layers) == 1:
        decoded = Dense(input_dimension, activation="sigmoid")(encoded)
    else:
        decoded = Dense(input_dimension, activation="sigmoid")(decoded)
    autoencoder = Model(outputs=decoded, inputs=input)
    autoencoder.compile(loss="binary_crossentropy", optimizer="adadelta")

    return autoencoder


def load_autoencoder(filename, protocol, port, hidden_layers, activation_function, dropout):
    autoencoder = load_model("models/{}/aeids-{}-hl{}-af{}-do{}.hdf5".format(filename, protocol + port, ",".join(hidden_layers), activation_function, dropout))
    return autoencoder


def byte_freq_generator(filename, protocol, port, batch_size):
    global prt
    global conf
    prt = StreamReaderThread(get_pcap_file_fullpath(filename), protocol, port)
    prt.start()
    counter = 0

    while not done:
        while not prt.done or prt.has_ready_message():
            if not prt.has_ready_message():
                time.sleep(0.0001)
                continue
            else:
                buffered_packets = prt.pop_connection()
                if buffered_packets is None:
                    time.sleep(0.0001)
                    continue
                if buffered_packets.get_payload_length("server") > 0:
                    byte_frequency = buffered_packets.get_byte_frequency("server")
                    X = numpy.reshape(byte_frequency, (1, 256))

                    if counter == 0 or counter % batch_size == 1:
                        dataX = X
                    else:
                        dataX = numpy.r_["0,2", dataX, X]

                    counter += 1

                    if counter % batch_size == 0:
                        yield dataX, dataX

        if dataX.shape[0] > 0:
            yield dataX, dataX

        prt.reset_read_status()


def predict_byte_freq_generator(autoencoder, filename, protocol, port, hidden_layers, activation_function, dropout, phase="training", testing_filename = ""):
    global prt
    global threshold

    if prt is None:
        if phase == "testing":
            prt = StreamReaderThread(get_pcap_file_fullpath(testing_filename), protocol, port)
        else:
            prt = StreamReaderThread(get_pcap_file_fullpath(filename), protocol, port)

        prt.delete_read_connections = True
        prt.start()
    else:
        prt.reset_read_status()
        prt.delete_read_connections = True

    errors_list = []
    counter = 0
    print "predict"

    if phase == "testing":
        t1, t2 = load_threshold(filename, protocol, port, hidden_layers, activation_function, dropout)
        check_directory(filename, "results")
        # fresult = open("results/{}/result-{}-hl{}-af{}-do{}-{}.csv".format(filename, protocol + port, ",".join(hidden_layers), activation_function, dropout, testing_filename), "w")
        open_conn()
        experiment_id = create_experiment(filename, testing_filename, protocol, port, ",".join(hidden_layers), activation_function, dropout)
        # if fresult is None:
        #     raise Exception("Could not create file")

    # ftemp = open("results/data.txt", "wb")
    # fcsv = open("results/data.csv", "wb")
    # a = csv.writer(fcsv, quoting=csv.QUOTE_ALL)
    # time.sleep(2)
    i_counter = 0
    # for i in range(0,10):
    while (not prt.done) or (prt.has_ready_message()):
        if not prt.has_ready_message():
            time.sleep(0.0001)
        else:
            buffered_packets = prt.pop_connection()
            if buffered_packets is None:
                continue
            if buffered_packets.get_payload_length("server") == 0:
                continue

            i_counter += 1
            # print "{}-{}".format(i_counter, buffered_packets.id)
            # print "{}-{}: {}".format(i_counter, buffered_packets.id, buffered_packets.get_payload("server")[:100])
            byte_frequency = buffered_packets.get_byte_frequency("server")
            # ftemp.write(buffered_packets.get_payload())
            # a.writerow(byte_frequency)
            data_x = numpy.reshape(byte_frequency, (1, 256))
            decoded_x = autoencoder.predict(data_x)
            # a.writerow(decoded_x[0])

            # fcsv.close()
            error = numpy.mean((decoded_x - data_x) ** 2, axis=1)
            # ftemp.write("\r\n\r\n{}".format(error))
            # ftemp.close()
            if phase == "training" or phase == "predicting":
                errors_list.append(error)
            elif phase == "testing":
                decision = decide(error[0], t1, t2)
                # fresult.write("{},{},{},{},{},{}\n".format(buffered_packets.id, error[0], decision[0], decision[1], decision[2], buffered_packets.get_hexlify_payload()))
                write_results_to_db(experiment_id, buffered_packets, error, decision)

            counter += 1
            sys.stdout.write("\rCalculated {} connections.".format(counter))
            sys.stdout.flush()

    errors_list = numpy.reshape(errors_list, (1, len(errors_list)))
    if phase == "training" or phase == "predicting":
        save_mean_stdev(filename, protocol, port, hidden_layers, activation_function, dropout, errors_list)
        save_q3_iqr(filename, protocol, port, hidden_layers, activation_function, dropout, errors_list)
        save_median_mad(filename, protocol, port, hidden_layers, activation_function, dropout, errors_list)
    elif phase == "testing":
        # fresult.close()
        return


def count_byte_freq(filename, protocol, port):
    global prt
    global conf

    read_conf()

    prt = StreamReaderThread(get_pcap_file_fullpath(filename), protocol, port)
    prt.start()
    prt.delete_read_connections = True
    counter = 0
    missed_counter = 0

    while not prt.done or prt.has_ready_message():
        if not prt.has_ready_message():
            # print(1)
            time.sleep(0.0001)
            missed_counter += 1
            sys.stdout.write("\r1-{} flows. Missed: {}. {} items in buffer. packets: {}. last ts: {}".format(counter, missed_counter, len(prt.tcp_buffer), prt.packet_counter, prt.last_timestamp))
            sys.stdout.flush()
            continue
        else:
            start = time.time()
            buffered_packets = prt.pop_connection()
            end = time.time()
            if buffered_packets is None:
                # print(2)
                time.sleep(0.0001)
                missed_counter += 1
                sys.stdout.write("\r2-{} flows. Missed: {}. Time: {}".format(counter, missed_counter, end - start))
                sys.stdout.flush()
                continue
            if buffered_packets.get_payload_length("server") > 0:
                counter += 1
                sys.stdout.write("\r3-{} flows. Missed: {}. Time: {}".format(counter, missed_counter, end-start))
                sys.stdout.flush()

    print "Total flows: {}".format(counter)


def save_mean_stdev(filename, protocol, port, hidden_layers, activation_function, dropout, errors_list):
    mean = numpy.mean(errors_list)
    stdev = numpy.std(errors_list)
    fmean = open("models/{}/mean-{}-hl{}-af{}-do{}.txt".format(filename, protocol + port, ",".join(hidden_layers), activation_function, dropout), "w")
    fmean.write("{},{}".format(mean, stdev))
    fmean.close()


def save_q3_iqr(filename, protocol, port, hidden_layers, activation_function, dropout, errors_list):
    qs = numpy.percentile(errors_list, [100, 75, 50, 25, 0])
    iqr = qs[1] - qs[3]
    MC = ((qs[0]-qs[2])-(qs[2]-qs[4]))/(qs[0]-qs[4])
    if MC >= 0:
        constant = 3
    else:
        constant = 4
    iqrplusMC = 1.5 * math.pow(math.e, constant * MC) * iqr
    print "IQR: {}\nMC: {}\nConstant: {}".format(iqr, MC, constant)
    fmean = open("models/{}/median-{}-hl{}-af{}-do{}.txt".format(filename, protocol + port, ",".join(hidden_layers), activation_function, dropout), "w")
    fmean.write("{},{}".format(qs[2], iqrplusMC))
    fmean.close()


def save_median_mad(filename, protocol, port, hidden_layers, activation_function, dropout, errors_list):
    median = numpy.median(errors_list)
    mad = numpy.median([numpy.abs(error - median) for error in errors_list])

    fmean = open("models/{}/zscore-{}-hl{}-af{}-do{}.txt".format(filename, protocol + port, ",".join(hidden_layers), activation_function, dropout), "w")
    fmean.write("{},{}".format(median, mad))
    fmean.close()


def load_threshold(filename, protocol, port, hidden_layers, activation_function, dropout):
    t1 = []
    t2 = []

    fmean = open(
        "models/{}/mean-{}-hl{}-af{}-do{}.txt".format(filename, protocol + port, ",".join(hidden_layers), activation_function, dropout), "r")
    line = fmean.readline()
    split = line.split(",")
    t1.append(split[0])
    t2.append(split[1])
    fmean.close()

    fmean = open(
        "models/{}/median-{}-hl{}-af{}-do{}.txt".format(filename, protocol + port, ",".join(hidden_layers), activation_function, dropout), "r")
    line = fmean.readline()
    split = line.split(",")
    t1.append(split[0])
    t2.append(split[1])
    fmean.close()

    fmean = open(
        "models/{}/zscore-{}-hl{}-af{}-do{}.txt".format(filename, protocol + port, ",".join(hidden_layers), activation_function, dropout), "r")
    line = fmean.readline()
    split = line.split(",")
    t1.append(split[0])
    t2.append(split[1])
    fmean.close()

    return t1, t2


def get_threshold(threshold_method, t1, t2):
    if threshold_method == "mean":
        return (float(t1[0]) + 2 * float(t2[0]))
    elif threshold_method == "median":
        return (float(t1[1]) + float(t2[1]))
    elif threshold_method == "zscore":
        return 3.5


def decide(mse, t1, t2):
    decision = []

    if mse > (float(t1[0]) + 2 * float(t2[0])):
        decision.append(True)
    else:
        decision.append(False)

    if mse > (float(t1[1]) + float(t2[1])):
        decision.append(True)
    else:
        decision.append(False)

    zscore = 0.6745 * (mse - float(t1[2])) / float(t2[2])
    if zscore > 3.5 or zscore < -3.5:
        decision.append(True)
    else:
        decision.append(False)

    return decision


def check_directory(filename, root = "models"):
    if not os.path.isdir("./{}/{}".format(root, filename)):
        os.mkdir("./{}/{}".format(root, filename))


def get_pcap_file_fullpath(filename):
    global conf
    for i in range(0, len(conf["root_directory"])):
        if os.path.isfile(conf["root_directory"][i] + filename):
            return conf["root_directory"][i] + filename


def open_conn():
    global conn

    conn = psycopg2.connect(host="localhost", database="aeids", user="postgres", password="postgres")
    conn.set_client_encoding('Latin1')


def create_experiment(training_filename, testing_filename, protocol, port, hidden_layer, activation_function, dropout):
    global conn

    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute("SELECT * FROM experiments WHERE training_filename=%s AND testing_filename=%s AND protocol=%s AND port=%s AND hidden_layers=%s AND activation_function=%s AND dropout=%s", (training_filename, testing_filename, protocol, port, hidden_layer, activation_function, dropout))

    if cursor.rowcount > 0: # There is an existing experiment, get the ID
        row = cursor.fetchone()
        return row["id"]
    else:
        cursor.execute("INSERT INTO experiments(training_filename, testing_filename, protocol, port, hidden_layers, activation_function, dropout) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id", (training_filename, testing_filename, protocol, port, hidden_layer, activation_function, dropout))
        if cursor.rowcount == 1:
            row = cursor.fetchone()
            conn.commit()
            return row["id"]
        else:
            raise Exception("Cannot insert a new experiment")


def get_message_id(buffered_packet):
    global conn

    tmp = buffered_packet.id.split("-")
    src_addr = tmp[0]
    src_port = tmp[1]
    dst_addr = tmp[2]
    dst_port = tmp[3]
    protocol = tmp[4]
    start_time = buffered_packet.get_start_time()
    stop_time = buffered_packet.get_stop_time()

    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute("SELECT * FROM messages WHERE src_ip=%s AND src_port=%s AND dst_ip=%s AND dst_port=%s AND "
                   "protocol=%s AND window_size=%s AND start_time=%s AND stop_time=%s", (src_addr, src_port, dst_addr, dst_port, protocol, WINDOW_SIZE, start_time, stop_time))

    if cursor.rowcount > 0:
        row = cursor.fetchone()
        return row["id"]
    else:
        cursor.execute("""INSERT INTO messages (src_ip, src_port, dst_ip, dst_port, protocol, start_time, stop_time, """
                       """payload, window_size) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                       (src_addr, src_port, dst_addr, dst_port, protocol, start_time, stop_time,
                        psycopg2.Binary(buffered_packet.get_payload("server")), WINDOW_SIZE))
        if cursor.rowcount == 1:
            row = cursor.fetchone()
            conn.commit()
            return row["id"]
        else:
            raise Exception("Cannot insert a new message")


def write_results_to_db(experiment_id, buffered_packet, error, decision):
    global conn

    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    message_id = get_message_id(buffered_packet)

    cursor.execute("UPDATE mse_results SET mse=%s, decision_mean=%s, decision_median=%s, decision_zscore=%s WHERE messages_id=%s AND experiments_id=%s", (error[0], decision[0], decision[1], decision[2], message_id, experiment_id))
    if cursor.rowcount == 0: # The row doesn't exist
        cursor.execute("INSERT INTO mse_results (experiments_id, messages_id, mse, decision_mean, decision_median, decision_zscore) VALUES (%s, %s, %s, %s, %s, %s)", (experiment_id, message_id, error[0], decision[0], decision[1], decision[2]))

    conn.commit()


if __name__ == '__main__':
	main(sys.argv)
