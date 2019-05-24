AEIDS (Unsupervised Approach for Detecting Low Rate Attacks on Network Traffic with Autoencoder)
================================================================================================

AEIDS is a prototype of anomaly-based intrusion detection system which works by remembering the pattern of legitimate network traffic using Autoencoder. The full paper of this approach (Unsupervised Approach for Detecting Low Rate Attacks on Network Traffic with Autoencoder) is available [here](https://ieeexplore.ieee.org/document/8560678)

Dependencies:
* Python 2.7
* Pcapy
* Keras
* psycopg2 (for database access)
* PostgreSQL 9.5

Installation:
1. Clone this repository and install all necessary libraries and programs
2. Create a database in PostgreSQL and import the schema in aeids.sql`
3. Modify `aeids.conf`, put the location of your PCAP file in the`root\_directory variable. Put the name of the PCAP file in the `training\_filename` along with the number of TCP connections to the server using this format `filename:num_connections`. See the examples config provided. Use wireshark or the `counting` phase in AEIDS to get the number of TCP connections.
4. Modify the database connection configuration in aeids.py. Find the `open_conn()` function.
