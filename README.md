# Efficient and Secure Range Counting over Distributed Geographic Data with Query Range Protection
This repository contains the implementation of **PPRC**, a Privacy-Preserving Range Counting protocol designed for secure range queries over distributed datasets. Range counting is a fundamental operation in geographic information systems (GIS) and various analytics tasks, yet it raises significant privacy concerns when data is held by multiple independent data holders (DHs). Existing privacy-preserving solutions either assume disjoint datasets, causing large estimation errors when overlaps occur, or expose the plaintext query range to DHs, thus compromising the privacy of query users. PPRC is the first protocol that addresses both issues while achieving practical efficiency. It reformulates secure point-in-range evaluation as encrypted membership tests implemented via encrypted Bloom filters, enabling efficient range queries without revealing the query range. Moreover, it employs an optimized secure count estimation sketch to aggregate overlapped results with minimal cryptographic cost, ensuring that no information beyond the final range count is leaked. Theoretical analysis and extensive experiments on real-world and synthetic datasets demonstrate that PPRC achieves up to 15× smaller errors and 37× faster performance than existing baselines.
## Datasets
We evaluate PPRC on both real-world and synthetic datasets to comprehensively assess its accuracy and efficiency. The real-world datasets include Yelp, Brightkite, and Gowalla, which provide diverse geographic and social network records. Specifically, we extract 21,900 merchant locations from the Yelp dataset in Florida, and 115,383 and 196,561 user check-ins from Brightkite and Gowalla, respectively. Furthermore, we construct a synthetic dataset by uniformly generating locations within the San Francisco region (latitude: 37.5–37.9, longitude: –122.6–122.2) at four scales: 10K, 100K, 1M, and 10M records.
## Metric
Our experiments measure both accuracy and efficiency. Accuracy is evaluated using Mean Absolute Error (MAE) and Mean Relative Error (MRE) between the estimated and true range counts. Efficiency is assessed by measuring the end-to-end computation time (from query generation to result retrieval) and the communication overhead among the query user (QU), the computation aggregator (CA), and the data holders (DHs).
## Experiments for Accuracy
1. Run `pip install -r requirements.txt` to download the required packages.

2. Please run 

```
cd ./experiment_acc
python pprc.py
```
## Experiments for Efficiency
1. Prepare the requirements of our PPRC protocol.

```
sudo apt update
sudo apt install build-essential libboost-all-dev libgmp-dev
```
   
2. Compile files of the query user (client.cpp), the central aggregator (center.cpp), and the data holders (server.cpp).

```
g++ -std=c++17 -o client client.cpp bloomfilter.cpp SHE.cpp MurmurHash3.cpp -lboost_system -lgmpxx -lgmp
g++ -std=c++17  -o server server.cpp MurmurHash3.cpp -lboost_system -lgmpxx -lgmp
g++ -std=c++17 -o center center.cpp -lboost_system -lgmpxx -lgmp
```
   
3. Run our PPRC protocol in the three separate terminals. First, run the central aggregator and the data holders

```
./center 9001 127.0.0.1 9002
./server 9002
```
Then, run the query user
```
./client 127.0.0.1 9001
```
