# 🛰️ Efficient and Secure Range Counting over Distributed Geographic Data with Query Range Protection
This repository contains the implementation of **PPRC**, a Privacy-Preserving Range Counting protocol designed for secure range queries over distributed datasets. Range counting is a fundamental operation in geographic information systems (GIS) and various analytics tasks, yet it raises significant privacy concerns when data is held by multiple independent data holders (DHs). Existing privacy-preserving solutions either assume disjoint datasets, causing large estimation errors when overlaps occur, or expose the plaintext query range to DHs, thus compromising the privacy of query users. PPRC is the first protocol that addresses both issues while achieving practical efficiency. It reformulates secure point-in-range evaluation as encrypted membership tests implemented via encrypted Bloom filters, enabling efficient range queries without revealing the query range. Moreover, it employs an optimized secure count estimation sketch to aggregate overlapped results with minimal cryptographic cost, ensuring that no information beyond the final range count is leaked. Theoretical analysis and extensive experiments on real-world and synthetic datasets demonstrate that PPRC achieves up to 15× smaller errors and 37× faster performance than existing baselines.

## 🚀 Key Features
- **Query Range Protection** – The query range is encrypted and never revealed to data holders.  
- **Overlap-Aware Counting** – Correctly aggregates results across overlapping datasets without double-counting.  
- **Optimized Secure Sketching** – Employs a lightweight encrypted sketch to minimize cryptographic cost.  
- **End-to-End Efficiency** – Achieves up to **15× smaller errors** and **37× faster performance** than existing baselines.

## 📂 Repository Structure
PPRC/
├── experiment_acc/ # Accuracy evaluation scripts (Python)
├── experiment_eff/ # Efficiency evaluation (C++ implementation)
├── bloomfilter.cpp # Encrypted Bloom filter implementation
├── SHE.cpp # Simplified Homomorphic Encryption primitives
├── client.cpp # Query user (QU) client
├── center.cpp # Computation aggregator (CA)
├── server.cpp # Data holder (DH) server
├── requirements.txt # Python dependencies
└── README.md

## 📊 Datasets
We evaluate PPRC on both real-world and synthetic datasets to comprehensively assess its accuracy and efficiency. The real-world datasets include Yelp, Brightkite, and Gowalla, which provide diverse geographic and social network records. Specifically, we extract 21,900 merchant locations from the Yelp dataset in Florida, and 115,383 and 196,561 user check-ins from Brightkite and Gowalla, respectively. Furthermore, we construct a synthetic dataset by uniformly generating locations within the San Francisco region (latitude: 37.5–37.9, longitude: –122.6–122.2) at four scales: 10K, 100K, 1M, and 10M records. The datasets are as follows:
| Dataset     | Type            | Records | Description |
|--------------|-----------------|----------|-------------|
| Yelp         | Business         | 21,900   | Merchant locations (Florida) |
| Brightkite   | Social Network   | 115,383  | User check-ins |
| Gowalla      | Social Network   | 196,561  | User check-ins |
| Synthetic    | Generated        | 10K–10M  | Uniformly generated in the region (37.5–37.9, –122.6– –122.2) |

## ⚙️ Experimental Metrics
Our experiments measure both accuracy and efficiency. Accuracy is evaluated using **Mean Absolute Error (MAE)** and **Mean Relative Error (MRE)** between the estimated and true range counts. Efficiency is assessed by measuring the **end-to-end computation time** (from query generation to result retrieval) and the **communication overhead** among the query user (QU), the computation aggregator (CA), and the data holders (DHs).
## 🧪 Running Accuracy Experiments
1. Install Python dependencies.
 ```bash
   pip install -r requirements.txt
```
2. Please run 

``` bash
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
