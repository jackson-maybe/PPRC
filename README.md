# 🛰️ Efficient and Secure Range Counting over Distributed Geographic Data with Query Range Protection
This repository contains the implementation of **PPRC**, a Privacy-Preserving Range Counting protocol designed for secure range queries over distributed datasets. Range counting is a fundamental operation in geographic information systems (GIS) and various analytics tasks, yet it raises significant privacy concerns when data is held by multiple independent data holders (DHs). Existing privacy-preserving solutions either assume disjoint datasets, causing large estimation errors when overlaps occur, or expose the plaintext query range to DHs, thus compromising the privacy of query users. PPRC is the first protocol that addresses both issues while achieving practical efficiency. It reformulates secure point-in-range evaluation as encrypted membership tests implemented via encrypted Bloom filters, enabling efficient range queries without revealing the query range. Moreover, it employs an optimized secure count estimation sketch to aggregate overlapped results with minimal cryptographic cost, ensuring that no information beyond the final range count is leaked. Theoretical analysis and extensive experiments on real-world and synthetic datasets demonstrate that PPRC achieves up to 15× smaller errors and 37× faster performance than existing baselines.

## 🚀 Key Features
- **Query Range Protection** – The query range is encrypted and never revealed to data holders.  
- **Overlap-Aware Counting** – Correctly aggregates results across overlapping datasets without double-counting.  
- **Optimized Secure Sketching** – Employs a lightweight encrypted sketch to minimize cryptographic cost.  
- **Accurate** – Achieves up to **15× smaller estimation errors** than  baselines.  
- **Efficient** – Achieves up to **37× faster runtime** (end-to-end) compared to baselines.


## 📂 Repository Structure
```text
PPRC/
├── datasets/       # Datasets used in the evaluation
│   ├── brightkite/         # The Brightkite dataset
│   ├── gowalla/            # The Gowalla dataset
│   ├── spatial/            # The Yelp dataset
│   └── synthetic_datasets/ # The synthetic datasets 
├── experiment_acc/ # Accuracy evaluation scripts (Python)
│   ├── bloom_filter.py     # Python implementation of Bloom Filter
│   ├── data_provider.py    # Simulates data holders and their local datasets
│   ├── linear_counting.py  # Python implementation of Linear Counting
│   └── pprc.py             # Main script to run the PPRC
├── MurmurHash3.cpp # Hash function implementation
├── MurmurHash3.h   # Hash function header
├── README.md
├── SHE.cpp         # SHE scheme implementation
├── SHE.h           # SHE header
├── bloomfilter.cpp # Bloom filter implementation
├── bloomfilter.h   # Bloom filter header
├── linearcounting.cpp # Linear counting sketch implementation
├── linearcounting.h # Linear counting header
├── client.cpp # Query user (QU) client
├── center.cpp # central aggregator (CA)
├── server.cpp # Data holder (DH) server
└── requirements.txt # Python dependencies
```

## 📊 Datasets
We evaluate PPRC on three real-world and one synthetic dataset to assess both accuracy and efficiency.
The real-world datasets—Yelp, Brightkite, and Gowalla—cover diverse geographic and social contexts.
The synthetic dataset is uniformly generated within the San Francisco region (lat: 37.5–37.9, lon: –122.6––122.2) at four scales: 10K, 100K, 1M, and 10M records.

| Dataset     | Type            | Records | Description |
|--------------|-----------------|---------:|-------------|
| Yelp         | Business        |   21,900 | Geographic business records (Florida) |
| Brightkite   | Social Network  |  115,383 | User check-in records |
| Gowalla      | Social Network  |  196,561 | User check-in records |
| Synthetic    | Generated       |  10K–10M | Uniformly sampled within the San Francisco region (lat: 37.5–37.9, lon: –122.6––122.2) |





## ⚙️ Experimental Metrics
Our experiments measure both accuracy and efficiency. Accuracy is evaluated using **Mean Absolute Error (MAE)** and **Mean Relative Error (MRE)** between the estimated and true range counts. Efficiency is assessed by measuring the **end-to-end running time** (from query generation to result retrieval) and the **communication overhead** among the query user (QU), the central aggregator (CA), and the data holders (DHs).
## 🧪 Running Accuracy Experiments
**1. Install Python dependencies**
 ```bash
   pip install -r requirements.txt
```
**2. Run accuracy evaluation**

``` bash
cd ./experiment_acc
python pprc.py
```
## ⚡ Running Efficiency Experiments
**1. Install dependencies**

``` bash
sudo apt update
sudo apt install build-essential libboost-all-dev libgmp-dev
```
   
**2. Compile the components**

``` bash
# Query user 
g++ -std=c++17 -o client client.cpp bloomfilter.cpp SHE.cpp MurmurHash3.cpp -lboost_system -lgmpxx -lgmp

# Data holders
g++ -std=c++17  -o server server.cpp MurmurHash3.cpp -lboost_system -lgmpxx -lgmp

# Central aggregator 
g++ -std=c++17 -o center center.cpp -lboost_system -lgmpxx -lgmp
```
   
**3. Run PPRC in three terminals**

Terminal 1 – Start the Central Aggregator (CA)

``` bash
./center <listen_port_CA> <server_ip> <server_port>
# Example:
./center 9001 127.0.0.1 9002
```
Terminal 2 – Start the Data Holders (DHs)

``` bash
./server <listen_port_DH>
# Example:
./server 9002
```


Terminal 3 – Start the Query User (QU)
``` bash
./client <CA_ip> <CA_port>
# Example:
./client 127.0.0.1 9001
```
