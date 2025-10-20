# Efficient and Secure Range Counting over Distributed Geographic Data with Query Range Protection
This repository contains the implementation of **PPRC**, a Privacy-Preserving Range Counting protocol designed for secure range queries over distributed datasets. Range counting is a fundamental operation in geographic information systems (GIS) and various analytics tasks, yet it raises significant privacy concerns when data is held by multiple independent data holders (DHs). Existing privacy-preserving solutions either assume disjoint datasets, causing large estimation errors when overlaps occur, or expose the plaintext query range to DHs, thus compromising the privacy of query users. PPRC is the first protocol that addresses both issues while achieving practical efficiency. It reformulates secure point-in-range evaluation as encrypted membership tests implemented via encrypted Bloom filters, enabling efficient range queries without revealing the query range. Moreover, it employs an optimized secure count estimation sketch to aggregate overlapped results with minimal cryptographic cost, ensuring that no information beyond the final range count is leaked. Theoretical analysis and extensive experiments on real-world and synthetic datasets demonstrate that PPRC achieves up to 15× smaller errors and 37× faster performance than existing baselines.
## Datasets
We evaluate PPRC on both real-world and synthetic datasets to comprehensively assess its accuracy and efficiency. The real-world datasets include Yelp, Brightkite, and Gowalla, which provide diverse geographic and social network records. Specifically, we extract 21,900 merchant locations from the Yelp dataset in Florida, and 115,383 and 196,561 user check-ins from Brightkite and Gowalla, respectively. Furthermore, we construct a synthetic dataset by uniformly generating locations within the San Francisco region (latitude: 37.5–37.9, longitude: –122.6–122.2) at four scales: 10K, 100K, 1M, and 10M records.
## Metric
Our experiments measure both accuracy and efficiency. Accuracy is evaluated using Mean Absolute Error (MAE) and Mean Relative Error (MRE) between the estimated and true range counts. Efficiency is assessed by measuring the end-to-end computation time (from query generation to result retrieval) and the communication overhead among the query user (QU), the computation aggregator (CA), and the data holders (DHs).
## Experiments for Accuracy
1. Run `pip install -r requirements.txt` to download the required packages.

2. If you want to test the accuracy of MPC-FH (using MPS sketch), please run `python MPS.py`.

   If you want to test the accuracy of MPC-LiquidLegions, please run `python LiquidLegions.py`.
## Experiments for Efficiency
1. Prepare requirements and compile fundamental protocols of SPDZ.

```
cd MP-SPDZ
sudo apt-get install automake build-essential clang cmake git libboost-dev libboost-thread-dev libntl-dev libsodium-dev libssl-dev libtool m4 python3 texinfo yasm libgmp-dev libmpfr-dev libmpc-dev
sh protocol_compile.sh
```

   Please make sure that CMake's version is at least 3.12 .
   
2. Compile our MPC-FH protocol and set the number of computation providers (CPs).

```
./compile.py -F 64 MPC_FH
Scripts/setup-online.sh <nCPs>
```

   Besides, we should also set the number of CPs in the `Scripts/run-common.sh`.
   
3. Run our MPC-FH protocol.

```
Scripts/run-online.sh MPC_FH
```
   
