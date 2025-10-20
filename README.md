# Efficient and Secure Range Counting over Distributed Geographic Data with Query Range Protection
This repository contains the implementation of **PPRC**, a Privacy-Preserving Range Counting protocol designed for secure range queries over distributed datasets. Range counting is a fundamental operation in geographic information systems (GIS) and various analytics tasks, yet it raises significant privacy concerns when data is held by multiple independent data holders (DHs). Existing privacy-preserving solutions either assume disjoint datasets, causing large estimation errors when overlaps occur, or expose the plaintext query range to DHs, thus compromising the privacy of query users. PPRC is the first protocol that addresses both issues while achieving practical efficiency. It reformulates secure point-in-range evaluation as encrypted membership tests implemented via encrypted Bloom filters, enabling efficient range queries without revealing the query range. Moreover, it employs an optimized secure count estimation sketch to aggregate overlapped results with minimal cryptographic cost, ensuring that no information beyond the final range count is leaked. Theoretical analysis and extensive experiments on real-world and synthetic datasets demonstrate that PPRC achieves up to 15× smaller errors and 37× faster performance than existing baselines.
## Datasets
To simulate the real scenario, we first generate varieties of publishers' ID datasets, which are randomly sampled from the universe set without duplicates. As for the publishers' frequency datasets, we set the homogeneous and heterogeneous cases. For the homogeneous case, the frequencies across different users are sampled from the same zero-shifted Poisson distribution, while for the heterogeneous case, each of them is sampled from a customized zero-shifted negative binomial distribution. 
## Metric
To evaluate the accuracy, we use the metric Shuffle Distance (SD) to measure the difference between the estimated frequency histogram and the ground-truth frequency histogram. We use the metric because it represents the fraction of data whose frequency is wrong.
In addition, we measure the running time and communication overload of our protocol MPC-FH compared with the state-of-the-art protocol MPC-LiquidLegions.
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
   
