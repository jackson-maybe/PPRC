

This repository contains the official C++ implementation of the Privacy-Preserving Range Counting (PPRC) protocol. The system evaluates spatial range queries over distributed datasets entirely in the encrypted domain, ensuring robust data privacy against semi-honest entities.

The protocol is instantiated using the Fan-Vercauteren (BFV) Fully Homomorphic Encryption (FHE) scheme.


# 🛠️ Prerequisites

To build and run this project, ensure your environment meets the following standard requirements:

* **C++ Compiler**: Fully supports C++17 with built-in concurrency support (e.g., GCC 9+ or Clang 10+).
* **CMake**: Version 3.13 or higher.
* **Boost.Asio**: For asynchronous, non-blocking network TCP streams.
* **Microsoft SEAL (v4.1+)**: The underlying homomorphic encryption library (configured with ZSTD compression support).

## Installing Dependencies (Ubuntu/Linux Example)

```bash
# Install standard build tools and Boost
sudo apt update
sudo apt install build-essential cmake libboost-all-dev

# Install Microsoft SEAL
git clone [https://github.com/microsoft/SEAL.git](https://github.com/microsoft/SEAL.git)
cd SEAL
cmake -S . -B build -DSEAL_USE_ZSTD=ON
cmake --build build
sudo cmake --install build
```


---

# 🚀 Build Instructions

We recommend using **Modern CMake** to compile the project.

From the root directory of the project, run:

```bash
# Configure the build directory
cmake -S . -B build

# Compile the project with multi-threading (e.g., 5 jobs)
cmake --build build -j5
```

After compilation, three executable binaries will be generated inside the `build/` directory:

- `server`
- `center`
- `client`

---

# 💻 How to Run

The system requires starting the three components in the following order:

```text
Server → Center → Client
```

Navigate into the `build/` directory before running:

```bash
cd build
```

---

## Step 1: Start the Server (Data Holder)

The server loads the dataset, generates the cryptographic context, and listens for requests from the Center.

### Usage

```bash
./server <listen_port>
```

### Example

```bash
# Start Server on port 9012
./server 9012
```

---

## Step 2: Start the Center (Central Aggregator)

The center acts as an anonymizing proxy and aggregation hub.

It requires:

- its own listening port
- the IP address of the upstream Server
- the port of the upstream Server

### Usage

```bash
./center <listen_port> <server_ip> <server_port>
```

### Example

```bash
# Start Center listening on port 9011
# Forward requests to Server at 127.0.0.1:9012
./center 9011 127.0.0.1 9012
```

---

## Step 3: Start the Client (Query User)

The client generates the spatial query range, builds the encrypted Bloom filters, and submits the request to the Center.

### Usage

```bash
./client <center_ip> <center_port>
```

### Example

```bash
# Start Client and connect to Center at 127.0.0.1:9011
./client 127.0.0.1 9011
```


