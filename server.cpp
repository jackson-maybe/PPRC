/*
 * =====================================================================================
 *
 *       Filename:  server.cpp
 *
 *    Description:  Server (the data holder) application for PPRC. 
 *                  This server simulates multiple data holders.
 *                  It receives an encrypted query (as Bloom filters) from a
 *                  central server, homomorphically processes the query against
 *                  its local dataset, generates an encrypted Linear Counting
 *                  sketch as a result, and sends it back.
 *
 *        Version:  1.0
 *
 * =====================================================================================
 */

#include <boost/asio.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <gmpxx.h>
#include "MurmurHash3.h"

using boost::asio::ip::tcp;


/**
 * @brief  Serializes and sends a vector of mpz_class numbers over a TCP socket.
 * @note   This function implements a custom binary protocol:
 *         1. A 4-byte header with the total buffer length is sent first.
 *         2. The main buffer follows, containing a sequence of numbers.
 *         3. Each number is encoded as [4-byte length][binary data].
 * @param  socket   The active Boost.Asio TCP socket.
 * @param  numbers  A constant reference to the vector of mpz_class to send.
 */
void send_multiple_mpz_class(tcp::socket &socket, const std::vector<mpz_class> &numbers) {
    std::vector<uint8_t> buffer;
    buffer.reserve(numbers.size() * 520);

    for (const auto &num : numbers) {
        size_t count = 0;
        void *bin = mpz_export(nullptr, &count, 1, 1, 1, 0, num.get_mpz_t());

        uint32_t len = static_cast<uint32_t>(count);
        uint8_t *len_ptr = reinterpret_cast<uint8_t *>(&len);
        buffer.insert(buffer.end(), len_ptr, len_ptr + sizeof(len));
        buffer.insert(buffer.end(), reinterpret_cast<uint8_t *>(bin), reinterpret_cast<uint8_t *>(bin) + len);

        free(bin);
    }

    uint32_t total_length = static_cast<uint32_t>(buffer.size());
    boost::asio::write(socket, boost::asio::buffer(&total_length, sizeof(total_length)));
    boost::asio::write(socket, boost::asio::buffer(buffer));
}


/**
 * @brief  Receives and deserializes a vector of mpz_class numbers from a TCP socket.
 * @note   This function reads data according to the custom binary protocol defined
 *         in send_multiple_mpz_class.
 * @param  socket  The active Boost.Asio TCP socket.
 * @return A vector containing the received mpz_class numbers.
 */
std::vector<mpz_class> receive_multiple_mpz_class(tcp::socket &socket) {
    uint32_t total_length;
    boost::asio::read(socket, boost::asio::buffer(&total_length, sizeof(total_length)));

    std::vector<uint8_t> buffer(total_length);
    boost::asio::read(socket, boost::asio::buffer(buffer));

    std::vector<mpz_class> numbers;
    size_t offset = 0;

    while (offset < buffer.size()) {
        uint32_t len;
        std::memcpy(&len, buffer.data() + offset, sizeof(len));
        offset += sizeof(len);

        mpz_class num;
        mpz_import(num.get_mpz_t(), len, 1, 1, 1, 0, buffer.data() + offset);
        offset += len;

        numbers.emplace_back(std::move(num));
    }

    return numbers;
}

/**
 * @brief  Computes a hash in the bloom filter.
 */
int hashr(int data, int length, int seed) {
    uint32_t hash_result;
    std::string key = std::to_string(data) + "|" + std::to_string(length);
    MurmurHash3_x86_32(key.c_str(), key.size(), seed, &hash_result);
    return hash_result % length;
}

/**
 * @brief  Computes a hash in the linear counting sketch.
 */
int hasht(int data_1, int data_2, int length, int seed) {
    uint32_t hash_result;
    std::string key = std::to_string(data_1) + "|" + std::to_string(data_2) + "|" + std::to_string(length);
    MurmurHash3_x86_32(key.c_str(), key.size(), seed, &hash_result);
    return hash_result % length;
}

/**
 * @brief  Generates a random integer within a specified range.
 */
int generateRandomNumber(int lowerBound, int upperBound) {
    static std::mt19937 gen(std::chrono::steady_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<> RandomNumber(lowerBound, upperBound);
    return RandomNumber(gen);
}


/**
 * @brief  Main entry point for the Data Holder server application.
 */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <listen_port>\n";
        return 1;
    }
    std::string listen_port = argv[1];

    try {
        boost::asio::io_context io_context;

        // --- Step 1: Network Setup ---
        // Listen for an incoming connection from the central server.
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), std::stoi(listen_port)));
        std::cout << "Data Holder server listening on port " << listen_port << "...\n";
        tcp::socket socket(io_context);
        acceptor.accept(socket);
        std::cout << "Center server connected.\n";

        // --- Protocol Parameters ---
        const int hash_count = 7;       // Number of hash functions for the Bloom filter.
        const int lc_length = 2 * 1024;   // Size of the Linear Counting sketch per provider.
        const int server_number = 4;     // The number of data holders this server will simulate.
        const int data_size_per_provider = int(21900 * 0.1); // Size of each provider's dataset.
        const int total_data_size = data_size_per_provider * server_number;

        // --- Step 2: Simulate Local Data Generation ---
        // In a real scenario, this data would be loaded from a database or file.
        // Here, we generate synthetic data for simulation purposes.
        auto start_time = std::chrono::high_resolution_clock::now();
        std::vector<int> arr1(total_data_size), arr2(total_data_size);
        for (int p = 0; p < server_number; ++p) {
            for (int i = 0; i < data_size_per_provider; ++i) {
                int index = p * data_size_per_provider + i;
                arr1[index] = i + p; // Simple non-overlapping data.
                arr2[index] = i + p;
            }
        }
        auto end_time = std::chrono::high_resolution_clock::now();
        
        // --- Step 3: Receive Encrypted data from the Central Aggregator ---
        // The received vector contains: [Encrypted BFx][Encrypted BFy][E(0)][E(0)][N]
        std::vector<mpz_class> query_from_client = receive_multiple_mpz_class(socket);
        const int bf_length = (query_from_client.size() - 3) / 2;
        std::cout << "Received encrypted query Bloom filter." << std::endl;

        // --- Step 4: Homomorphic Range Evaluation ---
        // For each data point, homomorphically check if it's in the query range.
        std::vector<mpz_class> sign_list;
        sign_list.reserve(total_data_size);
        mpz_class pk_N = query_from_client.back(); // Extract public modulus N.

        for (int i = 0; i < total_data_size; i++) {
            mpz_class sign_1 = 1; // E(1) is 1 in this scheme
            mpz_class sign_2 = 1;
            
            // Homomorphically check against the Bloom filters.
            // This is equivalent to an AND operation in the plaintext domain.
            for (int j = 0; j < hash_count; j++) {
                int index1 = hashr(arr1[i], bf_length, j);
                int index2 = hashr(arr2[i], bf_length, j);
                // Homomorphic multiplication: E(a) * E(b) = E(a*b).
                // If any bf_from_client[index] is E(0), the product becomes E(0).
                sign_1 = (sign_1 * query_from_client[index1]) % pk_N;
                sign_2 = (sign_2 * query_from_client[index2 + bf_length]) % pk_N;
            }
            // Final check: if both dimensions are in range, result is E(1), otherwise E(0).
            sign_list.push_back(sign_1 * sign_2);
        }
        
        // --- Step 5: Generate Encrypted Linear Counting Sketches ---
        // The final result is a concatenation of sketches from all simulated providers.
        std::vector<mpz_class> lc_sketch_combined(lc_length * server_number);
        const mpz_class E_0_1 = query_from_client[query_from_client.size() - 3];
        const mpz_class E_0_2 = query_from_client[query_from_client.size() - 2];

        // For each simulated provider...
        for (int p = 0; p < server_number; p++) {
            // Initialize this provider's sketch with random noise using E(0).
            for (int i = 0; i < lc_length; i++) {
                // E(r1*0 + r2*0) = E(0), but blinded.
                lc_sketch_combined[i + p * lc_length] = (generateRandomNumber(1, 100) * E_0_1) + (generateRandomNumber(1, 100) * E_0_2);
            }

            // For each data point belonging to this provider...
            for (int i = 0; i < data_size_per_provider; i++) {
                int data_index = p * data_size_per_provider + i;
                int lc_index = hasht(arr1[data_index], arr2[data_index], lc_length, 0);
                
                // Homomorphically add the sign (E(1) or E(0)) to the corresponding sketch bucket.
                // E(s) + E(val) = E(s + val).
                lc_sketch_combined[lc_index + p * lc_length] += sign_list[data_index];
            }
        }
        
        // --- Send LC Sketches Back ---
        send_multiple_mpz_class(socket, lc_sketch_combined);
        std::cout << "Sent encrypted sketches back to the center server.\n";

    } catch (std::exception &e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

