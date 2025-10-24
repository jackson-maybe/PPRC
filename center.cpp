/*
 * =====================================================================================
 *
 *       Filename:  center.cpp
 *
 *    Description:  A center (the central aggregator) application that acts 
 *                  as a proxy and aggregator in PPRC. It receives an encrypted
 *                  query from a client, forwards it to data holder servers,
 *                  receives back multiple encrypted sketches, aggregates them,
 *                  applies privacy enhancements, and sends the final result
 *                  back to the client.
 *
 *        Version:  1.0
 *
 * =====================================================================================
 */

#include <boost/asio.hpp>
#include <iostream>
#include <vector>
#include <numeric>
#include <algorithm>
#include <chrono>
#include <random>
#include <gmpxx.h>

using boost::asio::ip::tcp;

// --- Global Static Random Number Generator ---
// A static random engine is initialized once and used throughout the application's lifetime.
// This ensures that sequences of random numbers are not repeated on successive function calls
// within the same program run, which would happen if a new engine were seeded each time.
static std::mt19937 gen(std::chrono::steady_clock::now().time_since_epoch().count());


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

    // Pre-allocate buffer space to improve performance by reducing reallocations.
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
 * @brief  Generates a random integer within a specified range.
 * @param  lowerBound The lower bound of the range (inclusive).
 * @param  upperBound The upper bound of the range (inclusive).
 * @return A random integer.
 */
int generateRandomNumber(int lowerBound, int upperBound) {
    // Define the distribution for the random numbers.
    std::uniform_int_distribution<> RandomNumber(lowerBound, upperBound);
    // Generate and return an integer using the global static engine.
    return RandomNumber(gen);
}


/**
 * @brief  Main process for the central server application.
 */
int main(int argc, char *argv[]) {
    // --- Argument Parsing ---
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <listen_port> <data_holder_ip> <data_holder_port>\n";
        return 1;
    }
    std::string listen_port = argv[1];
    std::string data_holder_ip = argv[2];
    std::string data_holder_port = argv[3];

    try {
        boost::asio::io_context io_context;

        // --- Step 1: Network Setup ---
        // Create an acceptor to listen for incoming connections from the client.
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), std::stoi(listen_port)));
        std::cout << "Center server listening on port " << listen_port << "...\n";
        tcp::socket client_socket(io_context);
        acceptor.accept(client_socket);
        std::cout << "Client connected.\n";

        // Create a socket to connect to the downstream data holder server.
        tcp::resolver resolver(io_context);
        tcp::socket data_holder_socket(io_context);
        boost::asio::connect(data_holder_socket, resolver.resolve(data_holder_ip, data_holder_port));
        std::cout << "Connected to data holder at " << data_holder_ip << ":" << data_holder_port << ".\n";

        // --- Step 2: Receive and Forward Query ---
        // Receive the encrypted query payload from the client.
        std::vector<mpz_class> query_from_client = receive_multiple_mpz_class(client_socket);
        std::cout << "Received encrypted query from client.\n";

        // Forward the entire payload to the data holder server.
        send_multiple_mpz_class(data_holder_socket, query_from_client);
        std::cout << "Forwarded query to data holder.\n";

        // --- Step 3: Receive and Process Results ---
        // Receive the concatenated encrypted Linear Counting sketches from the data holder.
        std::vector<mpz_class> lc_sketches_holder = receive_multiple_mpz_class(data_holder_socket);
        std::cout << "Received encrypted sketches from data holders.\n";
       
        // --- Step 3a: Aggregate Sketches ---
        // The protocol assumes a fixed number of data providers and that the received
        // vector is a concatenation of their individual sketches.
        int server_number = 4; // This should ideally be a parameter or dynamically determined.
        if (lc_sketches_holder.size() % server_number != 0) {
             std::cerr << "Error: Received sketch size is not divisible by the number of providers.\n";
             return 1;
        }
        int lc_length = lc_sketches_holder.size() / server_number;
        std::vector<mpz_class> lc_sketch_agg(lc_length);

        // Aggregate the sketches homomorphically by adding the corresponding encrypted elements.
        for (int i = 0; i < lc_length; i++) {
            lc_sketch_agg[i] = 0; // Initialize sum to E(0) which is 0 in this scheme.
            for (int j = 0; j < server_number; j++) {
                lc_sketch_agg[i] += lc_sketches_holder[i + j * lc_length];
            }
        }
        std::cout << "Homomorphically aggregated sketches.\n";

        // --- Step 3b: Apply Privacy Enhancements ---
        // Multiply each element of the aggregated sketch by an encrypted random number
        // to further blind the result before sending it back to the client.
        // NOTE: This step's cryptographic purpose needs to be clearly defined by the protocol.
        std::vector<mpz_class> private_lc_sketch;
        for (mpz_class& mpz : lc_sketch_agg) {
            private_lc_sketch.push_back(mpz * generateRandomNumber(1, 100));
        }

        // Shuffle the privatized sketch to hide the positional information of the bits.
        std::shuffle(private_lc_sketch.begin(), private_lc_sketch.end(), gen);
        std::cout << "Applied privacy enhancements (blinding and shuffling).\n";
        
        // --- Send Final Result to Client ---
        send_multiple_mpz_class(client_socket, private_lc_sketch);
        std::cout << "Sent final processed sketch to client.\n";

    } catch (std::exception &e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1; // Return an error code on exception.
    }

    return 0;
}