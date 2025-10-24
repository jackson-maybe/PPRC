/*
 * =====================================================================================
 *
 *       Filename:  client.cpp
 *
 *    Description:  Client-side (the query user) application for the PPRC. 
 *                  This client creates a query, encrypts it using the SHE scheme, 
 *                  sends it to a server, receives an encrypted result, decrypts it, and
 *                  estimates the final count.
 *
 *        Version:  1.0
 *
 * =====================================================================================
 */

#include <boost/asio.hpp>
#include <iostream>
#include <vector>
#include <chrono>
#include <gmpxx.h>
#include "bloomfilter.h"
#include "linearcounting.h" // Note: This header is included but the class is not directly used.
#include "SHE.h"
#include "MurmurHash3.h"

using boost::asio::ip::tcp;

/**
 * @brief  A local reimplementation of a hash function.
 * @note   This appears to be a duplicate of the hash_result function from bloomfilter.cpp.
 *         Consolidating such functions into a shared utility file is recommended.
 * @param  data_id  The integer data to hash.
 * @param  length   The range for the modulo operation.
 * @param  seed     The seed for the hash function.
 * @return The resulting hash value, mapped to the range [0, length-1].
 */
int hashr(int data_id, int length, int seed) {
    uint32_t hash_result;
    std::string key = std::to_string(data_id) + "|" + std::to_string(length);
    MurmurHash3_x86_32(key.c_str(), key.size(), seed, &hash_result);
    return hash_result % length;
}

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
    // Estimated average size of 520 bytes per number.
    buffer.reserve(numbers.size() * 520);

    for (const auto &num : numbers) {
        // Export the mpz_class to a raw binary format.
        size_t count = 0;
        void *bin = mpz_export(nullptr, &count, 1, 1, 1, 0, num.get_mpz_t());

        // Append the length of the binary data (as a 4-byte integer).
        uint32_t len = static_cast<uint32_t>(count);
        uint8_t *len_ptr = reinterpret_cast<uint8_t *>(&len);
        buffer.insert(buffer.end(), len_ptr, len_ptr + sizeof(len));
        
        // Append the binary data itself.
        buffer.insert(buffer.end(), reinterpret_cast<uint8_t *>(bin), reinterpret_cast<uint8_t *>(bin) + len);

        // Free the temporary buffer allocated by mpz_export.
        free(bin);
    }

    // Send the total size of the constructed buffer.
    uint32_t total_length = static_cast<uint32_t>(buffer.size());
    boost::asio::write(socket, boost::asio::buffer(&total_length, sizeof(total_length)));
    
    // Send the buffer itself.
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
    // Read the total length of the incoming buffer.
    uint32_t total_length;
    boost::asio::read(socket, boost::asio::buffer(&total_length, sizeof(total_length)));

    // Read the entire data buffer based on the received length.
    std::vector<uint8_t> buffer(total_length);
    boost::asio::read(socket, boost::asio::buffer(buffer));

    std::vector<mpz_class> numbers;
    size_t offset = 0;

    // Parse the buffer by iteratively reading [length][data] chunks.
    while (offset < buffer.size()) {
        // Read the 4-byte length of the next number.
        uint32_t len;
        std::memcpy(&len, buffer.data() + offset, sizeof(len));
        offset += sizeof(len);

        // Import the binary data into a new mpz_class object.
        mpz_class num;
        mpz_import(num.get_mpz_t(), len, 1, 1, 1, 0, buffer.data() + offset);
        offset += len;

        numbers.emplace_back(std::move(num));
    }

    return numbers;
}

/**
 * @brief  Sends a single mpz_class number as a string.
 * @deprecated This string-based serialization is less efficient than the binary format
 *             used in send_multiple_mpz_class. Recommended for debugging only.
 */
void send_mpz_class(tcp::socket &socket, const mpz_class &number) {
    std::string data = number.get_str();
    uint32_t length = data.size();
    boost::asio::write(socket, boost::asio::buffer(&length, sizeof(length)));
    boost::asio::write(socket, boost::asio::buffer(data));
}

/**
 * @brief  Receives a single mpz_class number sent as a string.
 * @deprecated Corresponds to the inefficient send_mpz_class function.
 */
mpz_class receive_mpz_class(tcp::socket &socket) {
    uint32_t length;
    boost::asio::read(socket, boost::asio::buffer(&length, sizeof(length)));
    std::vector<char> buffer(length);
    boost::asio::read(socket, boost::asio::buffer(buffer));
    return mpz_class(std::string(buffer.begin(), buffer.end()));
}

/**
 * @brief  Main entry point for the client application.
 */
int main(int argc, char *argv[]) {
    // --- Argument Parsing ---
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <port>\n";
        return 1;
    }
    std::string server_ip = argv[1];
    std::string port = argv[2];

    try {
        // --- Network Setup ---
        boost::asio::io_context io_context;
        tcp::socket socket(io_context);
        tcp::resolver resolver(io_context);
        boost::asio::connect(socket, resolver.resolve(server_ip, port));
        
        auto total_start_time = std::chrono::high_resolution_clock::now();

        // --- Step 1: Query Generation (Client-side) ---
        // Define a 2D query range [a, b] x [c, d].
        int a = 0, b = 100;
        int c = 0, d = 100;
        std::vector<int> range_x, range_y;
        for (int i = a; i < b; i++) { range_x.push_back(i); }
        for (int i = c; i < d; i++) { range_y.push_back(i); }

        // Create two Bloom filters to represent the query range and the false positive rate is 0.0001.
        BloomFilter *bfx = create_bloom_filter(range_x.size(), 0.0001);
        for (int val : range_x) { bloom_filter_insert(bfx, val); }

        BloomFilter *bfy = create_bloom_filter(range_y.size(), 0.0001);
        for (int val : range_y) { bloom_filter_insert(bfy, val); }
        
        // --- Step 2: Query Encryption ---
        // NOTE: Hardcoded keys are used for this proof-of-concept. In a real
        // system, keys must be managed securely.
        mpz_class p("24949947668204895169844816279817288492414547819866675629196367227690787470169613155592517331436994431290237129971591491697651840834349620997268980480906268395121128743403076738941611756262701100600337509940012574326308548496255602554176656185505317308069007483713003383893987835829101624859098236400325591893987156914330601585661147623846403075246396332268980092371247871842378726521706210349480430847941451750416021497540541325690672019958068418437982341656155182085983628398491651770170518457520016889488745644657092443571740862417400519834822886322713319302563133379081003649775280137182242840819599772353133239557");
        mpz_class q("30401921436417668354205981245794155113091168091058229071087431152925431803626330928792844068497024013695732699678103788668903183316410652539558968411166596698165768116382511567468227444150175501098154493466321652465307264846602986567019610415655831314987165648814030266745386487366578358462443364985995001433081076453138689439979466036329516087758824960556630262032790509515668449307078307730020388645543284503552354728956759127646815121604724218822060284548126215374106215799906404988717264919893807269017703078074417505647585091932603554391566511681499329866661086106213929877678227760111895141197486092739671683413");
        mpz_class L("975861485164544069203193");
        SecretKey sk(p, q, L);

        // Prepare the payload to send to the server.
        std::vector<mpz_class> send_mpz_vector;
        // Encrypt and add the first Bloom filter.
        for (int i = 0; i < bfx->size; ++i) {
            send_mpz_vector.push_back(encrypt(mpz_class(bfx->bits[i]), sk));
        }
        // Encrypt and add the second Bloom filter.
        for (int i = 0; i < bfy->size; ++i) {
            send_mpz_vector.push_back(encrypt(mpz_class(bfy->bits[i]), sk));
        }

        // Append encrypted auxiliary values for the server-side protocol.
        send_mpz_vector.push_back(encrypt(mpz_class("0"), sk)); // E(0)
        send_mpz_vector.push_back(encrypt(mpz_class("0"), sk)); // E(0)
        
        // Append the public modulus N, which is the public key for the SHE scheme.
        send_mpz_vector.push_back(sk.N);

        // --- Step 3: Send Encrypted Query to Server ---
        send_multiple_mpz_class(socket, send_mpz_vector);
        
        // --- Step 4: Receive Encrypted Result from Server ---
        std::vector<mpz_class> receive_mpz_vector = receive_multiple_mpz_class(socket);
        
        // --- Step 5: Decrypt Result and Estimate Cardinality from Decrypted Sketch ---
        std::vector<mpz_class> LC_sketch_decrypted;
        for (const mpz_class& mpz : receive_mpz_vector) {
            LC_sketch_decrypted.push_back(decrypt(mpz, sk));
        }

        double zero_bits_count = 0;
        int lc_length = LC_sketch_decrypted.size();
        for (int i = 0; i < lc_length; i++) {
            if (LC_sketch_decrypted[i] == 0) {
                zero_bits_count++;
            }
        }
        
        // Apply the standard Linear Counting estimator: -S * log(S' / S)
        int estimated_count = 0;
        if (zero_bits_count > 0) { // Avoid log(0)
            estimated_count = std::floor(-lc_length * log(zero_bits_count / static_cast<double>(lc_length)));
        } else {
             // If there are no zero bits, the sketch is saturated.
             // The estimation is unreliable, but we can report the sketch size as a lower bound.
            estimated_count = lc_length;
        }

        // --- Final Output ---
        std::cout << "The true range count is: " << 100 << " \n"; 
        std::cout << "The estimated range count is: " << estimated_count << " \n";

        auto total_end_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> total_elapsed = total_end_time - total_start_time;
        std::cout << "The total time: " << total_elapsed.count() << " s\n";

        // Clean up dynamically allocated Bloom filters.
        destroy_bloom_filter(bfx);
        destroy_bloom_filter(bfy);

    } catch (std::exception &e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1; // Return an error code on exception.
    }

    return 0;
}