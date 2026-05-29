#pragma once
#include "seal/seal.h"
#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <chrono>

using boost::asio::ip::tcp;
const int SKETCH_SIZE = 1000; 

inline uint64_t modInverse(int64_t a, int64_t m) {
    int64_t m0 = m, y = 0, x = 1;
    if (m == 1) return 0;
    while (a > 1) {
        int64_t q = a / m; int64_t t = m;
        m = a % m; a = t; t = y; y = x - q * y; x = t;
    }
    if (x < 0) x += m0;
    return (uint64_t)x;
}



inline seal::SEALContext create_fhe_context() {
    seal::EncryptionParameters parms(seal::scheme_type::bfv);
    size_t poly_modulus_degree = 8192; 
    parms.set_poly_modulus_degree(poly_modulus_degree);
    
    
    parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
    
    
    parms.set_plain_modulus(seal::PlainModulus::Batching(poly_modulus_degree, 17));
    
    return seal::SEALContext(parms);
}

inline void send_data(tcp::socket& socket, const std::string& data) {
    uint64_t len = data.size();
    boost::asio::write(socket, boost::asio::buffer(&len, sizeof(len)));
    boost::asio::write(socket, boost::asio::buffer(data));
}

inline std::string receive_data(tcp::socket& socket) {
    uint64_t len = 0;
    boost::asio::read(socket, boost::asio::buffer(&len, sizeof(len)));
    std::string data(len, '\0');
    boost::asio::read(socket, boost::asio::buffer(&data[0], len));
    return data;
}


