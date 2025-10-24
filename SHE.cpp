/*
 * =====================================================================================
 *
 *       Filename:  SHE.cpp
 *
 *    Description:  Implementation of the SHE scheme.
 *
 *        Version:  1.0
 *
 * =====================================================================================
 */

#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include <random>
#include <chrono>   // Included but not used in the library functions.
#include <limits>   // Required for std::numeric_limits.
#include "SHE.h"

/**
 * @brief  Constructor for the SecretKey class.
 * @param  p  The first large prime.
 * @param  q  The second large prime.
 * @param  L  The random number.
 */
SecretKey::SecretKey(const mpz_class& p, const mpz_class& q, const mpz_class& L) : p(p), q(q), L(L) {
    // The public modulus N is calculated as the product of p and q.
    this->N = this->p * this->q;
}

/**
 * @brief  Generates a random mpz_class integer of a specified bit length.
 * @note   This uses std::mt19937_64 for pseudo-randomness, which is suitable
 *         for general purposes but might not be sufficient for production-grade
 *         cryptography, where a hardware-based or OS-level entropy source is preferred.
 * @param  k  The desired bit length of the random number.
 * @return An mpz_class integer containing k random bits.
 */
mpz_class generateRandom(int k) {
    // Use std::random_device to seed the pseudo-random number generator for better entropy.
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(0, std::numeric_limits<uint64_t>::max());

    int num_bits = k;
    int num_words = (num_bits + 63) / 64; // Calculate how many 64-bit chunks are needed.
    mpz_class r = 0;

    // Build the large random number by concatenating 64-bit random words.
    for (int i = 0; i < num_words; ++i) {
        mpz_class word = dis(gen);
        r = (r << 64) | word;
    }

    // Ensure the random number is strictly within the desired bit length by masking
    // off any excess bits in the most significant word.
    if (num_bits % 64 != 0) {
        mpz_class mask = (mpz_class(1) << (num_bits % 64)) - 1;
        r &= mask;
    }
    return r;
}

/**
 * @brief  Encrypts a plaintext message 'm'.
 * @note   The encryption formula is: c = ((r*L + m) * (1 + r'*p)) mod N
 *         This structure supports homomorphic addition and multiplication.
 * @param  m   The plaintext message.
 * @param  sk  The secret key.
 * @return The encrypted ciphertext.
 */
mpz_class encrypt(const mpz_class& m, const SecretKey& sk) {
    // Generate two random numbers, 'r' and 'r_prime', for noise.
    // The bit sizes here are parameters of the scheme (k2 and k0).
    mpz_class r = generateRandom(80);
    mpz_class r_prime = generateRandom(4096);

    // Calculate c = (r*L + m) * (1 + r'*p) mod N
    mpz_class term1 = r * sk.L + m;
    mpz_class term2 = 1 + r_prime * sk.p;

    mpz_class c = (term1 * term2) % sk.N;

    return c;
}

/**
 * @brief  Decrypts a ciphertext 'c'.
 * @note   The decryption formula is: m = (c mod p) mod L
 *         This works because (1 + r'*p) mod p = 1.
 *         So, (c mod p) = ((r*L + m) * 1) mod p = (r*L + m) mod p.
 *         Since m is much smaller than L, and L is much smaller than p, this
 *         simplifies further.
 * @param  c   The ciphertext.
 * @param  sk  The secret key.
 * @return The decrypted plaintext.
 */
mpz_class decrypt(const mpz_class& c, const SecretKey& sk) {
    // Calculate m = (c mod p) mod L
    mpz_class m = (c % sk.p) % sk.L;
    return m;
}

// NOTE: The main() function and extensive test code have been removed to create a clean
// library implementation file. It is best practice to place testing code in a
// separate file (e.g., test_main.cpp) that links against this object file.