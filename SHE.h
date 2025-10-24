/*
 * =====================================================================================
 *
 *       Filename:  SHE.h
 *
 *    Description:  Public interface for the SHE scheme.
 *                  This header defines the SecretKey class and the core cryptographic
 *                  functions: encryption, decryption, and random number generation.
 *
 *        Version:  1.0
 * =====================================================================================
 */

#ifndef SHE_H
#define SHE_H

#include <gmpxx.h>

/**
 * @class SecretKey
 * @brief Holds the secret parameters for the SHE scheme.
 *
 * This class encapsulates the private and public parameters required for
 * encryption and decryption operations.
 */
class SecretKey {
public:
    /// A large prime number, part of the secret key.
    mpz_class p;
    /// Another large prime number, part of the secret key.
    mpz_class q;
    /// A random value, part of the secret key.
    mpz_class L;
    /// The public modulus, N = p * q.
    mpz_class N;

    /**
     * @brief  Constructs a SecretKey object.
     * @param  p  The first large prime.
     * @param  q  The second large prime.
     * @param  L  The plaintext space modulus.
     */
    SecretKey(const mpz_class& p, const mpz_class& q, const mpz_class& L);
};

/**
 * @brief  Generates a cryptographically suitable random number of k bits.
 * @param  k  The desired number of bits for the random number.
 * @return An mpz_class integer with approximately k random bits.
 */
mpz_class generateRandom(int k);

/**
 * @brief  Encrypts a plaintext message using the provided secret key.
 * @param  m   The plaintext message (an mpz_class integer) to be encrypted.
 *             It should be in the range [0, L-1].
 * @param  sk  A constant reference to the SecretKey.
 * @return The resulting ciphertext (an mpz_class integer).
 */
mpz_class encrypt(const mpz_class& m, const SecretKey& sk);

/**
 * @brief  Decrypts a ciphertext to retrieve the original message.
 * @param  c   The ciphertext (an mpz_class integer) to be decrypted.
 * @param  sk  A constant reference to the SecretKey.
 * @return The original plaintext message (an mpz_class integer).
 */
mpz_class decrypt(const mpz_class& c, const SecretKey& sk);

#endif // SHE_H