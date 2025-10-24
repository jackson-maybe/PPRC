/*
 * =====================================================================================
 *
 *       Filename:  linearcounting.cpp
 *
 *    Description:  Implementation of the LinearCounting class.
 *
 *        Version:  1.0
 *        
 *
 *        
 *
 * =====================================================================================
 */

#include "linearcounting.h"
#include <cstdlib> // Included but not used in the provided functions.

/**
 * @brief  Constructor implementation.
 * @param  base  The desired size of the bit array.
 */
LinearCounting::LinearCounting(int base) : size(base), bits(base, 0) {
    // The member initializer list is used here for efficient construction.
    // 'size' is initialized with 'base'.
    // 'bits' is constructed as a std::vector of size 'base', with all elements initialized to 0.
}

/**
 * @brief  Destructor implementation.
 */
LinearCounting::~LinearCounting() {
    // No explicit memory management is needed here.
    // The 'bits' std::vector will automatically deallocate its memory
    // when the LinearCounting object goes out of scope (RAII principle).
}

/**
 * @brief  Inserts a 2D point into the sketch.
 * @param  seed  The seed for the hash function.
 * @param  x     The x-coordinate.
 * @param  y     The y-coordinate.
 */
void LinearCounting::insert(int seed, int x, int y) {
    uint32_t hash_result;

    // Create a unique string key from the (x, y) pair to treat it as a single item.
    // The "|" separator prevents collisions, e.g., (12, 3) vs (1, 23).
    std::string key = std::to_string(x) + "|" + std::to_string(y);

    // Compute the hash using the MurmurHash3 algorithm.
    MurmurHash3_x86_32(key.c_str(), key.size(), seed, &hash_result);

    // Map the 32-bit hash value to a valid index in the bit array.
    int bit_index = hash_result % size;

    // Set the bit at the calculated index to 1, marking this hash bucket as "occupied".
    bits[bit_index] = 1;
}

/**
 * @brief  Estimates the cardinality based on the current state of the bit array.
 * @return The estimated number of distinct items.
 */
double LinearCounting::count() const {
    double num_zeros = 0;

    // Step 1: Count the number of empty buckets (bits that are still 0).
    // This is often denoted as 'V' in the algorithm's description.
    for (int i = 0; i < size; i++) {
        if (bits[i] == 0) {
            num_zeros++;
        }
    }

    // Step 2: Apply the Linear Counting estimation formula: -m * log(V / m).
    // where m = size and V = num_zeros.
    // A static_cast is used to ensure floating-point division.
    return -size * log(num_zeros / static_cast<double>(size));
}