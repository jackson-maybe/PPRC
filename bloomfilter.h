/*
 * =====================================================================================
 *
 *       Filename:  bloomfilter.h
 *
 *    Description:  Public interface for the Bloom Filter module.
 *                  This header file defines the data structures and function
 *                  prototypes for creating and interacting with a Bloom Filter.
 *
 *        Version:  1.0
 *       Revision:  none
 *
 *
 * =====================================================================================
 */

#ifndef BLOOMFILTER_H
#define BLOOMFILTER_H

#include <iostream>
#include <string>
#include <cmath>
#include <cstdint>
#include <stdbool.h> // Include for C-style 'bool' type if not in a C++ context

/**
 * @struct BloomFilter
 * @brief  The core data structure for a Bloom Filter.
 * @var    bits        A pointer to the dynamically allocated bit array.
 * @var    size        The total number of bits in the bit array.
 * @var    hash_count  The number of hash functions (k) to be used.
 */
typedef struct {
    int *bits;       // Pointer to the bit array.
    int size;        // The size of the bit array (m).
    int hash_count;  // The number of hash functions to use (k).
} BloomFilter;


/**
 * @brief  Creates and allocates a new Bloom Filter.
 * @note   The caller is responsible for freeing the allocated memory by calling
 *         destroy_bloom_filter() to prevent memory leaks.
 * @param  expected_elements    The anticipated number of items to be stored.
 * @param  false_positive_rate  The desired false positive probability (e.g., 0.01 for 1%).
 * @return A pointer to the newly created BloomFilter struct, or NULL on allocation failure.
 */
BloomFilter *create_bloom_filter(int expected_elements, double false_positive_rate);


/**
 * @brief  Inserts an element into the Bloom Filter.
 * @param  bf         A pointer to a valid BloomFilter instance created by create_bloom_filter().
 * @param  data_id    The integer element to be added to the set.
 */
void bloom_filter_insert(BloomFilter *bf, int data_id);


/**
 * @brief  Checks if an element is possibly in the set represented by the Bloom Filter.
 * @note   A return value of 'false' guarantees the element is not in the set.
 *         A return value of 'true' indicates the element is *probably* in the set,
 *         but it could be a false positive.
 * @param  bf         A pointer to a valid BloomFilter instance.
 * @param  data_id    The integer element to check.
 * @return `true` if the element may be in the set, `false` otherwise.
 */
bool bloom_filter_contains(BloomFilter *bf, int data_id);



/**
 * @brief  Frees all memory associated with a Bloom Filter.
 * @note   It is safe to call this function with a NULL pointer.
 * @param  bf    A pointer to the BloomFilter struct to be destroyed.
 */
void destroy_bloom_filter(BloomFilter *bf);


/**
 * @brief  Computes a hash value for a given data ID using a specific seed.
 * @note   This function is used internally by the filter's operations but is
 *         exposed as a public utility.
 * @param  data_id    The integer data to be hashed.
 * @param  length     The size of the bit array, used to map the hash to a valid index.
 * @param  seed       The seed for the hash function.
 * @return The resulting hash value, scaled to the range [0, length-1].
 */
double hash_result(int data_id, int length, int seed);

#endif // BLOOMFILTER_H