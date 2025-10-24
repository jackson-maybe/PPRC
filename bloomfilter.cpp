/*
 * =====================================================================================
 *
 *       Filename:  bloom_filter.cpp
 *
 *    Description:  Implementation of a standard Bloom Filter data structure.
 *                  Provides functions for creation, insertion, checking, and
 *                  destruction of the filter.
 *
 *        Version:  1.0
 *       Revision:  none
 *
 *
 * =====================================================================================
 */

#include "bloomfilter.h"
#include "MurmurHash3.h"
#include <cmath>   // Required for log()
#include <string>  // Required for std::to_string
#include <cstdlib> // Required for malloc, calloc, free

// --- Internal Function Prototypes ---
// This function is intended for internal use within this file.
double hash_result(int data_id, int length, int seed);


/**
 * @brief  Creates and allocates a new Bloom Filter.
 * @note   The caller is responsible for freeing the allocated memory by calling
 *         destroy_bloom_filter() to prevent memory leaks.
 * @param  expected_elements    The anticipated number of items to be stored.
 * @param  false_positive_rate  The desired false positive probability (e.g., 0.01 for 1%).
 * @return A pointer to the newly created BloomFilter struct, or NULL on allocation failure.
 */
BloomFilter *create_bloom_filter(int expected_elements, double false_positive_rate) {
    // Calculate the optimal bit array size 'm' using the standard formula:
    // m = -(n * ln(p)) / (ln(2)^2)
    // where 'n' is expected_elements and 'p' is false_positive_rate.
    int size = (int)(-expected_elements * log(false_positive_rate) / (log(2) * log(2)));
    
    // Round up the size to the nearest multiple of 8. This is a common integer
    // arithmetic trick that can sometimes offer memory alignment benefits.
    size = (size + 7) / 8 * 8;

    // Allocate memory for the main BloomFilter struct.
    BloomFilter *filter = (BloomFilter*)malloc(sizeof(BloomFilter));
    if (filter == NULL) {
        // Return NULL if memory allocation for the struct fails.
        return NULL;
    }

    // Allocate memory for the bit array. calloc is used to initialize all bits to zero.
    filter->bits = (int*)calloc(size, sizeof(int));
    if (filter->bits == NULL) {
        // If bit array allocation fails, free the already allocated struct and return NULL.
        free(filter);
        return NULL;
    }
    
    filter->size = size;
    
    // Set the number of hash functions.
    // NOTE: A fixed value is used for simplicity. For a truly optimal filter, this
    // should be calculated dynamically using the formula: k = (m / n) * ln(2).
    filter->hash_count = 7;
    
    return filter;
}

/**
 * @brief  Inserts an element into the Bloom Filter.
 * @note   This operation is idempotent; inserting the same element multiple
 *         times has no additional effect.
 * @param  bf         A pointer to a valid BloomFilter instance.
 * @param  data_id    The integer element to be added to the set.
 */
void bloom_filter_insert(BloomFilter *bf, int data_id) {
    // For each hash function, calculate a hash value and set the corresponding bit.
    for (int i = 0; i < bf->hash_count; ++i) {
        // A different seed (i) is used for each iteration to simulate multiple hash functions.
        int bit_index = (int)hash_result(data_id, bf->size, i);
        // Set the bit at the computed index to 1.
        bf->bits[bit_index] = 1;
    }
}

/**
 * @brief  Checks if an element is possibly in the set represented by the Bloom Filter.
 * @note   A return value of 'false' guarantees the element is not in the set.
 *         A return value of 'true' indicates the element is *probably* in the set,
 *         but it could be a false positive.
 * @param  bf         A pointer to a valid BloomFilter instance.
 * @param  data_id    The integer element to check.
 * @return `true` if the element may be in the set, `false` otherwise.
 */
bool bloom_filter_contains(BloomFilter *bf, int data_id) {
    for (int i = 0; i < bf->hash_count; ++i) {
        int bit_index = (int)hash_result(data_id, bf->size, i);
        // If any of the bits at the hashed indices is 0, the element is
        // guaranteed to not be in the set.
        if (bf->bits[bit_index] == 0) {
            return false;
        }
    }
    
    // If all bits at all hashed indices are 1, the element is considered to be in the set.
    return true;
}

/**
 * @brief  Frees all memory associated with a Bloom Filter.
 * @note   This function safely handles being called with a NULL pointer.
 * @param  bf    A pointer to the BloomFilter struct to be destroyed.
 */
void destroy_bloom_filter(BloomFilter *bf) {
    // Check for NULL pointer to prevent segfaults on double-free or freeing a NULL pointer.
    if (bf != NULL) {
        // The bit array must be freed first.
        free(bf->bits);
        // Then, the container struct itself can be freed.
        free(bf);
    }
}

/**
 * @brief  Internal helper function to compute a single hash value.
 * @note   This function uses the MurmurHash3 algorithm to generate a hash.
 *         It is not intended to be called directly from outside this file.
 * @param  data_id    The integer data to be hashed.
 * @param  length     The size of the bit array, used to map the hash to a valid index.
 * @param  seed       The seed for the MurmurHash3 function.
 * @return The resulting hash value, scaled to the range [0, length-1].
 */
double hash_result(int data_id, int length, int seed) {
    uint32_t hash_output;
    
    // Construct a key from the data and filter properties to ensure hash uniqueness
    // across filters of different sizes.
    std::string key = std::to_string(data_id) + "|" + std::to_string(length);
    
    // Execute the MurmurHash3 32-bit algorithm.
    MurmurHash3_x86_32(key.c_str(), key.size(), seed, &hash_output);
    
    // Use the modulo operator to map the 32-bit hash output to a valid
    // index within the bit array's bounds.
    return hash_output % length;
}