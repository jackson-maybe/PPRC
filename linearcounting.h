/*
 * =====================================================================================
 *
 *       Filename:  linearcounting.h
 *
 *    Description:  Public interface for the LinearCounting class.
 *                  This class provides a cardinality estimation sketch based on the
 *                  Linear Counting algorithm.
 *
 *        Version:  1.0
 *
 * =====================================================================================
 */

#ifndef LINEAR_COUNTING_H
#define LINEAR_COUNTING_H

// NOTE: <bits/stdc++.h> is a non-standard, compiler-specific header.
// For portable code, it's better to include only the necessary headers, such as:
// #include <vector>
// #include <string>
// #include <cmath>
#include <bits/stdc++.h>

#include "MurmurHash3.h"

/**
 * @class LinearCounting
 * @brief Implements the Linear Counting algorithm for estimating the number of
 *        distinct elements (cardinality) in a set.
 */
class LinearCounting {
public:
    /**
     * @brief  Constructs a new Linear Counting object.
     * @param  base  The size of the internal bit array (m). A larger size
     *               improves accuracy at the cost of more memory.
     */
    LinearCounting(int base);

    /**
     * @brief  Destroys the Linear Counting object.
     * @note   Resources are managed automatically by the std::vector member,
     *         so the destructor body is empty.
     */
    ~LinearCounting();

    /**
     * @brief  Adds a 2D data point to the sketch for counting.
     * @note   This method hashes the (x, y) pair and sets a corresponding
     *         bit in the internal bit array.
     * @param  seed  The seed for the MurmurHash3 function.
     * @param  x     The x-coordinate of the data point.
     * @param  y     The y-coordinate of the data point.
     */
    void insert(int seed, int x, int y);

    /**
     * @brief  Estimates the cardinality of the set of inserted items.
     * @note   This is a const method and does not modify the sketch's state.
     *         The estimation is based on the formula: -m * log(V / m),
     *         where V is the count of zero-bits.
     * @return A double-precision floating-point estimation of the number of
     *         distinct items.
     */
    double count() const;

private:
    /// The bit array used to record the presence of hash values.
    std::vector<unsigned int> bits;

    /// The total size of the bit array (m).
    int size;
};

#endif // LINEAR_COUNTING_H