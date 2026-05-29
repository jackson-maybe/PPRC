#ifndef BLOOMFILTER_H
#define BLOOMFILTER_H

#include <iostream>
#include <string>
#include <cmath>
#include <cstdint>


typedef struct {
    int *bits; 
    int size;      
    int hash_count;   
} BloomFilter;


BloomFilter *create_bloom_filter(int expected_elements, double false_positive_rate);


void bloom_filter_insert(BloomFilter *bf, int data_id);


bool bloom_filter_maybe_contains(BloomFilter *bf, int data_id);


void destroy_bloom_filter(BloomFilter *bf);


double hash_result(int data_id, int length, int seed);

#endif // SKETCHMETHOD_H
