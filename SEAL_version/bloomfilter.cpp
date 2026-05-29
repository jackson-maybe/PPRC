#include "bloomfilter.h"
#include "MurmurHash3.h"


BloomFilter *create_bloom_filter(int expected_elements, double false_positive_rate) {
    
    // 直接构建
    BloomFilter *filter = (BloomFilter*)malloc(sizeof(BloomFilter)); 
    filter->hash_count = 3; 
    

    double K = (double)filter->hash_count;
    double mu = (double)expected_elements;
    double fp = false_positive_rate;
    double M = (-K * mu) / log(1.0 - pow(fp, 1.0 / K));
    int size = (int)ceil(M);

    filter->bits = (int*)calloc(size, sizeof(int));
    filter->size = size;
    

    return filter;
}


void bloom_filter_insert(BloomFilter *bf, int data_id) {
    for (int i = 0; i < bf->hash_count; ++i) {
        int bit_index = (int)hash_result(data_id, bf->size, i); 
        bf->bits[bit_index] = 1;  
    }
}


bool bloom_filter_maybe_contains(BloomFilter *bf, int data_id) {
    for (int i = 0; i < bf->hash_count; ++i) {
        int bit_index = (int)hash_result(data_id, bf->size, i);
        if ((bf->bits[bit_index]) == 0) { 
            return false;
        }
    }
    return true; 
}

// �ͷŲ�¡��������Դ
void destroy_bloom_filter(BloomFilter *bf) {
    free(bf->bits);
    free(bf);
}


double hash_result(int data_id, int length, int seed) {
    uint32_t hash_result;
    std::string key = std::to_string(data_id) + "|" + std::to_string(length);
    MurmurHash3_x86_32(key.c_str(), key.size(), seed, &hash_result);
    return hash_result % length;
}


