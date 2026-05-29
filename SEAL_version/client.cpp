#include "common.h"
#include "bloomfilter.h"
#include "MurmurHash3.h"
#include <sstream>
#include <cmath>
#include <omp.h>

using namespace std;
using namespace seal;

int main(int argc, char* argv[]) {
    if (argc != 3) { cerr << "Usage: ./client <center_ip> <center_port>\n"; return 1; }

   

   
    SEALContext context = create_fhe_context();
    KeyGenerator keygen(context); SecretKey sk = keygen.secret_key();
    PublicKey pk; keygen.create_public_key(pk); RelinKeys rk; keygen.create_relin_keys(rk); GaloisKeys gal_keys; keygen.create_galois_keys(gal_keys);

    BatchEncoder encoder(context); Decryptor decryptor(context, sk);

    
    

    double fpr = 0.0001; int expected_elements = 100;
    BloomFilter* bf_x = create_bloom_filter(expected_elements, fpr);
    BloomFilter* bf_y = create_bloom_filter(expected_elements, fpr);
    int M = bf_x->size; 

    int min_range = 0; int max_range = 100; 
    for (int x = min_range+99; x <= max_range+99; x++) bloom_filter_insert(bf_x, x);
    for (int y = min_range+299; y <= max_range+299; y++) bloom_filter_insert(bf_y, y);

    int SLOT_COUNT = encoder.slot_count();
    vector<uint64_t> vec_x(SLOT_COUNT, 0ULL); vector<uint64_t> vec_y(SLOT_COUNT, 0ULL);
    
    int count_1 = 0;
    for (int m = 0; m < M; m++) { 
        vec_x[m] = (bf_x->bits[m] != 0) ? 1ULL : 0ULL; 
        vec_y[m] = (bf_y->bits[m] != 0) ? 1ULL : 0ULL; 
        if (vec_x[m] == 1) count_1++;
    }

    

    

    Ciphertext enc_bf_x, enc_bf_y; string str_bf_x, str_bf_y;
    #pragma omp parallel sections
    {
        #pragma omp section
        {
            Encryptor local_enc(context, pk); Plaintext pt_x; encoder.encode(vec_x, pt_x);
            local_enc.encrypt(pt_x, enc_bf_x); stringstream sx; enc_bf_x.save(sx); str_bf_x = sx.str();
        }
        #pragma omp section
        {
            Encryptor local_enc(context, pk); Plaintext pt_y; encoder.encode(vec_y, pt_y);
            local_enc.encrypt(pt_y, enc_bf_y); stringstream sy; enc_bf_y.save(sy); str_bf_y = sy.str();
        }
    }
    
    

    
    
    stringstream ss_out;
    pk.save(ss_out); rk.save(ss_out); gal_keys.save(ss_out);
    
    ss_out.write(reinterpret_cast<const char*>(&M), sizeof(M));
    uint64_t size_x = str_bf_x.size(); uint64_t size_y = str_bf_y.size();
    ss_out.write(reinterpret_cast<const char*>(&size_x), sizeof(size_x)); ss_out.write(str_bf_x.c_str(), size_x);
    ss_out.write(reinterpret_cast<const char*>(&size_y), sizeof(size_y)); ss_out.write(str_bf_y.c_str(), size_y);

    boost::asio::io_context io_context; tcp::socket socket(io_context); tcp::resolver resolver(io_context);
    boost::asio::connect(socket, resolver.resolve(argv[1], argv[2]));
    
    string send_payload = ss_out.str();
    
    send_data(socket, send_payload);

    string result_data = receive_data(socket); 
    
    const char* ptr = result_data.data();
    uint64_t S; 
    memcpy(&S, ptr, sizeof(S));
    ptr += sizeof(S);

    

    
    

    
    

    vector<const seal::seal_byte*> block_ptrs(S);
    vector<uint64_t> block_lens(S);
    
    for (uint64_t s = 0; s < S; s++) {
        memcpy(&block_lens[s], ptr, sizeof(uint64_t));
        ptr += sizeof(uint64_t);
        block_ptrs[s] = reinterpret_cast<const seal::seal_byte*>(ptr);
        ptr += block_lens[s];
    }

    int S_prime = 0;
    
    
    int K = 5;
    int SHIFT_BITS = 9;
    uint64_t BIT_MASK = (1ULL << SHIFT_BITS) - 1;

    #pragma omp parallel
    {
        Decryptor local_decryptor(context, sk);
        BatchEncoder local_encoder(context);
        
        #pragma omp for schedule(dynamic)
        for (uint64_t s = 0; s < S; s++) {
            Ciphertext ct_bucket; 
            ct_bucket.load(context, block_ptrs[s], block_lens[s]);

            Plaintext pt_res; 
            local_decryptor.decrypt(ct_bucket, pt_res);
            
            vector<uint64_t> dec_val; 
            local_encoder.decode(pt_res, dec_val);

            
            for(int k = 0; k < K; k++) {
                if (s * K + k >= SKETCH_SIZE) break; // 防越界
                
                uint64_t bucket_sum = 0;
                for (auto val : dec_val) {
                    uint64_t extracted_val = (val >> (SHIFT_BITS * k)) & BIT_MASK;
                    bucket_sum += extracted_val;
                }

                if (bucket_sum == 0) {
                    #pragma omp atomic
                    S_prime++;
                }
            }
        }
    }

    double RC = - (double)SKETCH_SIZE * log((double)S_prime / SKETCH_SIZE);
    
    
    
    
    
    

    destroy_bloom_filter(bf_x); destroy_bloom_filter(bf_y);
    return 0;
}


