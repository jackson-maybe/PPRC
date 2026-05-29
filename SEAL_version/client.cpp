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

    auto start_time = std::chrono::high_resolution_clock::now();

    cout << "=====================================================" << endl;
    cout << "[Client] 初始化 BFV 探针版环境..." << endl;
    SEALContext context = create_fhe_context();
    KeyGenerator keygen(context); SecretKey sk = keygen.secret_key();
    PublicKey pk; keygen.create_public_key(pk); RelinKeys rk; keygen.create_relin_keys(rk); GaloisKeys gal_keys; keygen.create_galois_keys(gal_keys);

    BatchEncoder encoder(context); Decryptor decryptor(context, sk);

    // 阶段1  构造bloom filter结构
    auto start = std::chrono::high_resolution_clock::now();

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

    cout << "\n[DEBUG-Client] BF 长度: " << M << ", 置 1 个数: " << count_1 << endl;
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration = end - start;
    std::cout << "Phase 1: the time is " << duration.count()/1000 << " s\n";
    
    // 阶段2  加密 BloomFilter结构
    start = std::chrono::high_resolution_clock::now();

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
    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "Phase 2: the time is " << duration.count()/1000 << " s\n";

    // 阶段3 将密文打包并传输，并接收结果
    start = std::chrono::high_resolution_clock::now();
    stringstream ss_out;
    // 【关键】私钥 sk 已移除，绝不发送
    pk.save(ss_out); rk.save(ss_out); gal_keys.save(ss_out);
    
    ss_out.write(reinterpret_cast<const char*>(&M), sizeof(M));
    uint64_t size_x = str_bf_x.size(); uint64_t size_y = str_bf_y.size();
    ss_out.write(reinterpret_cast<const char*>(&size_x), sizeof(size_x)); ss_out.write(str_bf_x.c_str(), size_x);
    ss_out.write(reinterpret_cast<const char*>(&size_y), sizeof(size_y)); ss_out.write(str_bf_y.c_str(), size_y);

    boost::asio::io_context io_context; tcp::socket socket(io_context); tcp::resolver resolver(io_context);
    boost::asio::connect(socket, resolver.resolve(argv[1], argv[2]));
    
    string send_payload = ss_out.str();
    cout << "[Comm] Client 发送的请求数据量 (Keys + BloomFilters): " << send_payload.size() / 1024.0 / 1024.0 << " MB" << endl;
    cout << "[Client] 密文已发送，等待 Server 计算..." << endl;
    send_data(socket, send_payload);

    string result_data = receive_data(socket); 
    cout << "[Comm] Client 接收的响应数据量 (压缩打包后的 Sketch 块): " << result_data.size() / 1024.0 / 1024.0 << " MB" << endl;
    const char* ptr = result_data.data();
    uint64_t S; // 这里的 S 是 PACKED_SIZE
    memcpy(&S, ptr, sizeof(S));
    ptr += sizeof(S);

    cout << "[Client] 接收到打乱后的密文块 List，块数: " << S << "，开始位解析与解密..." << endl;

    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "Phase 3 (Network Recv): the time is " << duration.count()/1000.0 << " s\n";

    // ==========================================
    // 阶段4：直接内存提取、并发解密与大整数拆包
    // ==========================================
    start = std::chrono::high_resolution_clock::now();

    vector<const seal::seal_byte*> block_ptrs(S);
    vector<uint64_t> block_lens(S);
    
    for (uint64_t s = 0; s < S; s++) {
        memcpy(&block_lens[s], ptr, sizeof(uint64_t));
        ptr += sizeof(uint64_t);
        block_ptrs[s] = reinterpret_cast<const seal::seal_byte*>(ptr);
        ptr += block_lens[s];
    }

    int S_prime = 0;
    
    // 【核心】位拆解参数 (K=5 桶绑定)
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

            // 从 1 个解密后的块中，拆解出 K 个独立的桶
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
    
    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "Phase 4 (Concurrent Decrypt & Unpack): the time is " << duration.count()/1000.0 << " s\n";

    cout << "\n================ 最终统计结果 ================" << endl;
    cout << "  - 零桶数量 (S_prime): " << S_prime << endl;
    cout << "  - 范围内估算数量 (Estimated RC): " << RC << endl;
    cout << "=====================================================\n" << endl;
    
    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration_t = end_time - start_time;
    std::cout << "The overall time is " << duration_t.count()/1000.0 << " s\n";

    destroy_bloom_filter(bf_x); destroy_bloom_filter(bf_y);
    return 0;
}








// #include "common.h"
// #include "bloomfilter.h"
// #include "MurmurHash3.h"
// #include <sstream>
// #include <cmath>
// #include <omp.h>

// using namespace std;
// using namespace seal;

// // 最终版，无打包

// int main(int argc, char* argv[]) {
//     if (argc != 3) { cerr << "Usage: ./client <center_ip> <center_port>\n"; return 1; }

//     auto start_time = std::chrono::high_resolution_clock::now();

//     cout << "=====================================================" << endl;
//     cout << "[Client] 初始化 BFV 探针版环境..." << endl;
//     SEALContext context = create_fhe_context();
//     KeyGenerator keygen(context); SecretKey sk = keygen.secret_key();
//     PublicKey pk; keygen.create_public_key(pk); RelinKeys rk; keygen.create_relin_keys(rk); GaloisKeys gal_keys; keygen.create_galois_keys(gal_keys);

//     BatchEncoder encoder(context); Decryptor decryptor(context, sk);

//     // 阶段1  构造bloom filter结构
//     auto start = std::chrono::high_resolution_clock::now();

//     double fpr = 0.0001; int expected_elements = 100;
//     BloomFilter* bf_x = create_bloom_filter(expected_elements, fpr);
//     BloomFilter* bf_y = create_bloom_filter(expected_elements, fpr);
//     int M = bf_x->size; 

//     int min_range = 0; int max_range = 100; 
//     for (int x = min_range+99; x <= max_range+99; x++) bloom_filter_insert(bf_x, x);
//     for (int y = min_range+299; y <= max_range+299; y++) bloom_filter_insert(bf_y, y);

//     int SLOT_COUNT = encoder.slot_count();
//     vector<uint64_t> vec_x(SLOT_COUNT, 0ULL); vector<uint64_t> vec_y(SLOT_COUNT, 0ULL);
    
//     int count_1 = 0;
//     for (int m = 0; m < M; m++) { 
//         vec_x[m] = (bf_x->bits[m] != 0) ? 1ULL : 0ULL; 
//         vec_y[m] = (bf_y->bits[m] != 0) ? 1ULL : 0ULL; 
//         if (vec_x[m] == 1) count_1++;
//     }






//     cout << "\n[DEBUG-Client] BF 长度: " << M << ", 置 1 个数: " << count_1 << endl;
//     auto end = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration = end - start;
//     std::cout << "Phase 1: the time is " << duration.count()/1000 << " s\n";
    
//     // 阶段2  加密 BloomFilter结构
//     start = std::chrono::high_resolution_clock::now();


//     Ciphertext enc_bf_x, enc_bf_y; string str_bf_x, str_bf_y;
//     #pragma omp parallel sections
//     {
//         #pragma omp section
//         {
//             Encryptor local_enc(context, pk); Plaintext pt_x; encoder.encode(vec_x, pt_x);
//             local_enc.encrypt(pt_x, enc_bf_x); stringstream sx; enc_bf_x.save(sx); str_bf_x = sx.str();
//         }
//         #pragma omp section
//         {
//             Encryptor local_enc(context, pk); Plaintext pt_y; encoder.encode(vec_y, pt_y);
//             local_enc.encrypt(pt_y, enc_bf_y); stringstream sy; enc_bf_y.save(sy); str_bf_y = sy.str();
//         }
//     }
//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 2: the time is " << duration.count()/1000 << " s\n";


//     // 阶段3 将密文打包并传输，并接收结果
//     start = std::chrono::high_resolution_clock::now();
//     stringstream ss_out;
//     pk.save(ss_out); rk.save(ss_out); gal_keys.save(ss_out);
    

//     ss_out.write(reinterpret_cast<const char*>(&M), sizeof(M));
//     uint64_t size_x = str_bf_x.size(); uint64_t size_y = str_bf_y.size();
//     ss_out.write(reinterpret_cast<const char*>(&size_x), sizeof(size_x)); ss_out.write(str_bf_x.c_str(), size_x);
//     ss_out.write(reinterpret_cast<const char*>(&size_y), sizeof(size_y)); ss_out.write(str_bf_y.c_str(), size_y);

//     boost::asio::io_context io_context; tcp::socket socket(io_context); tcp::resolver resolver(io_context);
//     boost::asio::connect(socket, resolver.resolve(argv[1], argv[2]));
//     string send_payload = ss_out.str();
//     cout << "[Comm] Client 发送的请求数据量 (Keys + BloomFilters): " << send_payload.size() / 1024.0 / 1024.0 << " MB" << endl;
//     cout << "[Client] 密文已发送，等待 Server 计算..." << endl;
//     send_data(socket, ss_out.str());

//     string result_data = receive_data(socket); 
//     cout << "[Comm] Client 接收的响应数据量 (Sketch 密文桶): " << result_data.size() / 1024.0 / 1024.0 << " MB" << endl;
//     const char* ptr = result_data.data();
//     uint64_t S;
//     memcpy(&S, ptr, sizeof(S));
//     ptr += sizeof(S);

//     cout << "[Client] 接收到打乱后的密文 List，长度: " << S << "，开始解析与解密..." << endl;

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3 (Network Recv): the time is " << duration.count()/1000.0 << " s\n";

//     // ==========================================
//     // 阶段4：直接内存提取与并发解密
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();

//     // 1. 快速遍历一遍内存，把所有密文的起始指针和长度提取出来
//     // 这一步必须单线程，因为每个块的长度不一
//     vector<const seal::seal_byte*> block_ptrs(S);
//     vector<uint64_t> block_lens(S);
    
//     for (uint64_t s = 0; s < S; s++) {
//         memcpy(&block_lens[s], ptr, sizeof(uint64_t));
//         ptr += sizeof(uint64_t);
        
//         block_ptrs[s] = reinterpret_cast<const seal::seal_byte*>(ptr);
//         ptr += block_lens[s];
//     }

//     int S_prime = 0;

//     // 2. 开启 OpenMP 并发，直接从内存块加载并解密 (绕过 stringstream)
//     #pragma omp parallel reduction(+:S_prime)
//     {
//         // Decryptor 和 BatchEncoder 不是完全线程安全的，必须实例化线程局部副本
//         Decryptor local_decryptor(context, sk);
//         BatchEncoder local_encoder(context);
        
//         #pragma omp for schedule(dynamic)
//         for (uint64_t s = 0; s < S; s++) {
//             Ciphertext ct_bucket; 
//             // 核心优化：直接从连续内存块(seal_byte*)加载，内置 ZSTD 解压自动生效
//             ct_bucket.load(context, block_ptrs[s], block_lens[s]);

//             Plaintext pt_res; 
//             local_decryptor.decrypt(ct_bucket, pt_res);
            
//             vector<uint64_t> dec_val; 
//             local_encoder.decode(pt_res, dec_val);

//             uint64_t bucket_sum = 0;
//             for (auto val : dec_val) {
//                 bucket_sum += val;
//             }

//             if (bucket_sum == 0) {
//                 S_prime++;
//             }
//         }
//     }

//     double RC = - (double)SKETCH_SIZE * log((double)S_prime / SKETCH_SIZE);
    
//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 4 (Concurrent Decrypt & Decode): the time is " << duration.count()/1000.0 << " s\n";

//     cout << "\n================ 最终统计结果 ================" << endl;
//     cout << "  - 零桶数量 (S_prime): " << S_prime << endl;
//     cout << "  - 范围内估算数量 (Estimated RC): " << RC << endl;
//     cout << "=====================================================\n" << endl;
    
//     auto end_time = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration_t = end_time - start_time;
//     std::cout << "The overall time is " << duration_t.count()/1000.0 << " s\n";

//     destroy_bloom_filter(bf_x); destroy_bloom_filter(bf_y);
//     return 0;
// }


// #include "common.h"
// #include "bloomfilter.h"
// #include "MurmurHash3.h"
// #include <sstream>
// #include <cmath>
// #include <omp.h>

// using namespace std;
// using namespace seal;

// // 这版的问题，去重不够简洁
// // 最后才解决传输sk问题
// // 这版改的是通信过程

// int main(int argc, char* argv[]) {
//     if (argc != 3) { cerr << "Usage: ./client <center_ip> <center_port>\n"; return 1; }

//     auto start_time = std::chrono::high_resolution_clock::now();

//     cout << "=====================================================" << endl;
//     cout << "[Client] 初始化 BFV 探针版环境..." << endl;
//     SEALContext context = create_fhe_context();
//     KeyGenerator keygen(context); SecretKey sk = keygen.secret_key();
//     PublicKey pk; keygen.create_public_key(pk); RelinKeys rk; keygen.create_relin_keys(rk); GaloisKeys gal_keys; keygen.create_galois_keys(gal_keys);

//     BatchEncoder encoder(context); Decryptor decryptor(context, sk);

//     // 阶段1  构造bloom filter结构
//     auto start = std::chrono::high_resolution_clock::now();

//     double fpr = 0.01; int expected_elements = 100;
//     BloomFilter* bf_x = create_bloom_filter(expected_elements, fpr);
//     BloomFilter* bf_y = create_bloom_filter(expected_elements, fpr);
//     int M = bf_x->size; 

//     int min_range = 0; int max_range = 100; 
//     for (int x = min_range+99; x <= max_range+99; x++) bloom_filter_insert(bf_x, x);
//     for (int y = min_range+299; y <= max_range+299; y++) bloom_filter_insert(bf_y, y);

//     int SLOT_COUNT = encoder.slot_count();
//     vector<uint64_t> vec_x(SLOT_COUNT, 0ULL); vector<uint64_t> vec_y(SLOT_COUNT, 0ULL);
    
//     int count_1 = 0;
//     for (int m = 0; m < M; m++) { 
//         vec_x[m] = (bf_x->bits[m] != 0) ? 1ULL : 0ULL; 
//         vec_y[m] = (bf_y->bits[m] != 0) ? 1ULL : 0ULL; 
//         if (vec_x[m] == 1) count_1++;
//     }






//     cout << "\n[DEBUG-Client] BF 长度: " << M << ", 置 1 个数: " << count_1 << endl;
//     auto end = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration = end - start;
//     std::cout << "Phase 1: the time is " << duration.count()/1000 << " s\n";
    
//     // 阶段2  加密 BloomFilter结构
//     start = std::chrono::high_resolution_clock::now();


//     Ciphertext enc_bf_x, enc_bf_y; string str_bf_x, str_bf_y;
//     #pragma omp parallel sections
//     {
//         #pragma omp section
//         {
//             Encryptor local_enc(context, pk); Plaintext pt_x; encoder.encode(vec_x, pt_x);
//             local_enc.encrypt(pt_x, enc_bf_x); stringstream sx; enc_bf_x.save(sx); str_bf_x = sx.str();
//         }
//         #pragma omp section
//         {
//             Encryptor local_enc(context, pk); Plaintext pt_y; encoder.encode(vec_y, pt_y);
//             local_enc.encrypt(pt_y, enc_bf_y); stringstream sy; enc_bf_y.save(sy); str_bf_y = sy.str();
//         }
//     }
//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 2: the time is " << duration.count()/1000 << " s\n";


//     // 阶段3 将密文打包并传输，并接收结果
//     start = std::chrono::high_resolution_clock::now();
//     stringstream ss_out;
//     pk.save(ss_out); rk.save(ss_out); gal_keys.save(ss_out);
//     sk.save(ss_out); // 发送私钥供打印

//     ss_out.write(reinterpret_cast<const char*>(&M), sizeof(M));
//     uint64_t size_x = str_bf_x.size(); uint64_t size_y = str_bf_y.size();
//     ss_out.write(reinterpret_cast<const char*>(&size_x), sizeof(size_x)); ss_out.write(str_bf_x.c_str(), size_x);
//     ss_out.write(reinterpret_cast<const char*>(&size_y), sizeof(size_y)); ss_out.write(str_bf_y.c_str(), size_y);

//     boost::asio::io_context io_context; tcp::socket socket(io_context); tcp::resolver resolver(io_context);
//     boost::asio::connect(socket, resolver.resolve(argv[1], argv[2]));
//     cout << "[Client] 密文与私钥已发送，等待 Server 打印内部日志..." << endl;
//     send_data(socket, ss_out.str());

//     string result_data = receive_data(socket); 
    
//     const char* ptr = result_data.data();
//     uint64_t S;
//     memcpy(&S, ptr, sizeof(S));
//     ptr += sizeof(S);

//     cout << "[Client] 接收到打乱后的密文 List，长度: " << S << "，开始解析与解密..." << endl;

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3 (Network Recv): the time is " << duration.count()/1000.0 << " s\n";

//     // ==========================================
//     // 阶段4：直接内存提取与并发解密
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();

//     // 1. 快速遍历一遍内存，把所有密文的起始指针和长度提取出来
//     // 这一步必须单线程，因为每个块的长度不一
//     vector<const seal::seal_byte*> block_ptrs(S);
//     vector<uint64_t> block_lens(S);
    
//     for (uint64_t s = 0; s < S; s++) {
//         memcpy(&block_lens[s], ptr, sizeof(uint64_t));
//         ptr += sizeof(uint64_t);
        
//         block_ptrs[s] = reinterpret_cast<const seal::seal_byte*>(ptr);
//         ptr += block_lens[s];
//     }

//     int S_prime = 0;

//     // 2. 开启 OpenMP 并发，直接从内存块加载并解密 (绕过 stringstream)
//     #pragma omp parallel reduction(+:S_prime)
//     {
//         // Decryptor 和 BatchEncoder 不是完全线程安全的，必须实例化线程局部副本
//         Decryptor local_decryptor(context, sk);
//         BatchEncoder local_encoder(context);
        
//         #pragma omp for schedule(dynamic)
//         for (uint64_t s = 0; s < S; s++) {
//             Ciphertext ct_bucket; 
//             // 核心优化：直接从连续内存块(seal_byte*)加载，内置 ZSTD 解压自动生效
//             ct_bucket.load(context, block_ptrs[s], block_lens[s]);

//             Plaintext pt_res; 
//             local_decryptor.decrypt(ct_bucket, pt_res);
            
//             vector<uint64_t> dec_val; 
//             local_encoder.decode(pt_res, dec_val);

//             uint64_t bucket_sum = 0;
//             for (auto val : dec_val) {
//                 bucket_sum += val;
//             }

//             if (bucket_sum == 0) {
//                 S_prime++;
//             }
//         }
//     }

//     double RC = - (double)SKETCH_SIZE * log((double)S_prime / SKETCH_SIZE);
    
//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 4 (Concurrent Decrypt & Decode): the time is " << duration.count()/1000.0 << " s\n";

//     cout << "\n================ 最终统计结果 ================" << endl;
//     cout << "  - 零桶数量 (S_prime): " << S_prime << endl;
//     cout << "  - 范围内估算数量 (Estimated RC): " << RC << endl;
//     cout << "=====================================================\n" << endl;
    
//     auto end_time = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration_t = end_time - start_time;
//     std::cout << "The overall time is " << duration_t.count()/1000.0 << " s\n";

//     destroy_bloom_filter(bf_x); destroy_bloom_filter(bf_y);
//     return 0;
// }











// #include "common.h"
// #include "bloomfilter.h"
// #include "MurmurHash3.h"
// #include <sstream>
// #include <cmath>
// #include <omp.h>

// using namespace std;
// using namespace seal;

// // 这版的问题，去重不够简洁
// // 最后才解决传输sk问题

// int main(int argc, char* argv[]) {
//     if (argc != 3) { cerr << "Usage: ./client <center_ip> <center_port>\n"; return 1; }

//     auto start_time = std::chrono::high_resolution_clock::now();

//     cout << "=====================================================" << endl;
//     cout << "[Client] 初始化 BFV 探针版环境..." << endl;
//     SEALContext context = create_fhe_context();
//     KeyGenerator keygen(context); SecretKey sk = keygen.secret_key();
//     PublicKey pk; keygen.create_public_key(pk); RelinKeys rk; keygen.create_relin_keys(rk); GaloisKeys gal_keys; keygen.create_galois_keys(gal_keys);

//     BatchEncoder encoder(context); Decryptor decryptor(context, sk);

//     // 阶段1  构造bloom filter结构
//     auto start = std::chrono::high_resolution_clock::now();

//     double fpr = 0.01; int expected_elements = 100;
//     BloomFilter* bf_x = create_bloom_filter(expected_elements, fpr);
//     BloomFilter* bf_y = create_bloom_filter(expected_elements, fpr);
//     int M = bf_x->size; 

//     int min_range = 0; int max_range = 100; 
//     for (int x = min_range+99; x <= max_range+99; x++) bloom_filter_insert(bf_x, x);
//     for (int y = min_range+299; y <= max_range+299; y++) bloom_filter_insert(bf_y, y);

//     int SLOT_COUNT = encoder.slot_count();
//     vector<uint64_t> vec_x(SLOT_COUNT, 0ULL); vector<uint64_t> vec_y(SLOT_COUNT, 0ULL);
    
//     int count_1 = 0;
//     for (int m = 0; m < M; m++) { 
//         vec_x[m] = (bf_x->bits[m] != 0) ? 1ULL : 0ULL; 
//         vec_y[m] = (bf_y->bits[m] != 0) ? 1ULL : 0ULL; 
//         if (vec_x[m] == 1) count_1++;
//     }






//     cout << "\n[DEBUG-Client] BF 长度: " << M << ", 置 1 个数: " << count_1 << endl;
//     auto end = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration = end - start;
//     std::cout << "Phase 1: the time is " << duration.count()/1000 << " s\n";
    
//     // 阶段2  加密 BloomFilter结构
//     start = std::chrono::high_resolution_clock::now();


//     Ciphertext enc_bf_x, enc_bf_y; string str_bf_x, str_bf_y;
//     #pragma omp parallel sections
//     {
//         #pragma omp section
//         {
//             Encryptor local_enc(context, pk); Plaintext pt_x; encoder.encode(vec_x, pt_x);
//             local_enc.encrypt(pt_x, enc_bf_x); stringstream sx; enc_bf_x.save(sx); str_bf_x = sx.str();
//         }
//         #pragma omp section
//         {
//             Encryptor local_enc(context, pk); Plaintext pt_y; encoder.encode(vec_y, pt_y);
//             local_enc.encrypt(pt_y, enc_bf_y); stringstream sy; enc_bf_y.save(sy); str_bf_y = sy.str();
//         }
//     }
//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 2: the time is " << duration.count()/1000 << " s\n";


//     // 阶段3 将密文打包并传输，并接收结果
//     start = std::chrono::high_resolution_clock::now();
//     stringstream ss_out;
//     pk.save(ss_out); rk.save(ss_out); gal_keys.save(ss_out);
//     sk.save(ss_out); // 发送私钥供打印

//     ss_out.write(reinterpret_cast<const char*>(&M), sizeof(M));
//     uint64_t size_x = str_bf_x.size(); uint64_t size_y = str_bf_y.size();
//     ss_out.write(reinterpret_cast<const char*>(&size_x), sizeof(size_x)); ss_out.write(str_bf_x.c_str(), size_x);
//     ss_out.write(reinterpret_cast<const char*>(&size_y), sizeof(size_y)); ss_out.write(str_bf_y.c_str(), size_y);

//     boost::asio::io_context io_context; tcp::socket socket(io_context); tcp::resolver resolver(io_context);
//     boost::asio::connect(socket, resolver.resolve(argv[1], argv[2]));
//     cout << "[Client] 密文与私钥已发送，等待 Server 打印内部日志..." << endl;
//     send_data(socket, ss_out.str());

//     string result_data = receive_data(socket); 
//     stringstream ss_in(result_data);
    
//     uint64_t S;
//     ss_in.read(reinterpret_cast<char*>(&S), sizeof(S));
//     cout << "[Client] 接收到打乱后的密文 List，长度: " << S << "，开始解析与解密..." << endl;

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3: the time is " << duration.count()/1000 << " s\n";

//     // 解密并计算结果

//     int S_prime = 0;
    
//     // 遍历解析每一个混淆过的桶密文
//     for (uint64_t s = 0; s < S; s++) {
//         uint64_t len; 
//         ss_in.read(reinterpret_cast<char*>(&len), sizeof(len));
//         string str(len, '\0'); 
//         ss_in.read(&str[0], len);
        
//         stringstream stmp(str);
//         Ciphertext ct_bucket; 
//         ct_bucket.load(context, stmp);

//         Plaintext pt_res; 
//         decryptor.decrypt(ct_bucket, pt_res);
//         vector<uint64_t> dec_val; 
//         encoder.decode(pt_res, dec_val);

//         // 由于 Server 没有做同态累加，桶的值等于该密文所有槽位的总和
//         uint64_t bucket_sum = 0;
//         for (auto val : dec_val) {
//             bucket_sum += val;
//         }

//         // 如果这个桶所有槽加起来依然是 0，说明这是一个真实的零桶
//         if (bucket_sum == 0) {
//             S_prime++;
//         }
//     }

    
//     double RC = - (double)SKETCH_SIZE * log((double)S_prime / SKETCH_SIZE);
    
//     cout << "\n================ 最终统计结果 ================" << endl;
//     cout << "  - 零桶数量 (S_prime): " << S_prime << endl;
//     cout << "  - 范围内估算数量 (Estimated RC): " << RC << endl;
//     cout << "=====================================================\n" << endl;
//     auto end_time = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration_t = end_time - start_time;
//     std::cout << "The time is " << duration_t.count()/1000 << " s\n";

//     destroy_bloom_filter(bf_x); destroy_bloom_filter(bf_y);
//     return 0;
// }











// #include "common.h"
// #include "bloomfilter.h"
// #include "MurmurHash3.h"
// #include <sstream>
// #include <cmath>
// #include <omp.h>

// using namespace std;
// using namespace seal;

// // 标注最全版

// int main(int argc, char* argv[]) {
//     if (argc != 3) { cerr << "Usage: ./client <center_ip> <center_port>\n"; return 1; }

//     auto start_time = std::chrono::high_resolution_clock::now();

//     cout << "=====================================================" << endl;
//     cout << "[Client] 初始化 BFV 探针版环境..." << endl;
//     SEALContext context = create_fhe_context();
//     KeyGenerator keygen(context); SecretKey sk = keygen.secret_key();
//     PublicKey pk; keygen.create_public_key(pk); RelinKeys rk; keygen.create_relin_keys(rk); GaloisKeys gal_keys; keygen.create_galois_keys(gal_keys);

//     BatchEncoder encoder(context); Decryptor decryptor(context, sk);

//     // 阶段1  构造bloom filter结构
//     auto start = std::chrono::high_resolution_clock::now();

//     double fpr = 0.01; int expected_elements = 100;
//     BloomFilter* bf_x = create_bloom_filter(expected_elements, fpr);
//     BloomFilter* bf_y = create_bloom_filter(expected_elements, fpr);
//     int M = bf_x->size; 

//     int min_range = 0; int max_range = 100; 
//     for (int x = min_range+99; x <= max_range+99; x++) bloom_filter_insert(bf_x, x);
//     for (int y = min_range+299; y <= max_range+299; y++) bloom_filter_insert(bf_y, y);

//     int SLOT_COUNT = encoder.slot_count();
//     vector<uint64_t> vec_x(SLOT_COUNT, 0ULL); vector<uint64_t> vec_y(SLOT_COUNT, 0ULL);
    
//     int count_1 = 0;
//     for (int m = 0; m < M; m++) { 
//         vec_x[m] = (bf_x->bits[m] != 0) ? 1ULL : 0ULL; 
//         vec_y[m] = (bf_y->bits[m] != 0) ? 1ULL : 0ULL; 
//         if (vec_x[m] == 1) count_1++;
//     }






//     cout << "\n[DEBUG-Client] BF 长度: " << M << ", 置 1 个数: " << count_1 << endl;
//     auto end = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration = end - start;
//     std::cout << "Phase 1: the time is " << duration.count()/1000 << " s\n";
    
//     // 阶段2  加密 BloomFilter结构
//     start = std::chrono::high_resolution_clock::now();


//     Ciphertext enc_bf_x, enc_bf_y; string str_bf_x, str_bf_y;
//     #pragma omp parallel sections
//     {
//         #pragma omp section
//         {
//             Encryptor local_enc(context, pk); Plaintext pt_x; encoder.encode(vec_x, pt_x);
//             local_enc.encrypt(pt_x, enc_bf_x); stringstream sx; enc_bf_x.save(sx); str_bf_x = sx.str();
//         }
//         #pragma omp section
//         {
//             Encryptor local_enc(context, pk); Plaintext pt_y; encoder.encode(vec_y, pt_y);
//             local_enc.encrypt(pt_y, enc_bf_y); stringstream sy; enc_bf_y.save(sy); str_bf_y = sy.str();
//         }
//     }
//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 2: the time is " << duration.count()/1000 << " s\n";


//     // 阶段3 将密文打包并传输，并接收结果
//     start = std::chrono::high_resolution_clock::now();
//     stringstream ss_out;
//     pk.save(ss_out); rk.save(ss_out); gal_keys.save(ss_out);
//     sk.save(ss_out); // 发送私钥供打印

//     ss_out.write(reinterpret_cast<const char*>(&M), sizeof(M));
//     uint64_t size_x = str_bf_x.size(); uint64_t size_y = str_bf_y.size();
//     ss_out.write(reinterpret_cast<const char*>(&size_x), sizeof(size_x)); ss_out.write(str_bf_x.c_str(), size_x);
//     ss_out.write(reinterpret_cast<const char*>(&size_y), sizeof(size_y)); ss_out.write(str_bf_y.c_str(), size_y);

//     boost::asio::io_context io_context; tcp::socket socket(io_context); tcp::resolver resolver(io_context);
//     boost::asio::connect(socket, resolver.resolve(argv[1], argv[2]));
//     cout << "[Client] 密文与私钥已发送，等待 Server 打印内部日志..." << endl;
//     send_data(socket, ss_out.str());

//     string result_data = receive_data(socket); 
//     stringstream ss_in(result_data);
    
//     uint64_t S;
//     ss_in.read(reinterpret_cast<char*>(&S), sizeof(S));
//     cout << "[Client] 接收到打乱后的密文 List，长度: " << S << "，开始解析与解密..." << endl;

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3: the time is " << duration.count()/1000 << " s\n";

//     // 解密并计算结果

//     int S_prime = 0;
    
//     // 遍历解析每一个混淆过的桶密文
//     for (uint64_t s = 0; s < S; s++) {
//         uint64_t len; 
//         ss_in.read(reinterpret_cast<char*>(&len), sizeof(len));
//         string str(len, '\0'); 
//         ss_in.read(&str[0], len);
        
//         stringstream stmp(str);
//         Ciphertext ct_bucket; 
//         ct_bucket.load(context, stmp);

//         Plaintext pt_res; 
//         decryptor.decrypt(ct_bucket, pt_res);
//         vector<uint64_t> dec_val; 
//         encoder.decode(pt_res, dec_val);

//         // 由于 Server 没有做同态累加，桶的值等于该密文所有槽位的总和
//         uint64_t bucket_sum = 0;
//         for (auto val : dec_val) {
//             bucket_sum += val;
//         }

//         // 如果这个桶所有槽加起来依然是 0，说明这是一个真实的零桶
//         if (bucket_sum == 0) {
//             S_prime++;
//         }
//     }

    
//     double RC = - (double)SKETCH_SIZE * log((double)S_prime / SKETCH_SIZE);
    
//     cout << "\n================ 最终统计结果 ================" << endl;
//     cout << "  - 零桶数量 (S_prime): " << S_prime << endl;
//     cout << "  - 范围内估算数量 (Estimated RC): " << RC << endl;
//     cout << "=====================================================\n" << endl;
//     auto end_time = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration_t = end_time - start_time;
//     std::cout << "The time is " << duration_t.count()/1000 << " s\n";

//     destroy_bloom_filter(bf_x); destroy_bloom_filter(bf_y);
//     return 0;
// }




// // #include "common.h"
// // #include "bloomfilter.h"
// // #include "MurmurHash3.h"
// // #include <sstream>
// // #include <cmath>
// // #include <omp.h>

// // using namespace std;
// // using namespace seal;

// // int main(int argc, char* argv[]) {
// //     if (argc != 3) { cerr << "Usage: ./client <center_ip> <center_port>\n"; return 1; }

// //     cout << "=====================================================" << endl;
// //     cout << "[Client] 初始化 BFV 探针版环境..." << endl;
// //     SEALContext context = create_fhe_context();
// //     KeyGenerator keygen(context); SecretKey sk = keygen.secret_key();
// //     PublicKey pk; keygen.create_public_key(pk); RelinKeys rk; keygen.create_relin_keys(rk); GaloisKeys gal_keys; keygen.create_galois_keys(gal_keys);

// //     BatchEncoder encoder(context); Decryptor decryptor(context, sk);

// //     double fpr = 0.01; int expected_elements = 100;
// //     BloomFilter* bf_x = create_bloom_filter(expected_elements, fpr);
// //     BloomFilter* bf_y = create_bloom_filter(expected_elements, fpr);
// //     int M = bf_x->size; 

// //     int min_range = 0; int max_range = 100; 
// //     for (int x = min_range; x <= max_range; x++) bloom_filter_insert(bf_x, x);
// //     for (int y = min_range; y <= max_range; y++) bloom_filter_insert(bf_y, y);

// //     int SLOT_COUNT = encoder.slot_count();
// //     vector<uint64_t> vec_x(SLOT_COUNT, 0ULL); vector<uint64_t> vec_y(SLOT_COUNT, 0ULL);
    
// //     int count_1 = 0;
// //     for (int m = 0; m < M; m++) { 
// //         vec_x[m] = (bf_x->bits[m] != 0) ? 1ULL : 0ULL; 
// //         vec_y[m] = (bf_y->bits[m] != 0) ? 1ULL : 0ULL; 
// //         if (vec_x[m] == 1) count_1++;
// //     }

// //     cout << "\n[DEBUG-Client] BF 长度: " << M << ", 置 1 个数: " << count_1 << endl;
    

// //     Ciphertext enc_bf_x, enc_bf_y; string str_bf_x, str_bf_y;
// //     #pragma omp parallel sections
// //     {
// //         #pragma omp section
// //         {
// //             Encryptor local_enc(context, pk); Plaintext pt_x; encoder.encode(vec_x, pt_x);
// //             local_enc.encrypt(pt_x, enc_bf_x); stringstream sx; enc_bf_x.save(sx); str_bf_x = sx.str();
// //         }
// //         #pragma omp section
// //         {
// //             Encryptor local_enc(context, pk); Plaintext pt_y; encoder.encode(vec_y, pt_y);
// //             local_enc.encrypt(pt_y, enc_bf_y); stringstream sy; enc_bf_y.save(sy); str_bf_y = sy.str();
// //         }
// //     }

// //     stringstream ss_out;
// //     pk.save(ss_out); rk.save(ss_out); gal_keys.save(ss_out);
// //     sk.save(ss_out); // 发送私钥供打印

// //     ss_out.write(reinterpret_cast<const char*>(&M), sizeof(M));
// //     uint64_t size_x = str_bf_x.size(); uint64_t size_y = str_bf_y.size();
// //     ss_out.write(reinterpret_cast<const char*>(&size_x), sizeof(size_x)); ss_out.write(str_bf_x.c_str(), size_x);
// //     ss_out.write(reinterpret_cast<const char*>(&size_y), sizeof(size_y)); ss_out.write(str_bf_y.c_str(), size_y);

// //     boost::asio::io_context io_context; tcp::socket socket(io_context); tcp::resolver resolver(io_context);
// //     boost::asio::connect(socket, resolver.resolve(argv[1], argv[2]));
// //     cout << "[Client] 密文与私钥已发送，等待 Server 打印内部日志..." << endl;
// //     send_data(socket, ss_out.str());

// //     string result_data = receive_data(socket); stringstream ss_in(result_data);
// //     Ciphertext enc_sketch_final; enc_sketch_final.load(context, ss_in);

// //     Plaintext pt_res; decryptor.decrypt(enc_sketch_final, pt_res);
// //     vector<uint64_t> dec_val; encoder.decode(pt_res, dec_val);

// //     int S_prime = 0; for (int s = 0; s < SKETCH_SIZE; s++) { if (dec_val[s] == 0) S_prime++; }
// //     double RC = - (double)SKETCH_SIZE * log((double)S_prime / SKETCH_SIZE);
    
// //     cout << "\n================ 最终统计结果 ================" << endl;
// //     cout << "  - 零桶数量 (S_prime): " << S_prime << endl;
// //     cout << "  - 范围内估算数量 (Estimated RC): " << RC << endl;
// //     cout << "=====================================================\n" << endl;

// //     destroy_bloom_filter(bf_x); destroy_bloom_filter(bf_y);
// //     return 0;
// // }