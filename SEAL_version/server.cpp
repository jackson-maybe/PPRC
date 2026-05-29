#include "common.h"
#include "bloomfilter.h"
#include "MurmurHash3.h"
#include <sstream>
#include <chrono>
#include <omp.h>
#include <vector>
#include <random>
#include <map>
#include <fstream>
#include <string>
#include <algorithm>
#include <iostream>

using namespace std;
using namespace seal;

struct Record { int id; int x; int y; int o; };

struct UniqueRecord { 
    int x; 
    int y; 
    vector<int> o_list; 
    map<int, int> bucket_counts; 
};

int main(int argc, char* argv[]) {
    auto start_time = std::chrono::high_resolution_clock::now();

    // ==========================================
    // 阶段1：数据加载与采样
    // ==========================================
    auto start = std::chrono::high_resolution_clock::now();
    if (argc != 2) { cerr << "Usage: ./server <listen_port>\n"; return 1; }

    vector<Record> dataset;

    std::random_device rd;
    std::mt19937 gen(rd());
    
    int dataset_choice = 1; 
    std::string dataset_path;
    int read_limit = 0;

    if (dataset_choice == 0) {
        dataset_path = "../dataset/spatial/quantize_spatial_1_20.csv";
        read_limit = 21900;
    } else {
        dataset_path = "../dataset/brightkite/Brightkite_filter_quantized.csv";
        read_limit = 115383;
    }

    double P = 0.2; 

    struct CsvRow { int original_row; int x; int y; };
    std::vector<CsvRow> all_csv_data;

    std::ifstream file(dataset_path);
    if (!file.is_open()) {
        std::cerr << "[Error] 无法打开数据集文件: " << dataset_path << std::endl;
        exit(1); 
    }

    std::string line;
    int loaded_count = 0;
    int current_row = 1; 

    while (std::getline(file, line) && loaded_count < read_limit) {
        std::stringstream ss(line);
        std::string cell_x, cell_y;

        if (std::getline(ss, cell_x, ',') && std::getline(ss, cell_y, ',')) {
            try {
                int x = std::stoi(cell_x);
                int y = std::stoi(cell_y);
                all_csv_data.push_back({current_row, x, y});
                loaded_count++; 
            } catch (const std::invalid_argument& e) {}
        }
        current_row++;
    }
    file.close();
    std::cout << "[Server] 成功从 " << dataset_path << " 提取 " << loaded_count << " 条有效数据。" << std::endl;

    int target_size = static_cast<int>(all_csv_data.size() * P);
    if (target_size == 0 && !all_csv_data.empty()) { target_size = 1; }

    std::shuffle(all_csv_data.begin(), all_csv_data.end(), gen);

    for (int i = 0; i < target_size; i++) {
        dataset.push_back({i, all_csv_data[i].x, all_csv_data[i].y, all_csv_data[i].original_row});
    }

    std::cout << "[Server] 按 P=" << P << " 比例随机抽取了 " << dataset.size() << " 条模拟数据参与 FHE 计算。" << std::endl;
    
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration = end - start;
    std::cout << "Phase 1 (Data Loading): the time is " << duration.count()/1000 << " s\n";

    boost::asio::io_context io_context; tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), stoi(argv[1])));
    tcp::socket socket(io_context); acceptor.accept(socket);

    SEALContext context = create_fhe_context(); BatchEncoder encoder(context);
    uint64_t plain_mod = context.first_context_data()->parms().plain_modulus().value();

    string recv_str = receive_data(socket); 
    cout << "[Comm] Server 接收到查询请求数据量: " << recv_str.size() / 1024.0 / 1024.0 << " MB" << endl;
    
    stringstream ss_in(recv_str);

    // ==========================================
    // 阶段2：接收数据与降维去重
    // ==========================================
    start = std::chrono::high_resolution_clock::now();

    // 【核心】首先读取 Center 注入的同步种子
    uint32_t session_seed;
    ss_in.read(reinterpret_cast<char*>(&session_seed), sizeof(session_seed));
    cout << "[Server] 接收到 Center 下发的同步随机种子: " << session_seed << endl;

    PublicKey pk; pk.load(context, ss_in); RelinKeys rk; rk.load(context, ss_in); GaloisKeys gal_keys; gal_keys.load(context, ss_in);

    int M; ss_in.read(reinterpret_cast<char*>(&M), sizeof(M));
    uint64_t size_x, size_y;
    ss_in.read(reinterpret_cast<char*>(&size_x), sizeof(size_x)); string str_x(size_x, '\0'); ss_in.read(&str_x[0], size_x); stringstream sx(str_x); Ciphertext enc_bf_x; enc_bf_x.load(context, sx);
    ss_in.read(reinterpret_cast<char*>(&size_y), sizeof(size_y)); string str_y(size_y, '\0'); ss_in.read(&str_y[0], size_y); stringstream sy(str_y); Ciphertext enc_bf_y; enc_bf_y.load(context, sy);

    map<pair<int, int>, vector<int>> unique_map;
    for (const auto& rec : dataset) {
        unique_map[{rec.x, rec.y}].push_back(rec.o);
    }
    
    vector<UniqueRecord> unique_dataset;
    for (const auto& kv : unique_map) {
        UniqueRecord ur;
        ur.x = kv.first.first;
        ur.y = kv.first.second;
        ur.o_list = kv.second;
        for (int o_val : ur.o_list) {
            int s = (int)hash_result(o_val, SKETCH_SIZE, 0);
            ur.bucket_counts[s]++;
        }
        unique_dataset.push_back(ur);
    }
    int total_unique_records = unique_dataset.size();
    
    cout << "[Server] 数据去重优化: 提取出 " << total_unique_records << " 个唯一的 (x, y) 组合以降低 FHE 计算开销。" << endl;

    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "Phase 2 (Recv & Dedup): the time is " << duration.count()/1000 << " s\n";

    // ==========================================
    // 阶段3：哈希缓存与并发旋转预计算
    // ==========================================
    start = std::chrono::high_resolution_clock::now();

    map<int, vector<int>> cache_hash_x;
    map<int, vector<int>> cache_hash_y;
    for (const auto& rec : unique_dataset) {
        if (cache_hash_x.find(rec.x) == cache_hash_x.end()) {
            vector<int> hx(3);
            for (int k = 0; k < 3; k++) hx[k] = (int)hash_result(rec.x, M, k);
            cache_hash_x[rec.x] = hx;
        }
        if (cache_hash_y.find(rec.y) == cache_hash_y.end()) {
            vector<int> hy(3);
            for (int k = 0; k < 3; k++) hy[k] = (int)hash_result(rec.y, M, k);
            cache_hash_y[rec.y] = hy;
        }
    }

    vector<uint64_t> server_blind_vec(SKETCH_SIZE, 0ULL);
    std::uniform_int_distribution<uint64_t> dist_blind(1, 100);
    for(int s = 0; s < SKETCH_SIZE; s++) {
        server_blind_vec[s] = dist_blind(gen); 
    }

    int ROW_SIZE = encoder.slot_count() / 2; 
    int num_batches = ceil((double)total_unique_records / ROW_SIZE); 

    vector<bool> need_rot_X(ROW_SIZE, false); vector<bool> need_rot_Y(ROW_SIZE, false);
    for (int b = 0; b < num_batches; b++) {
        int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_unique_records - start_idx);
        for (int i = 0; i < curr_size; i++) {
            auto& rec = unique_dataset[start_idx + i];
            const auto& hx = cache_hash_x[rec.x];
            for (int k = 0; k < 3; k++) {
                int off_x = (hx[k] - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE; need_rot_X[off_x] = true;
            }
            const auto& hy = cache_hash_y[rec.y];
            for (int k = 0; k < 3; k++) {
                int off_y = (hy[k] - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE; need_rot_Y[off_y] = true;
            }
        }
    }

    vector<Ciphertext> rot_X(ROW_SIZE), rot_Y(ROW_SIZE);

    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "Phase 3 (Hash Cache): the time is " << duration.count()/1000 << " s\n";

    start = std::chrono::high_resolution_clock::now();
    
    vector<int> active_rot_X;
    vector<int> active_rot_Y;
    for(int d = 0; d < ROW_SIZE; d++) {
        if(need_rot_X[d]) active_rot_X.push_back(d);
        if(need_rot_Y[d]) active_rot_Y.push_back(d);
    }

    cout << "[Server] 轮转操作优化: 实际执行 X=" << active_rot_X.size() 
         << " 次, Y=" << active_rot_Y.size() << " 次 (槽位上限 " << ROW_SIZE << ")" << endl;

    #pragma omp parallel for schedule(dynamic)
    for(size_t i = 0; i < active_rot_X.size(); i++) {
        Evaluator local_eval(context);
        int d = active_rot_X[i];
        local_eval.rotate_rows(enc_bf_x, d, gal_keys, rot_X[d]);
    }

    #pragma omp parallel for schedule(dynamic)
    for(size_t i = 0; i < active_rot_Y.size(); i++) {
        Evaluator local_eval(context);
        int d = active_rot_Y[i];
        local_eval.rotate_rows(enc_bf_y, d, gal_keys, rot_Y[d]);
    }

    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "Phase 3 (Rotate): the time is " << duration.count()/1000 << " s\n";
    
    start = std::chrono::high_resolution_clock::now();
    
    // ====== 【核心】 K=5 宽位打包初始化与同步洗牌映射 ======
    int K = 5;
    int PACKED_SIZE = ceil((double)SKETCH_SIZE / K);
    
    std::mt19937 gen_pack(session_seed);
    vector<int> perm_s(SKETCH_SIZE);
    iota(perm_s.begin(), perm_s.end(), 0);
    shuffle(perm_s.begin(), perm_s.end(), gen_pack);

    vector<int> inverted_perm(SKETCH_SIZE);
    for(int i = 0; i < SKETCH_SIZE; i++) {
        inverted_perm[perm_s[i]] = i;
    }

    vector<Ciphertext> batch_sketches(PACKED_SIZE);
    #pragma omp parallel for
    for(int p = 0; p < PACKED_SIZE; p++) {
        Encryptor init_enc(context, pk); Evaluator init_eval(context);
        init_enc.encrypt_zero(batch_sketches[p]);
        init_eval.mod_switch_to_inplace(batch_sketches[p], context.last_context_data()->parms_id()); 
    }
    // ===============================================

    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "Phase 3 (Batch Sketch Initialization): the time is " << duration.count()/1000 << " s\n";
    
    std::cout << "\n[Server] The batch number is " << num_batches << " \n";

    // ==========================================
    // 阶段4：多 Batch 并发计算与 L_n 生成
    // ==========================================
    start = std::chrono::high_resolution_clock::now();
    omp_set_nested(1); 
    
    #pragma omp parallel for schedule(dynamic)
    for (int b = 0; b < num_batches; b++) {
        Evaluator local_eval(context); Encryptor local_enc(context, pk); BatchEncoder local_enc_batch(context);
        int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_unique_records - start_idx);

        Ciphertext enc_S_x, enc_S_y; local_enc.encrypt_zero(enc_S_x); local_enc.encrypt_zero(enc_S_y);

        map<int, vector<int>> batch_x_to_i; map<int, vector<int>> batch_y_to_i;
        for (int i = 0; i < curr_size; i++) {
            batch_x_to_i[unique_dataset[start_idx + i].x].push_back(i);
            batch_y_to_i[unique_dataset[start_idx + i].y].push_back(i);
        }

        map<int, vector<uint64_t>> masks_X; map<int, vector<uint64_t>> masks_Y;
        for (const auto& kv : batch_x_to_i) {
            int x = kv.first; const auto& indices = kv.second; const auto& hx = cache_hash_x[x]; 
            for (int k = 0; k < 3; k++) {
                int t_x = hx[k];
                for (int i : indices) {
                    int off_x = (t_x - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE;
                    if (masks_X.find(off_x) == masks_X.end()) masks_X[off_x] = vector<uint64_t>(encoder.slot_count(), 0);
                    masks_X[off_x][i]++;
                }
            }
        }
        for (const auto& kv : batch_y_to_i) {
            int y = kv.first; const auto& indices = kv.second; const auto& hy = cache_hash_y[y]; 
            for (int k = 0; k < 3; k++) {
                int t_y = hy[k];
                for (int i : indices) {
                    int off_y = (t_y - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE;
                    if (masks_Y.find(off_y) == masks_Y.end()) masks_Y[off_y] = vector<uint64_t>(encoder.slot_count(), 0);
                    masks_Y[off_y][i]++;
                }
            }
        }

        vector<pair<int, vector<uint64_t>>> vec_masks_X(masks_X.begin(), masks_X.end());
        vector<pair<int, vector<uint64_t>>> vec_masks_Y(masks_Y.begin(), masks_Y.end());

        #pragma omp parallel
        {
            Evaluator thread_eval(context); BatchEncoder thread_encoder(context);
            Ciphertext local_S_x; local_enc.encrypt_zero(local_S_x); 
            
            #pragma omp for nowait schedule(dynamic)
            for (size_t i = 0; i < vec_masks_X.size(); i++) {
                int d = vec_masks_X[i].first; Plaintext pt; 
                thread_encoder.encode(vec_masks_X[i].second, pt);
                Ciphertext temp = rot_X[d]; 
                thread_eval.multiply_plain_inplace(temp, pt); 
                thread_eval.add_inplace(local_S_x, temp);
            }
            #pragma omp critical(x_accumulate)
            { local_eval.add_inplace(enc_S_x, local_S_x); }
        }

        #pragma omp parallel
        {
            Evaluator thread_eval(context); BatchEncoder thread_encoder(context);
            Ciphertext local_S_y; local_enc.encrypt_zero(local_S_y);
            
            #pragma omp for nowait schedule(dynamic)
            for (size_t i = 0; i < vec_masks_Y.size(); i++) {
                int d = vec_masks_Y[i].first; Plaintext pt; 
                thread_encoder.encode(vec_masks_Y[i].second, pt);
                Ciphertext temp = rot_Y[d]; 
                thread_eval.multiply_plain_inplace(temp, pt); 
                thread_eval.add_inplace(local_S_y, temp);
            }
            #pragma omp critical(y_accumulate)
            { local_eval.add_inplace(enc_S_y, local_S_y); }
        }

        vector<Ciphertext> all_terms;
        all_terms.push_back(enc_S_x); all_terms.push_back(enc_S_y);
        for(uint64_t j = 1; j <= 2; j++) {
            vector<uint64_t> vec_j(encoder.slot_count(), j); Plaintext pt_j; local_enc_batch.encode(vec_j, pt_j);
            Ciphertext temp_x, temp_y;
            local_eval.sub_plain(enc_S_x, pt_j, temp_x); local_eval.sub_plain(enc_S_y, pt_j, temp_y);
            all_terms.push_back(temp_x); all_terms.push_back(temp_y);
        }

        Ciphertext enc_L_n;
        local_eval.multiply_many(all_terms, rk, enc_L_n);

        // ====== 【核心】基于 K=5 的大整数掩码位移拼接 ======
        int SHIFT_BITS = 9; // 每个桶占 9 bit (最大计数值 511)
        map<int, vector<uint64_t>> packed_mask_out;
        
        for (int i = 0; i < curr_size; i++) {
            auto& rec = unique_dataset[start_idx + i];
            for (const auto& kv : rec.bucket_counts) {
                int original_s = kv.first; 
                int count = kv.second;
                
                int perm_idx = inverted_perm[original_s];
                int p = perm_idx / K;
                int k_off = perm_idx % K;

                if (packed_mask_out.find(p) == packed_mask_out.end()) {
                    packed_mask_out[p] = vector<uint64_t>(encoder.slot_count(), 0);
                }
                
                uint64_t val = (count * server_blind_vec[original_s]) % plain_mod;
                packed_mask_out[p][i] += (val << (SHIFT_BITS * k_off)); 
            }
        }

        vector<pair<int, vector<uint64_t>>> packed_mask_out_vec(packed_mask_out.begin(), packed_mask_out.end());
        
        vector<Ciphertext> local_batch_sketch(PACKED_SIZE);
        #pragma omp parallel for
        for(int p = 0; p < PACKED_SIZE; p++) {
            Encryptor init_enc(context, pk); Evaluator init_eval(context);
            init_enc.encrypt_zero(local_batch_sketch[p]);
            init_eval.mod_switch_to_inplace(local_batch_sketch[p], enc_L_n.parms_id());
        }

        #pragma omp parallel for schedule(dynamic)
        for (int idx = 0; idx < (int)packed_mask_out_vec.size(); idx++) {
            int p = packed_mask_out_vec[idx].first;
            Evaluator thread_eval(context); BatchEncoder thread_enc(context);
            Plaintext pt_m; thread_enc.encode(packed_mask_out_vec[idx].second, pt_m); 
            Ciphertext masked_L_n;
            thread_eval.multiply_plain(enc_L_n, pt_m, masked_L_n); 
            thread_eval.add_inplace(local_batch_sketch[p], masked_L_n);
        }
        
        #pragma omp parallel for
        for(int p = 0; p < PACKED_SIZE; p++) {
            Evaluator thread_eval(context);
            thread_eval.mod_switch_to_inplace(local_batch_sketch[p], context.last_context_data()->parms_id());
        }

        #pragma omp critical(global_merge)
        {
            for(int p = 0; p < PACKED_SIZE; p++) {
                local_eval.add_inplace(batch_sketches[p], local_batch_sketch[p]);
            }
        }
        // ===============================================
    } 

    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "Phase 4 (All Batches Process & Merge): the time is " << duration.count()/1000 << " s\n";

    cout << "\n================ 最终 FHE 汇总 ================" << endl;
    
    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration_t = end_time - start_time;
    std::cout << "\n[Total] The overall time is " << duration_t.count()/1000 << " s\n";
    
    // ==========================================
    // 阶段5：并发序列化、ZSTD压缩与零拷贝网络发送
    // ==========================================
    start = std::chrono::high_resolution_clock::now();

    seal::compr_mode_type compr_mode = seal::compr_mode_type::zstd;

    // 所有 SKETCH_SIZE 已替换为 PACKED_SIZE
    vector<vector<seal::seal_byte>> serialized_sketches(PACKED_SIZE);
    vector<uint64_t> actual_sizes(PACKED_SIZE, 0);
    
    uint64_t total_payload_size = sizeof(uint64_t); 

    #pragma omp parallel for reduction(+:total_payload_size)
    for (int s = 0; s < PACKED_SIZE; s++) {
        size_t max_size = batch_sketches[s].save_size(compr_mode);
        serialized_sketches[s].resize(max_size);
        
        actual_sizes[s] = batch_sketches[s].save(
            serialized_sketches[s].data(), 
            max_size, 
            compr_mode
        );
        
        total_payload_size += sizeof(uint64_t) + actual_sizes[s];
    }

    string final_payload;
    final_payload.reserve(total_payload_size);

    uint64_t S_out = PACKED_SIZE;
    final_payload.append(reinterpret_cast<const char*>(&S_out), sizeof(S_out));

    for (int s = 0; s < PACKED_SIZE; s++) {
        uint64_t len = actual_sizes[s];
        final_payload.append(reinterpret_cast<const char*>(&len), sizeof(len));
        final_payload.append(reinterpret_cast<const char*>(serialized_sketches[s].data()), len);
    }

    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "Phase 5 (Serialization & ZSTD Compression): the time is " << duration.count()/1000.0 << " s\n";

    cout << "[Comm] Server 即将发送给 Center 的结果数据量: " << final_payload.size() / 1024.0 / 1024.0 << " MB" << endl;
    cout << "[Server] 已完成 ZSTD 高效打包，准备发送 " << PACKED_SIZE << " 个密文块..." << endl;
    
    send_data(socket, final_payload);
    end_time = std::chrono::high_resolution_clock::now();
    duration_t = end_time - start_time;
    std::cout << "\n[Total] The overall time is " << duration_t.count()/1000.0 << " s\n";
    
    return 0;
}








// #include "common.h"
// #include "bloomfilter.h"
// #include "MurmurHash3.h"
// #include <sstream>
// #include <chrono>
// #include <omp.h>
// #include <vector>
// #include <random>
// #include <map>
// #include <fstream>
// #include <string>
// #include <algorithm>
// #include <iostream>

// using namespace std;
// using namespace seal;

// struct Record { int id; int x; int y; int o; };

// struct UniqueRecord { 
//     int x; 
//     int y; 
//     vector<int> o_list; 
//     map<int, int> bucket_counts; 
// };

// int main(int argc, char* argv[]) {
//     auto start_time = std::chrono::high_resolution_clock::now();

//     // PPRC 最终实验code，去掉sk，统计通信量，改进排列，无打包

//     // ==========================================
//     // 阶段1：数据加载与采样
//     // ==========================================
//     auto start = std::chrono::high_resolution_clock::now();
//     if (argc != 2) { cerr << "Usage: ./server <listen_port>\n"; return 1; }

//     vector<Record> dataset;

//     std::random_device rd;
//     std::mt19937 gen(rd());
//     std::uniform_int_distribution<> dist_x(0, 100);
//     std::uniform_int_distribution<> dist_y(0, 100);
//     std::uniform_int_distribution<> dist_x_miss(0, 1000);
//     std::uniform_int_distribution<> dist_y_miss(0, 1000);
//     std::uniform_int_distribution<> dist_o(10000, 99999);

//     int dataset_choice = 1; 
//     std::string dataset_path;
//     int read_limit = 0;

//     if (dataset_choice == 0) {
//         dataset_path = "../dataset/spatial/quantize_spatial_1_20.csv";
//         read_limit = 21900;
//     } else {
//         dataset_path = "../dataset/brightkite/Brightkite_filter_quantized.csv";
//         read_limit = 115383;
//     }

//     double P = 0.2; 

//     struct CsvRow { int original_row; int x; int y; };
//     std::vector<CsvRow> all_csv_data;

//     std::ifstream file(dataset_path);
//     if (!file.is_open()) {
//         std::cerr << "[Error] 无法打开数据集文件: " << dataset_path << std::endl;
//         exit(1); 
//     }

//     std::string line;
//     int loaded_count = 0;
//     int current_row = 1; 

//     while (std::getline(file, line) && loaded_count < read_limit) {
//         std::stringstream ss(line);
//         std::string cell_x, cell_y;

//         if (std::getline(ss, cell_x, ',') && std::getline(ss, cell_y, ',')) {
//             try {
//                 int x = std::stoi(cell_x);
//                 int y = std::stoi(cell_y);
//                 all_csv_data.push_back({current_row, x, y});
//                 loaded_count++; 
//             } catch (const std::invalid_argument& e) {}
//         }
//         current_row++;
//     }
//     file.close();
//     std::cout << "[Server] 成功从 " << dataset_path << " 提取 " << loaded_count << " 条有效数据。" << std::endl;

//     int target_size = static_cast<int>(all_csv_data.size() * P);
//     if (target_size == 0 && !all_csv_data.empty()) { target_size = 1; }

//     std::shuffle(all_csv_data.begin(), all_csv_data.end(), gen);

//     for (int i = 0; i < target_size; i++) {
//         dataset.push_back({i, all_csv_data[i].x, all_csv_data[i].y, all_csv_data[i].original_row});
//     }

//     std::cout << "[Server] 按 P=" << P << " 比例随机抽取了 " << dataset.size() << " 条模拟数据参与 FHE 计算。" << std::endl;
    
//     auto end = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration = end - start;
//     std::cout << "Phase 1 (Data Loading): the time is " << duration.count()/1000 << " s\n";

//     boost::asio::io_context io_context; tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), stoi(argv[1])));
//     tcp::socket socket(io_context); acceptor.accept(socket);

//     SEALContext context = create_fhe_context(); BatchEncoder encoder(context);
//     uint64_t plain_mod = context.first_context_data()->parms().plain_modulus().value();

//     string recv_str = receive_data(socket); stringstream ss_in(recv_str);
//     PublicKey pk; pk.load(context, ss_in); RelinKeys rk; rk.load(context, ss_in); GaloisKeys gal_keys; gal_keys.load(context, ss_in);
    

//     // ==========================================
//     // 阶段2：接收数据与降维去重
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();

//     int M; ss_in.read(reinterpret_cast<char*>(&M), sizeof(M));
//     uint64_t size_x, size_y;
//     ss_in.read(reinterpret_cast<char*>(&size_x), sizeof(size_x)); string str_x(size_x, '\0'); ss_in.read(&str_x[0], size_x); stringstream sx(str_x); Ciphertext enc_bf_x; enc_bf_x.load(context, sx);
//     ss_in.read(reinterpret_cast<char*>(&size_y), sizeof(size_y)); string str_y(size_y, '\0'); ss_in.read(&str_y[0], size_y); stringstream sy(str_y); Ciphertext enc_bf_y; enc_bf_y.load(context, sy);

    

//     map<pair<int, int>, vector<int>> unique_map;
//     for (const auto& rec : dataset) {
//         unique_map[{rec.x, rec.y}].push_back(rec.o);
//     }
    
//     vector<UniqueRecord> unique_dataset;
//     for (const auto& kv : unique_map) {
//         UniqueRecord ur;
//         ur.x = kv.first.first;
//         ur.y = kv.first.second;
//         ur.o_list = kv.second;
//         for (int o_val : ur.o_list) {
//             int s = (int)hash_result(o_val, SKETCH_SIZE, 0);
//             ur.bucket_counts[s]++;
//         }
//         unique_dataset.push_back(ur);
//     }
//     int total_unique_records = unique_dataset.size();
    
//     cout << "[Server] 数据去重优化: 提取出 " << total_unique_records << " 个唯一的 (x, y) 组合以降低 FHE 计算开销。" << endl;

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 2 (Recv & Dedup): the time is " << duration.count()/1000 << " s\n";

//     // ==========================================
//     // 阶段3：哈希缓存与并发旋转预计算
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();

//     map<int, vector<int>> cache_hash_x;
//     map<int, vector<int>> cache_hash_y;
//     for (const auto& rec : unique_dataset) {
//         if (cache_hash_x.find(rec.x) == cache_hash_x.end()) {
//             vector<int> hx(3);
//             for (int k = 0; k < 3; k++) hx[k] = (int)hash_result(rec.x, M, k);
//             cache_hash_x[rec.x] = hx;
//         }
//         if (cache_hash_y.find(rec.y) == cache_hash_y.end()) {
//             vector<int> hy(3);
//             for (int k = 0; k < 3; k++) hy[k] = (int)hash_result(rec.y, M, k);
//             cache_hash_y[rec.y] = hy;
//         }
//     }

//     vector<uint64_t> server_blind_vec(SKETCH_SIZE, 0ULL);
//     std::uniform_int_distribution<uint64_t> dist_blind(1, 100);
//     for(int s = 0; s < SKETCH_SIZE; s++) {
//         server_blind_vec[s] = dist_blind(gen); 
//     }

//     int ROW_SIZE = encoder.slot_count() / 2; 
//     int num_batches = ceil((double)total_unique_records / ROW_SIZE); 

//     vector<bool> need_rot_X(ROW_SIZE, false); vector<bool> need_rot_Y(ROW_SIZE, false);
//     for (int b = 0; b < num_batches; b++) {
//         int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_unique_records - start_idx);
//         for (int i = 0; i < curr_size; i++) {
//             auto& rec = unique_dataset[start_idx + i];
//             const auto& hx = cache_hash_x[rec.x];
//             for (int k = 0; k < 3; k++) {
//                 int off_x = (hx[k] - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE; need_rot_X[off_x] = true;
//             }
//             const auto& hy = cache_hash_y[rec.y];
//             for (int k = 0; k < 3; k++) {
//                 int off_y = (hy[k] - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE; need_rot_Y[off_y] = true;
//             }
//         }
//     }

//     // 【修改点】：直接 OMP 并行遍历 ROW_SIZE，数据量大时大概率 4096 次全跑，取消 active_X 额外开销
//     vector<Ciphertext> rot_X(ROW_SIZE), rot_Y(ROW_SIZE);

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3 (Hash Cache): the time is " << duration.count()/1000 << " s\n";

//     start = std::chrono::high_resolution_clock::now();
    
//     // 【修改点】：统计实际不重叠的、需要的轮转步长集合，按需分配并行任务
//     vector<int> active_rot_X;
//     vector<int> active_rot_Y;
//     for(int d = 0; d < ROW_SIZE; d++) {
//         if(need_rot_X[d]) active_rot_X.push_back(d);
//         if(need_rot_Y[d]) active_rot_Y.push_back(d);
//     }

//     // 增加一条日志，明确告诉你到底实际 rotate 了多少次（不影响原有核心输出）
//     cout << "[Server] 轮转操作优化: 实际执行 X=" << active_rot_X.size() 
//          << " 次, Y=" << active_rot_Y.size() << " 次 (槽位上限 " << ROW_SIZE << ")" << endl;

    
//     // 仅对有效哈希位置关系进行 X 的并发轮转
//     #pragma omp parallel for schedule(dynamic)
//     for(size_t i = 0; i < active_rot_X.size(); i++) {
//         Evaluator local_eval(context);
//         int d = active_rot_X[i];
//         local_eval.rotate_rows(enc_bf_x, d, gal_keys, rot_X[d]);
//     }

//     // 仅对有效哈希位置关系进行 Y 的并发轮转
//     #pragma omp parallel for schedule(dynamic)
//     for(size_t i = 0; i < active_rot_Y.size(); i++) {
//         Evaluator local_eval(context);
//         int d = active_rot_Y[i];
//         local_eval.rotate_rows(enc_bf_y, d, gal_keys, rot_Y[d]);
//     }

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3 (Rotate): the time is " << duration.count()/1000 << " s\n";
    
//     start = std::chrono::high_resolution_clock::now();
//     vector<Ciphertext> batch_sketches(SKETCH_SIZE);
//     #pragma omp parallel for
//     for(int s = 0; s < SKETCH_SIZE; s++) {
//         Encryptor init_enc(context, pk); Evaluator init_eval(context);
//         init_enc.encrypt_zero(batch_sketches[s]);
//         init_eval.mod_switch_to_inplace(batch_sketches[s], context.last_context_data()->parms_id()); 
//     }

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3 (Batch Sketch Initialization): the time is " << duration.count()/1000 << " s\n";
    
    
//     std::cout << "\n[Server] The batch number is " << num_batches << " \n";

//     // ==========================================
//     // 阶段4：多 Batch 并发计算与 L_n 生成
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();
//     omp_set_nested(1); 
    
//     #pragma omp parallel for schedule(dynamic)
//     for (int b = 0; b < num_batches; b++) {
//         Evaluator local_eval(context); Encryptor local_enc(context, pk); BatchEncoder local_enc_batch(context);
//         int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_unique_records - start_idx);

//         Ciphertext enc_S_x, enc_S_y; local_enc.encrypt_zero(enc_S_x); local_enc.encrypt_zero(enc_S_y);

//         map<int, vector<int>> batch_x_to_i; map<int, vector<int>> batch_y_to_i;
//         for (int i = 0; i < curr_size; i++) {
//             batch_x_to_i[unique_dataset[start_idx + i].x].push_back(i);
//             batch_y_to_i[unique_dataset[start_idx + i].y].push_back(i);
//         }

//         map<int, vector<uint64_t>> masks_X; map<int, vector<uint64_t>> masks_Y;
//         for (const auto& kv : batch_x_to_i) {
//             int x = kv.first; const auto& indices = kv.second; const auto& hx = cache_hash_x[x]; 
//             for (int k = 0; k < 3; k++) {
//                 int t_x = hx[k];
//                 for (int i : indices) {
//                     int off_x = (t_x - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE;
//                     if (masks_X.find(off_x) == masks_X.end()) masks_X[off_x] = vector<uint64_t>(encoder.slot_count(), 0);
//                     masks_X[off_x][i]++;
//                 }
//             }
//         }
//         for (const auto& kv : batch_y_to_i) {
//             int y = kv.first; const auto& indices = kv.second; const auto& hy = cache_hash_y[y]; 
//             for (int k = 0; k < 3; k++) {
//                 int t_y = hy[k];
//                 for (int i : indices) {
//                     int off_y = (t_y - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE;
//                     if (masks_Y.find(off_y) == masks_Y.end()) masks_Y[off_y] = vector<uint64_t>(encoder.slot_count(), 0);
//                     masks_Y[off_y][i]++;
//                 }
//             }
//         }

//         // Map-Reduce 模式：并发处理掩码累加
//         vector<pair<int, vector<uint64_t>>> vec_masks_X(masks_X.begin(), masks_X.end());
//         vector<pair<int, vector<uint64_t>>> vec_masks_Y(masks_Y.begin(), masks_Y.end());

//         #pragma omp parallel
//         {
//             Evaluator thread_eval(context); BatchEncoder thread_encoder(context);
//             Ciphertext local_S_x; local_enc.encrypt_zero(local_S_x); 
            
//             #pragma omp for nowait schedule(dynamic)
//             for (size_t i = 0; i < vec_masks_X.size(); i++) {
//                 int d = vec_masks_X[i].first; Plaintext pt; 
//                 thread_encoder.encode(vec_masks_X[i].second, pt);
//                 Ciphertext temp = rot_X[d]; 
//                 thread_eval.multiply_plain_inplace(temp, pt); 
//                 thread_eval.add_inplace(local_S_x, temp);
//             }
//             #pragma omp critical(x_accumulate)
//             { local_eval.add_inplace(enc_S_x, local_S_x); }
//         }

//         #pragma omp parallel
//         {
//             Evaluator thread_eval(context); BatchEncoder thread_encoder(context);
//             Ciphertext local_S_y; local_enc.encrypt_zero(local_S_y);
            
//             #pragma omp for nowait schedule(dynamic)
//             for (size_t i = 0; i < vec_masks_Y.size(); i++) {
//                 int d = vec_masks_Y[i].first; Plaintext pt; 
//                 thread_encoder.encode(vec_masks_Y[i].second, pt);
//                 Ciphertext temp = rot_Y[d]; 
//                 thread_eval.multiply_plain_inplace(temp, pt); 
//                 thread_eval.add_inplace(local_S_y, temp);
//             }
//             #pragma omp critical(y_accumulate)
//             { local_eval.add_inplace(enc_S_y, local_S_y); }
//         }

//         vector<Ciphertext> all_terms;
//         all_terms.push_back(enc_S_x); all_terms.push_back(enc_S_y);
//         for(uint64_t j = 1; j <= 2; j++) {
//             vector<uint64_t> vec_j(encoder.slot_count(), j); Plaintext pt_j; local_enc_batch.encode(vec_j, pt_j);
//             Ciphertext temp_x, temp_y;
//             local_eval.sub_plain(enc_S_x, pt_j, temp_x); local_eval.sub_plain(enc_S_y, pt_j, temp_y);
//             all_terms.push_back(temp_x); all_terms.push_back(temp_y);
//         }

//         Ciphertext enc_L_n;
//         local_eval.multiply_many(all_terms, rk, enc_L_n);

        

//         vector<Ciphertext> local_batch_sketch(SKETCH_SIZE);
//         #pragma omp parallel for
//         for(int s = 0; s < SKETCH_SIZE; s++) {
//             Encryptor init_enc(context, pk); Evaluator init_eval(context);
//             init_enc.encrypt_zero(local_batch_sketch[s]);
//             init_eval.mod_switch_to_inplace(local_batch_sketch[s], enc_L_n.parms_id());
//         }

//         map<int, vector<uint64_t>> mask_out;
//         for (int i = 0; i < curr_size; i++) {
//             auto& rec = unique_dataset[start_idx + i];
//             for (const auto& kv : rec.bucket_counts) {
//                 int s = kv.first; int count = kv.second;
//                 if (mask_out.find(s) == mask_out.end()) {
//                     mask_out[s] = vector<uint64_t>(encoder.slot_count(), 0);
//                 }
//                 mask_out[s][i] = (count * server_blind_vec[s]) % plain_mod;
//             }
//         }

//         vector<pair<int, vector<uint64_t>>> mask_out_vec(mask_out.begin(), mask_out.end());
        
//         #pragma omp parallel for schedule(dynamic)
//         for (int idx = 0; idx < (int)mask_out_vec.size(); idx++) {
//             int s = mask_out_vec[idx].first;
//             Evaluator thread_eval(context); BatchEncoder thread_enc(context);
//             Plaintext pt_m; thread_enc.encode(mask_out_vec[idx].second, pt_m); 
//             Ciphertext masked_L_n;
//             thread_eval.multiply_plain(enc_L_n, pt_m, masked_L_n); 
//             thread_eval.add_inplace(local_batch_sketch[s], masked_L_n);
//         }
        
//         #pragma omp parallel for
//         for(int s = 0; s < SKETCH_SIZE; s++) {
//             Evaluator thread_eval(context);
//             thread_eval.mod_switch_to_inplace(local_batch_sketch[s], context.last_context_data()->parms_id());
//         }

//         #pragma omp critical(global_merge)
//         {
//             for(int s=0; s<SKETCH_SIZE; s++) {
//                 local_eval.add_inplace(batch_sketches[s], local_batch_sketch[s]);
//             }
//         }
//     } 

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 4 (All Batches Process & Merge): the time is " << duration.count()/1000 << " s\n";

//     cout << "\n================ 最终 FHE 汇总 ================" << endl;
    

//     auto end_time = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration_t = end_time - start_time;
//     std::cout << "\n[Total] The overall time is " << duration_t.count()/1000 << " s\n";
    
//     // ==========================================
//     // 阶段5：并发序列化、ZSTD压缩与零拷贝网络发送
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();

//     // 开启 ZSTD 压缩（极大降低网络带宽消耗，大幅提升 I/O 速度）
//     seal::compr_mode_type compr_mode = seal::compr_mode_type::zstd;

//     // 使用 seal_byte 数组替代 stringstream，避免内部隐式扩容和字符串深拷贝
//     vector<vector<seal::seal_byte>> serialized_sketches(SKETCH_SIZE);
//     vector<uint64_t> actual_sizes(SKETCH_SIZE, 0);
    
//     // 预先计算总载荷大小，预留 S_out 的 8 字节空间
//     uint64_t total_payload_size = sizeof(uint64_t); 

//     // reduction 保证多线程累加 total_payload_size 时的线程安全
//     #pragma omp parallel for reduction(+:total_payload_size)
//     for (int s = 0; s < SKETCH_SIZE; s++) {
//         // 1. 获取 ZSTD 压缩后的上限大小并一次性分配内存
//         size_t max_size = batch_sketches[s].save_size(compr_mode);
//         serialized_sketches[s].resize(max_size);
        
//         // 2. 直接向连续内存块写入序列化数据
//         actual_sizes[s] = batch_sketches[s].save(
//             serialized_sketches[s].data(), 
//             max_size, 
//             compr_mode
//         );
        
//         // 3. 累加所需的网络流总字节数：单个长度前缀(8 bytes) + 压缩后密文长度
//         total_payload_size += sizeof(uint64_t) + actual_sizes[s];
//     }

//     // 构建最终的网络发送缓冲块，一次性 Reserve，彻底消灭 string 动态扩容开销
//     string final_payload;
//     final_payload.reserve(total_payload_size);

//     uint64_t S_out = SKETCH_SIZE;
//     final_payload.append(reinterpret_cast<const char*>(&S_out), sizeof(S_out));

//     for (int s = 0; s < SKETCH_SIZE; s++) {
//         uint64_t len = actual_sizes[s];
//         final_payload.append(reinterpret_cast<const char*>(&len), sizeof(len));
//         final_payload.append(reinterpret_cast<const char*>(serialized_sketches[s].data()), len);
//     }

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 5 (Serialization & ZSTD Compression): the time is " << duration.count()/1000.0 << " s\n";

//     cout << "[Server] 已完成 ZSTD 高效打包，准备发送 " << SKETCH_SIZE << " 个密文..." << endl;
    
//     // 此时 final_payload 是一整块连续内存，交由 boost::asio 一次性推入网卡
//     send_data(socket, final_payload);
//     end_time = std::chrono::high_resolution_clock::now();
//     duration_t = end_time - start_time;
//     std::cout << "\n[Total] The overall time is " << duration_t.count()/1000.0 << " s\n";
    
//     // send_data(socket, ss_out.str());
//     return 0;
// }































// // 这个是RCC版本
// #include "common.h"
// #include "bloomfilter.h"
// #include "MurmurHash3.h"
// #include <sstream>
// #include <chrono>
// #include <omp.h>
// #include <vector>
// #include <random>
// #include <map>
// #include <set>
// #include <fstream>
// #include <string>
// #include <algorithm>
// #include <iostream>

// using namespace std;
// using namespace seal;

// struct Record { int id; int x; int y; int o; };

// struct UniqueRecord { 
//     int x; 
//     int y; 
//     vector<int> o_list; 
//     map<int, int> bucket_counts; 
// };

// int main(int argc, char* argv[]) {
//     auto start_time = std::chrono::high_resolution_clock::now();

//     // ==========================================
//     // 阶段1：数据加载与采样
//     // ==========================================
//     auto start = std::chrono::high_resolution_clock::now();
//     if (argc != 2) { cerr << "Usage: ./server <listen_port>\n"; return 1; }

//     vector<Record> dataset;

//     std::random_device rd;
//     std::mt19937 gen(rd());
    
//     int dataset_choice = 1; 
//     std::string dataset_path;
//     int read_limit = 0;

//     if (dataset_choice == 0) {
//         dataset_path = "../dataset/spatial/quantize_spatial_1_20.csv";
//         read_limit = 21900;
//     } else {
//         dataset_path = "../dataset/brightkite/Brightkite_filter_quantized.csv";
//         read_limit = 115383;
//     }

//     double P = 0.05; 

//     struct CsvRow { int original_row; int x; int y; };
//     std::vector<CsvRow> all_csv_data;

//     std::ifstream file(dataset_path);
//     if (!file.is_open()) {
//         std::cerr << "[Error] 无法打开数据集文件: " << dataset_path << std::endl;
//         exit(1); 
//     }

//     std::string line;
//     int loaded_count = 0;
//     int current_row = 1; 

//     while (std::getline(file, line) && loaded_count < read_limit) {
//         std::stringstream ss(line);
//         std::string cell_x, cell_y;

//         if (std::getline(ss, cell_x, ',') && std::getline(ss, cell_y, ',')) {
//             try {
//                 int x = std::stoi(cell_x);
//                 int y = std::stoi(cell_y);
//                 all_csv_data.push_back({current_row, x, y});
//                 loaded_count++; 
//             } catch (const std::invalid_argument& e) {}
//         }
//         current_row++;
//     }
//     file.close();
//     std::cout << "[Server] 成功从 " << dataset_path << " 提取 " << loaded_count << " 条有效数据。" << std::endl;

//     int target_size = static_cast<int>(all_csv_data.size() * P);
//     if (target_size == 0 && !all_csv_data.empty()) { target_size = 1; }

//     std::shuffle(all_csv_data.begin(), all_csv_data.end(), gen);

//     for (int i = 0; i < target_size; i++) {
//         dataset.push_back({i, all_csv_data[i].x, all_csv_data[i].y, all_csv_data[i].original_row});
//     }

//     std::cout << "[Server] 按 P=" << P << " 比例随机抽取了 " << dataset.size() << " 条模拟数据参与 FHE 计算。" << std::endl;
    
//     auto end = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration = end - start;
//     std::cout << "Phase 1 (Data Loading): the time is " << duration.count()/1000 << " s\n";

//     boost::asio::io_context io_context; tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), stoi(argv[1])));
//     tcp::socket socket(io_context); acceptor.accept(socket);

//     SEALContext context = create_fhe_context(); BatchEncoder encoder(context);
//     uint64_t plain_mod = context.first_context_data()->parms().plain_modulus().value();

//     // 接收网络数据并统计通信量
//     string recv_str = receive_data(socket); 
//     cout << "[Comm] Server 接收到查询请求数据量: " << recv_str.size() / 1024.0 / 1024.0 << " MB" << endl;
    
//     stringstream ss_in(recv_str);
//     PublicKey pk; pk.load(context, ss_in); 
//     RelinKeys rk; rk.load(context, ss_in); 
//     GaloisKeys gal_keys; gal_keys.load(context, ss_in);
//     // 【已删除】不再接收、加载私钥 sk


//     // ==========================================
//     // 阶段2：接收数据 (已移除数据去重优化)
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();

//     int M; ss_in.read(reinterpret_cast<char*>(&M), sizeof(M));
//     uint64_t size_x, size_y;
//     ss_in.read(reinterpret_cast<char*>(&size_x), sizeof(size_x)); string str_x(size_x, '\0'); ss_in.read(&str_x[0], size_x); stringstream sx(str_x); Ciphertext enc_bf_x; enc_bf_x.load(context, sx);
//     ss_in.read(reinterpret_cast<char*>(&size_y), sizeof(size_y)); string str_y(size_y, '\0'); ss_in.read(&str_y[0], size_y); stringstream sy(str_y); Ciphertext enc_bf_y; enc_bf_y.load(context, sy);

//     int total_records = dataset.size();
    
//     cout << "[Server] 接收密文完毕，当前准备处理的总数据量: " << total_records << " 条记录。" << endl;

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 2 (Recv Data): the time is " << duration.count()/1000 << " s\n";

//     // ==========================================
//     // 阶段3/4 (重构版)：基于 (l, n, h) 复杂度的代数计算框架
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();

//     // 1. 定义新协议的复杂度参数
//     int l_1 = 20, n_1 = 12; // X轴参数
//     int l_2 = 17, n_2 = 11; // Y轴参数
//     int h = 4;            // ct-ct mul 操作次数

//     cout << "[Server] 协议切换: 准备对 " << total_records << " 条记录的 X 和 Y 逐条执行定制化同态运算..." << endl;

//     // 因为不再去重，我们需要把每条记录的计算结果都存下来，长度就是 total_records
//     vector<Ciphertext> result_X(total_records);
//     vector<Ciphertext> result_Y(total_records);

//     // ---------------------------------------------------------
//     // 针对原始数据集中的【每一条记录】的 X 执行规定的运算组合
//     // ---------------------------------------------------------
//     #pragma omp parallel for schedule(dynamic)
//     for (size_t idx = 0; idx < dataset.size(); idx++) {
//         int x = dataset[idx].x;
//         Evaluator local_eval(context);
//         BatchEncoder local_encoder(context);
//         Ciphertext current_ct_x = enc_bf_x; 

//         // [操作 1] (n_1 + 1) 次 Rotate
//         for (int i = 0; i < n_1 + 1; i++) {
//             local_eval.rotate_rows(current_ct_x, 1, gal_keys, current_ct_x);
//         }

//         // [操作 2] (l_1 + 1) 次 明文跟密文相乘 (pt-ct mul)
//         for (int i = 0; i < l_1 + 1; i++) {
//             vector<uint64_t> mask_vec_mul(local_encoder.slot_count(), (i + 1) % plain_mod);
//             Plaintext pt_mul_mask;
//             local_encoder.encode(mask_vec_mul, pt_mul_mask);
//             local_eval.multiply_plain_inplace(current_ct_x, pt_mul_mask);
//         }

//         // [操作 3] (n_1 + l_1) 次 明文跟密文相加 (pt-ct add)
//         for (int i = 0; i < n_1 + l_1; i++) {
//             vector<uint64_t> mask_vec_add(local_encoder.slot_count(), 5ULL % plain_mod);
//             Plaintext pt_add_mask;
//             local_encoder.encode(mask_vec_add, pt_add_mask);
//             local_eval.add_plain_inplace(current_ct_x, pt_add_mask);
//         }

//         // [操作 4] h 次 密文跟密文相乘 (ct-ct mul)
//         for (int i = 0; i < h; i++) {
//             Ciphertext ct_other = enc_bf_x; 
//             local_eval.multiply_inplace(current_ct_x, ct_other);
//             local_eval.relinearize_inplace(current_ct_x, rk); // 【关键】降维
//         }

//         // 将算完的密文按照数据集的原始索引存入
//         result_X[idx] = current_ct_x; 
//     }

//     // // ---------------------------------------------------------
//     // // 针对原始数据集中的【每一条记录】的 Y 执行规定的运算组合
//     // // ---------------------------------------------------------
//     // #pragma omp parallel for schedule(dynamic)
//     // for (size_t idx = 0; idx < dataset.size(); idx++) {
//     //     int y = dataset[idx].y;
//     //     Evaluator local_eval(context);
//     //     BatchEncoder local_encoder(context);
//     //     Ciphertext current_ct_y = enc_bf_y;

//     //     // [操作 1] (n_2 + 1) 次 Rotate
//     //     for (int i = 0; i < n_2 + 1; i++) {
//     //         local_eval.rotate_rows(current_ct_y, 1, gal_keys, current_ct_y);
//     //     }

//     //     // [操作 2] (l_2 + 1) 次 明文跟密文相乘 (pt-ct mul)
//     //     for (int i = 0; i < l_2 + 1; i++) {
//     //         vector<uint64_t> mask_vec_mul(local_encoder.slot_count(), (i + 1) % plain_mod);
//     //         Plaintext pt_mul_mask;
//     //         local_encoder.encode(mask_vec_mul, pt_mul_mask);
//     //         local_eval.multiply_plain_inplace(current_ct_y, pt_mul_mask);
//     //     }

//     //     // [操作 3] (n_2 + l_2) 次 明文跟密文相加 (pt-ct add)
//     //     for (int i = 0; i < n_2 + l_2; i++) {
//     //         vector<uint64_t> mask_vec_add(local_encoder.slot_count(), 5ULL % plain_mod);
//     //         Plaintext pt_add_mask;
//     //         local_encoder.encode(mask_vec_add, pt_add_mask);
//     //         local_eval.add_plain_inplace(current_ct_y, pt_add_mask);
//     //     }

//     //     // [操作 4] h 次 密文跟密文相乘 (ct-ct mul)
//     //     for (int i = 0; i < h; i++) {
//     //         Ciphertext ct_other = enc_bf_y; 
//     //         local_eval.multiply_inplace(current_ct_y, ct_other);
//     //         local_eval.relinearize_inplace(current_ct_y, rk); // 【关键】降维
//     //     }

//     //     // 将算完的密文按照数据集的原始索引存入
//     //     result_Y[idx] = current_ct_y; 
//     // }

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3/4 (Raw Data Algebra Computation): the time is " << duration.count()/1000 << " s\n";

//     // ==========================================
//     // 阶段5：并发序列化、ZSTD压缩与零拷贝网络发送
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();

//     // 生成 SKETCH_SIZE 个桶，为了通信量模拟真实性，这里用合法的密文填满它
//     vector<Ciphertext> batch_sketches(SKETCH_SIZE);
//     Ciphertext dummy_val;
//     Evaluator eval_main(context);
//     eval_main.mod_switch_to(enc_bf_x, context.last_context_data()->parms_id(), dummy_val);
    
//     #pragma omp parallel for
//     for(int s = 0; s < SKETCH_SIZE; s++) {
//         batch_sketches[s] = dummy_val;
//     }

//     // 开启 ZSTD 压缩
//     seal::compr_mode_type compr_mode = seal::compr_mode_type::zstd;
//     vector<vector<seal::seal_byte>> serialized_sketches(SKETCH_SIZE);
//     vector<uint64_t> actual_sizes(SKETCH_SIZE, 0);
    
//     uint64_t total_payload_size = sizeof(uint64_t); 

//     #pragma omp parallel for reduction(+:total_payload_size)
//     for (int s = 0; s < SKETCH_SIZE; s++) {
//         size_t max_size = batch_sketches[s].save_size(compr_mode);
//         serialized_sketches[s].resize(max_size);
//         actual_sizes[s] = batch_sketches[s].save(
//             serialized_sketches[s].data(), 
//             max_size, 
//             compr_mode
//         );
//         total_payload_size += sizeof(uint64_t) + actual_sizes[s];
//     }

//     string final_payload;
//     final_payload.reserve(total_payload_size);

//     uint64_t S_out = SKETCH_SIZE;
//     final_payload.append(reinterpret_cast<const char*>(&S_out), sizeof(S_out));

//     for (int s = 0; s < SKETCH_SIZE; s++) {
//         uint64_t len = actual_sizes[s];
//         final_payload.append(reinterpret_cast<const char*>(&len), sizeof(len));
//         final_payload.append(reinterpret_cast<const char*>(serialized_sketches[s].data()), len);
//     }

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 5 (Serialization & ZSTD Compression): the time is " << duration.count()/1000.0 << " s\n";

//     cout << "[Comm] Server 即将发送给 Center 的压缩后结果数据量: " << final_payload.size() / 1024.0 / 1024.0 << " MB" << endl;
//     cout << "[Server] 已完成 ZSTD 高效打包，准备发送 " << SKETCH_SIZE << " 个密文..." << endl;
    
//     send_data(socket, final_payload);
    
//     auto end_time = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration_t = end_time - start_time;
//     std::cout << "\n[Total] The overall time is " << duration_t.count()/1000.0 << " s\n";
    
//     return 0;
// }






















    // // ==========================================
    // // 阶段2：接收数据与降维去重
    // // ==========================================
    // start = std::chrono::high_resolution_clock::now();

    // int M; ss_in.read(reinterpret_cast<char*>(&M), sizeof(M));
    // uint64_t size_x, size_y;
    // ss_in.read(reinterpret_cast<char*>(&size_x), sizeof(size_x)); string str_x(size_x, '\0'); ss_in.read(&str_x[0], size_x); stringstream sx(str_x); Ciphertext enc_bf_x; enc_bf_x.load(context, sx);
    // ss_in.read(reinterpret_cast<char*>(&size_y), sizeof(size_y)); string str_y(size_y, '\0'); ss_in.read(&str_y[0], size_y); stringstream sy(str_y); Ciphertext enc_bf_y; enc_bf_y.load(context, sy);

    // map<pair<int, int>, vector<int>> unique_map;
    // for (const auto& rec : dataset) {
    //     unique_map[{rec.x, rec.y}].push_back(rec.o);
    // }
    
    // vector<UniqueRecord> unique_dataset;
    // for (const auto& kv : unique_map) {
    //     UniqueRecord ur;
    //     ur.x = kv.first.first;
    //     ur.y = kv.first.second;
    //     ur.o_list = kv.second;
    //     for (int o_val : ur.o_list) {
    //         int s = (int)hash_result(o_val, SKETCH_SIZE, 0);
    //         ur.bucket_counts[s]++;
    //     }
    //     unique_dataset.push_back(ur);
    // }
    // int total_unique_records = unique_dataset.size();
    
    // cout << "[Server] 数据去重优化: 提取出 " << total_unique_records << " 个唯一的 (x, y) 组合以降低 FHE 计算开销。" << endl;

    // end = std::chrono::high_resolution_clock::now();
    // duration = end - start;
    // std::cout << "Phase 2 (Recv & Dedup): the time is " << duration.count()/1000 << " s\n";

    // // ==========================================
    // // 阶段3/4 (重构版)：基于 (l, n, h) 复杂度的全新代数计算框架
    // // ==========================================
    // start = std::chrono::high_resolution_clock::now();

    // // 1. 定义新协议的复杂度参数 (请根据你的理论推导调整)
    // int l_1 = 20, n_1 = 12; // X轴参数
    // int l_2 = 17, n_2 = 11; // Y轴参数
    // int h = 4;            // ct-ct mul 操作次数

    // // 2. 提取数据集中所有全局唯一的 X 和 Y
    // set<int> unique_x_set;
    // set<int> unique_y_set;
    // for (const auto& rec : unique_dataset) {
    //     unique_x_set.insert(rec.x);
    //     unique_y_set.insert(rec.y);
    // }
    
    // // 转换为 vector 以便 OpenMP 随机访问
    // vector<int> unique_x_vec(unique_x_set.begin(), unique_x_set.end());
    // vector<int> unique_y_vec(unique_y_set.begin(), unique_y_set.end());

    // cout << "[Server] 协议切换: 准备对 " << unique_x_vec.size() << " 个唯一 X 和 " 
    //      << unique_y_vec.size() << " 个唯一 Y 执行定制化同态运算..." << endl;

    // map<int, Ciphertext> result_X_map;
    // map<int, Ciphertext> result_Y_map;

    // // ---------------------------------------------------------
    // // 针对每个唯一 X 执行规定的运算组合
    // // ---------------------------------------------------------
    // #pragma omp parallel for schedule(dynamic)
    // for (size_t idx = 0; idx < unique_x_vec.size(); idx++) {
    //     int x = unique_x_vec[idx];
    //     Evaluator local_eval(context);
    //     BatchEncoder local_encoder(context);
    //     Ciphertext current_ct_x = enc_bf_x; 

    //     // [操作 1] (n_1 + 1) 次 Rotate
    //     for (int i = 0; i < n_1 + 1; i++) {
    //         local_eval.rotate_rows(current_ct_x, 1, gal_keys, current_ct_x);
    //     }

    //     // [操作 2] (l_1 + 1) 次 明文跟密文相乘 (pt-ct mul)
    //     for (int i = 0; i < l_1 + 1; i++) {
    //         vector<uint64_t> mask_vec_mul(local_encoder.slot_count(), (i + 1) % plain_mod);
    //         Plaintext pt_mul_mask;
    //         local_encoder.encode(mask_vec_mul, pt_mul_mask);
    //         local_eval.multiply_plain_inplace(current_ct_x, pt_mul_mask);
    //     }

    //     // [操作 3] (n_1 + l_1) 次 明文跟密文相加 (pt-ct add)
    //     for (int i = 0; i < n_1 + l_1; i++) {
    //         vector<uint64_t> mask_vec_add(local_encoder.slot_count(), 5ULL % plain_mod);
    //         Plaintext pt_add_mask;
    //         local_encoder.encode(mask_vec_add, pt_add_mask);
    //         local_eval.add_plain_inplace(current_ct_x, pt_add_mask);
    //     }

    //     // [操作 4] h 次 密文跟密文相乘 (ct-ct mul)
    //     for (int i = 0; i < h; i++) {
    //         Ciphertext ct_other = enc_bf_x; 
    //         local_eval.multiply_inplace(current_ct_x, ct_other);
    //         local_eval.relinearize_inplace(current_ct_x, rk); // 【关键】降维
    //     }

    //     #pragma omp critical
    //     { result_X_map[x] = current_ct_x; }
    // }

    // // ---------------------------------------------------------
    // // 针对每个唯一 Y 执行规定的运算组合
    // // ---------------------------------------------------------
    // #pragma omp parallel for schedule(dynamic)
    // for (size_t idx = 0; idx < unique_y_vec.size(); idx++) {
    //     int y = unique_y_vec[idx];
    //     Evaluator local_eval(context);
    //     BatchEncoder local_encoder(context);
    //     Ciphertext current_ct_y = enc_bf_y;

    //     // [操作 1] (n_2 + 1) 次 Rotate
    //     for (int i = 0; i < n_2 + 1; i++) {
    //         local_eval.rotate_rows(current_ct_y, 1, gal_keys, current_ct_y);
    //     }

    //     // [操作 2] (l_2 + 1) 次 明文跟密文相乘 (pt-ct mul)
    //     for (int i = 0; i < l_2 + 1; i++) {
    //         vector<uint64_t> mask_vec_mul(local_encoder.slot_count(), (i + 1) % plain_mod);
    //         Plaintext pt_mul_mask;
    //         local_encoder.encode(mask_vec_mul, pt_mul_mask);
    //         local_eval.multiply_plain_inplace(current_ct_y, pt_mul_mask);
    //     }

    //     // [操作 3] (n_2 + l_2) 次 明文跟密文相加 (pt-ct add)
    //     for (int i = 0; i < n_2 + l_2; i++) {
    //         vector<uint64_t> mask_vec_add(local_encoder.slot_count(), 5ULL % plain_mod);
    //         Plaintext pt_add_mask;
    //         local_encoder.encode(mask_vec_add, pt_add_mask);
    //         local_eval.add_plain_inplace(current_ct_y, pt_add_mask);
    //     }

    //     // [操作 4] h 次 密文跟密文相乘 (ct-ct mul)
    //     for (int i = 0; i < h; i++) {
    //         Ciphertext ct_other = enc_bf_y; 
    //         local_eval.multiply_inplace(current_ct_y, ct_other);
    //         local_eval.relinearize_inplace(current_ct_y, rk); // 【关键】降维
    //     }

    //     #pragma omp critical
    //     { result_Y_map[y] = current_ct_y; }
    // }

    // end = std::chrono::high_resolution_clock::now();
    // duration = end - start;
    // std::cout << "Phase 3/4 (Custom Algebra Computation): the time is " << duration.count()/1000 << " s\n";






    // // ==========================================
    // // 阶段2：接收数据 (已移除数据去重优化)
    // // ==========================================
    // start = std::chrono::high_resolution_clock::now();

    // int M; ss_in.read(reinterpret_cast<char*>(&M), sizeof(M));
    // uint64_t size_x, size_y;
    // ss_in.read(reinterpret_cast<char*>(&size_x), sizeof(size_x)); string str_x(size_x, '\0'); ss_in.read(&str_x[0], size_x); stringstream sx(str_x); Ciphertext enc_bf_x; enc_bf_x.load(context, sx);
    // ss_in.read(reinterpret_cast<char*>(&size_y), sizeof(size_y)); string str_y(size_y, '\0'); ss_in.read(&str_y[0], size_y); stringstream sy(str_y); Ciphertext enc_bf_y; enc_bf_y.load(context, sy);

    // int total_records = dataset.size();
    
    // cout << "[Server] 接收密文完毕，当前准备处理的总数据量: " << total_records << " 条记录。" << endl;

    // end = std::chrono::high_resolution_clock::now();
    // duration = end - start;
    // std::cout << "Phase 2 (Recv Data): the time is " << duration.count()/1000 << " s\n";

    // // ==========================================
    // // 阶段3/4 (重构版)：基于 (l, n, h) 复杂度的代数计算框架
    // // ==========================================
    // start = std::chrono::high_resolution_clock::now();

    // // 1. 定义新协议的复杂度参数
    // int l_1 = 20, n_1 = 12; // X轴参数
    // int l_2 = 17, n_2 = 11; // Y轴参数
    // int h = 4;            // ct-ct mul 操作次数

    // cout << "[Server] 协议切换: 准备对 " << total_records << " 条记录的 X 和 Y 逐条执行定制化同态运算..." << endl;

    // // 因为不再去重，我们需要把每条记录的计算结果都存下来，长度就是 total_records
    // vector<Ciphertext> result_X(total_records);
    // vector<Ciphertext> result_Y(total_records);

    // // ---------------------------------------------------------
    // // 针对原始数据集中的【每一条记录】的 X 执行规定的运算组合
    // // ---------------------------------------------------------
    // #pragma omp parallel for schedule(dynamic)
    // for (size_t idx = 0; idx < dataset.size(); idx++) {
    //     int x = dataset[idx].x;
    //     Evaluator local_eval(context);
    //     BatchEncoder local_encoder(context);
    //     Ciphertext current_ct_x = enc_bf_x; 

    //     // [操作 1] (n_1 + 1) 次 Rotate
    //     for (int i = 0; i < n_1 + 1; i++) {
    //         local_eval.rotate_rows(current_ct_x, 1, gal_keys, current_ct_x);
    //     }

    //     // [操作 2] (l_1 + 1) 次 明文跟密文相乘 (pt-ct mul)
    //     for (int i = 0; i < l_1 + 1; i++) {
    //         vector<uint64_t> mask_vec_mul(local_encoder.slot_count(), (i + 1) % plain_mod);
    //         Plaintext pt_mul_mask;
    //         local_encoder.encode(mask_vec_mul, pt_mul_mask);
    //         local_eval.multiply_plain_inplace(current_ct_x, pt_mul_mask);
    //     }

    //     // [操作 3] (n_1 + l_1) 次 明文跟密文相加 (pt-ct add)
    //     for (int i = 0; i < n_1 + l_1; i++) {
    //         vector<uint64_t> mask_vec_add(local_encoder.slot_count(), 5ULL % plain_mod);
    //         Plaintext pt_add_mask;
    //         local_encoder.encode(mask_vec_add, pt_add_mask);
    //         local_eval.add_plain_inplace(current_ct_x, pt_add_mask);
    //     }

    //     // [操作 4] h 次 密文跟密文相乘 (ct-ct mul)
    //     for (int i = 0; i < h; i++) {
    //         Ciphertext ct_other = enc_bf_x; 
    //         local_eval.multiply_inplace(current_ct_x, ct_other);
    //         local_eval.relinearize_inplace(current_ct_x, rk); // 【关键】降维
    //     }

    //     // 将算完的密文按照数据集的原始索引存入
    //     result_X[idx] = current_ct_x; 
    // }

    // // ---------------------------------------------------------
    // // 针对原始数据集中的【每一条记录】的 Y 执行规定的运算组合
    // // ---------------------------------------------------------
    // #pragma omp parallel for schedule(dynamic)
    // for (size_t idx = 0; idx < dataset.size(); idx++) {
    //     int y = dataset[idx].y;
    //     Evaluator local_eval(context);
    //     BatchEncoder local_encoder(context);
    //     Ciphertext current_ct_y = enc_bf_y;

    //     // [操作 1] (n_2 + 1) 次 Rotate
    //     for (int i = 0; i < n_2 + 1; i++) {
    //         local_eval.rotate_rows(current_ct_y, 1, gal_keys, current_ct_y);
    //     }

    //     // [操作 2] (l_2 + 1) 次 明文跟密文相乘 (pt-ct mul)
    //     for (int i = 0; i < l_2 + 1; i++) {
    //         vector<uint64_t> mask_vec_mul(local_encoder.slot_count(), (i + 1) % plain_mod);
    //         Plaintext pt_mul_mask;
    //         local_encoder.encode(mask_vec_mul, pt_mul_mask);
    //         local_eval.multiply_plain_inplace(current_ct_y, pt_mul_mask);
    //     }

    //     // [操作 3] (n_2 + l_2) 次 明文跟密文相加 (pt-ct add)
    //     for (int i = 0; i < n_2 + l_2; i++) {
    //         vector<uint64_t> mask_vec_add(local_encoder.slot_count(), 5ULL % plain_mod);
    //         Plaintext pt_add_mask;
    //         local_encoder.encode(mask_vec_add, pt_add_mask);
    //         local_eval.add_plain_inplace(current_ct_y, pt_add_mask);
    //     }

    //     // [操作 4] h 次 密文跟密文相乘 (ct-ct mul)
    //     for (int i = 0; i < h; i++) {
    //         Ciphertext ct_other = enc_bf_y; 
    //         local_eval.multiply_inplace(current_ct_y, ct_other);
    //         local_eval.relinearize_inplace(current_ct_y, rk); // 【关键】降维
    //     }

    //     // 将算完的密文按照数据集的原始索引存入
    //     result_Y[idx] = current_ct_y; 
    // }

    // end = std::chrono::high_resolution_clock::now();
    // duration = end - start;
    // std::cout << "Phase 3/4 (Raw Data Algebra Computation): the time is " << duration.count()/1000 << " s\n";







// #include "common.h"
// #include "bloomfilter.h"
// #include "MurmurHash3.h"
// #include <sstream>
// #include <chrono>
// #include <omp.h>
// #include <vector>
// #include <random>
// #include <map>
// #include <fstream>
// #include <string>
// #include <algorithm>
// #include <iostream>

// using namespace std;
// using namespace seal;

// struct Record { int id; int x; int y; int o; };

// struct UniqueRecord { 
//     int x; 
//     int y; 
//     vector<int> o_list; 
//     map<int, int> bucket_counts; 
// };

// int main(int argc, char* argv[]) {
//     auto start_time = std::chrono::high_resolution_clock::now();

//     // 这版的问题，去重不够简洁，直接重复结合S_x结果，那这个可能就多出来点乘法操作
//     // 这版改的是通信过程
//     // 最后才解决传输sk问题

//     // ==========================================
//     // 阶段1：数据加载与采样
//     // ==========================================
//     auto start = std::chrono::high_resolution_clock::now();
//     if (argc != 2) { cerr << "Usage: ./server <listen_port>\n"; return 1; }

//     vector<Record> dataset;

//     std::random_device rd;
//     std::mt19937 gen(rd());
//     std::uniform_int_distribution<> dist_x(0, 100);
//     std::uniform_int_distribution<> dist_y(0, 100);
//     std::uniform_int_distribution<> dist_x_miss(0, 1000);
//     std::uniform_int_distribution<> dist_y_miss(0, 1000);
//     std::uniform_int_distribution<> dist_o(10000, 99999);

//     int dataset_choice = 1; 
//     std::string dataset_path;
//     int read_limit = 0;

//     if (dataset_choice == 0) {
//         dataset_path = "../dataset/spatial/quantize_spatial_1_20.csv";
//         read_limit = 21900;
//     } else {
//         dataset_path = "../dataset/brightkite/Brightkite_filter_quantized.csv";
//         read_limit = 115383;
//     }

//     double P = 0.2; 

//     struct CsvRow { int original_row; int x; int y; };
//     std::vector<CsvRow> all_csv_data;

//     std::ifstream file(dataset_path);
//     if (!file.is_open()) {
//         std::cerr << "[Error] 无法打开数据集文件: " << dataset_path << std::endl;
//         exit(1); 
//     }

//     std::string line;
//     int loaded_count = 0;
//     int current_row = 1; 

//     while (std::getline(file, line) && loaded_count < read_limit) {
//         std::stringstream ss(line);
//         std::string cell_x, cell_y;

//         if (std::getline(ss, cell_x, ',') && std::getline(ss, cell_y, ',')) {
//             try {
//                 int x = std::stoi(cell_x);
//                 int y = std::stoi(cell_y);
//                 all_csv_data.push_back({current_row, x, y});
//                 loaded_count++; 
//             } catch (const std::invalid_argument& e) {}
//         }
//         current_row++;
//     }
//     file.close();
//     std::cout << "[Server] 成功从 " << dataset_path << " 提取 " << loaded_count << " 条有效数据。" << std::endl;

//     int target_size = static_cast<int>(all_csv_data.size() * P);
//     if (target_size == 0 && !all_csv_data.empty()) { target_size = 1; }

//     std::shuffle(all_csv_data.begin(), all_csv_data.end(), gen);

//     for (int i = 0; i < target_size; i++) {
//         dataset.push_back({i, all_csv_data[i].x, all_csv_data[i].y, all_csv_data[i].original_row});
//     }

//     std::cout << "[Server] 按 P=" << P << " 比例随机抽取了 " << dataset.size() << " 条模拟数据参与 FHE 计算。" << std::endl;
    
//     auto end = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration = end - start;
//     std::cout << "Phase 1 (Data Loading): the time is " << duration.count()/1000 << " s\n";

//     boost::asio::io_context io_context; tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), stoi(argv[1])));
//     tcp::socket socket(io_context); acceptor.accept(socket);

//     SEALContext context = create_fhe_context(); BatchEncoder encoder(context);
//     uint64_t plain_mod = context.first_context_data()->parms().plain_modulus().value();

//     string recv_str = receive_data(socket); stringstream ss_in(recv_str);
//     PublicKey pk; pk.load(context, ss_in); RelinKeys rk; rk.load(context, ss_in); GaloisKeys gal_keys; gal_keys.load(context, ss_in);
//     SecretKey sk; sk.load(context, ss_in); Decryptor debug_dec(context, sk);

//     // ==========================================
//     // 阶段2：接收数据与降维去重
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();

//     int M; ss_in.read(reinterpret_cast<char*>(&M), sizeof(M));
//     uint64_t size_x, size_y;
//     ss_in.read(reinterpret_cast<char*>(&size_x), sizeof(size_x)); string str_x(size_x, '\0'); ss_in.read(&str_x[0], size_x); stringstream sx(str_x); Ciphertext enc_bf_x; enc_bf_x.load(context, sx);
//     ss_in.read(reinterpret_cast<char*>(&size_y), sizeof(size_y)); string str_y(size_y, '\0'); ss_in.read(&str_y[0], size_y); stringstream sy(str_y); Ciphertext enc_bf_y; enc_bf_y.load(context, sy);

//     cout << "\n[Noise Budget-1] 初始接收密文 enc_bf_x 剩余噪声: " 
//          << debug_dec.invariant_noise_budget(enc_bf_x) << " bits" << endl;

//     map<pair<int, int>, vector<int>> unique_map;
//     for (const auto& rec : dataset) {
//         unique_map[{rec.x, rec.y}].push_back(rec.o);
//     }
    
//     vector<UniqueRecord> unique_dataset;
//     for (const auto& kv : unique_map) {
//         UniqueRecord ur;
//         ur.x = kv.first.first;
//         ur.y = kv.first.second;
//         ur.o_list = kv.second;
//         for (int o_val : ur.o_list) {
//             int s = (int)hash_result(o_val, SKETCH_SIZE, 0);
//             ur.bucket_counts[s]++;
//         }
//         unique_dataset.push_back(ur);
//     }
//     int total_unique_records = unique_dataset.size();
    
//     cout << "[Server] 数据去重优化: 提取出 " << total_unique_records << " 个唯一的 (x, y) 组合以降低 FHE 计算开销。" << endl;

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 2 (Recv & Dedup): the time is " << duration.count()/1000 << " s\n";

//     // ==========================================
//     // 阶段3：哈希缓存与并发旋转预计算
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();

//     map<int, vector<int>> cache_hash_x;
//     map<int, vector<int>> cache_hash_y;
//     for (const auto& rec : unique_dataset) {
//         if (cache_hash_x.find(rec.x) == cache_hash_x.end()) {
//             vector<int> hx(3);
//             for (int k = 0; k < 3; k++) hx[k] = (int)hash_result(rec.x, M, k);
//             cache_hash_x[rec.x] = hx;
//         }
//         if (cache_hash_y.find(rec.y) == cache_hash_y.end()) {
//             vector<int> hy(3);
//             for (int k = 0; k < 3; k++) hy[k] = (int)hash_result(rec.y, M, k);
//             cache_hash_y[rec.y] = hy;
//         }
//     }

//     vector<uint64_t> server_blind_vec(SKETCH_SIZE, 0ULL);
//     std::uniform_int_distribution<uint64_t> dist_blind(1, 100);
//     for(int s = 0; s < SKETCH_SIZE; s++) {
//         server_blind_vec[s] = dist_blind(gen); 
//     }

//     int ROW_SIZE = encoder.slot_count() / 2; 
//     int num_batches = ceil((double)total_unique_records / ROW_SIZE); 

//     vector<bool> need_rot_X(ROW_SIZE, false); vector<bool> need_rot_Y(ROW_SIZE, false);
//     for (int b = 0; b < num_batches; b++) {
//         int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_unique_records - start_idx);
//         for (int i = 0; i < curr_size; i++) {
//             auto& rec = unique_dataset[start_idx + i];
//             const auto& hx = cache_hash_x[rec.x];
//             for (int k = 0; k < 3; k++) {
//                 int off_x = (hx[k] - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE; need_rot_X[off_x] = true;
//             }
//             const auto& hy = cache_hash_y[rec.y];
//             for (int k = 0; k < 3; k++) {
//                 int off_y = (hy[k] - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE; need_rot_Y[off_y] = true;
//             }
//         }
//     }

//     // 【修改点】：直接 OMP 并行遍历 ROW_SIZE，数据量大时大概率 4096 次全跑，取消 active_X 额外开销
//     vector<Ciphertext> rot_X(ROW_SIZE), rot_Y(ROW_SIZE);

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3 (Hash Cache): the time is " << duration.count()/1000 << " s\n";

//     start = std::chrono::high_resolution_clock::now();
    
//     // 【修改点】：统计实际不重叠的、需要的轮转步长集合，按需分配并行任务
//     vector<int> active_rot_X;
//     vector<int> active_rot_Y;
//     for(int d = 0; d < ROW_SIZE; d++) {
//         if(need_rot_X[d]) active_rot_X.push_back(d);
//         if(need_rot_Y[d]) active_rot_Y.push_back(d);
//     }

//     // 增加一条日志，明确告诉你到底实际 rotate 了多少次（不影响原有核心输出）
//     cout << "[Server] 轮转操作优化: 实际执行 X=" << active_rot_X.size() 
//          << " 次, Y=" << active_rot_Y.size() << " 次 (槽位上限 " << ROW_SIZE << ")" << endl;

    
//     // 仅对有效哈希位置关系进行 X 的并发轮转
//     #pragma omp parallel for schedule(dynamic)
//     for(size_t i = 0; i < active_rot_X.size(); i++) {
//         Evaluator local_eval(context);
//         int d = active_rot_X[i];
//         local_eval.rotate_rows(enc_bf_x, d, gal_keys, rot_X[d]);
//     }

//     // 仅对有效哈希位置关系进行 Y 的并发轮转
//     #pragma omp parallel for schedule(dynamic)
//     for(size_t i = 0; i < active_rot_Y.size(); i++) {
//         Evaluator local_eval(context);
//         int d = active_rot_Y[i];
//         local_eval.rotate_rows(enc_bf_y, d, gal_keys, rot_Y[d]);
//     }

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3 (Rotate): the time is " << duration.count()/1000 << " s\n";
    
//     start = std::chrono::high_resolution_clock::now();
//     vector<Ciphertext> batch_sketches(SKETCH_SIZE);
//     #pragma omp parallel for
//     for(int s = 0; s < SKETCH_SIZE; s++) {
//         Encryptor init_enc(context, pk); Evaluator init_eval(context);
//         init_enc.encrypt_zero(batch_sketches[s]);
//         init_eval.mod_switch_to_inplace(batch_sketches[s], context.last_context_data()->parms_id()); 
//     }

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3 (Batch Sketch Initialization): the time is " << duration.count()/1000 << " s\n";
    
//     int global_fhe_hit_count = 0;
//     std::cout << "\n[Server] The batch number is " << num_batches << " \n";

//     // ==========================================
//     // 阶段4：多 Batch 并发计算与 L_n 生成
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();
//     omp_set_nested(1); 
    
//     #pragma omp parallel for schedule(dynamic)
//     for (int b = 0; b < num_batches; b++) {
//         Evaluator local_eval(context); Encryptor local_enc(context, pk); BatchEncoder local_enc_batch(context);
//         int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_unique_records - start_idx);

//         Ciphertext enc_S_x, enc_S_y; local_enc.encrypt_zero(enc_S_x); local_enc.encrypt_zero(enc_S_y);

//         map<int, vector<int>> batch_x_to_i; map<int, vector<int>> batch_y_to_i;
//         for (int i = 0; i < curr_size; i++) {
//             batch_x_to_i[unique_dataset[start_idx + i].x].push_back(i);
//             batch_y_to_i[unique_dataset[start_idx + i].y].push_back(i);
//         }

//         map<int, vector<uint64_t>> masks_X; map<int, vector<uint64_t>> masks_Y;
//         for (const auto& kv : batch_x_to_i) {
//             int x = kv.first; const auto& indices = kv.second; const auto& hx = cache_hash_x[x]; 
//             for (int k = 0; k < 3; k++) {
//                 int t_x = hx[k];
//                 for (int i : indices) {
//                     int off_x = (t_x - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE;
//                     if (masks_X.find(off_x) == masks_X.end()) masks_X[off_x] = vector<uint64_t>(encoder.slot_count(), 0);
//                     masks_X[off_x][i]++;
//                 }
//             }
//         }
//         for (const auto& kv : batch_y_to_i) {
//             int y = kv.first; const auto& indices = kv.second; const auto& hy = cache_hash_y[y]; 
//             for (int k = 0; k < 3; k++) {
//                 int t_y = hy[k];
//                 for (int i : indices) {
//                     int off_y = (t_y - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE;
//                     if (masks_Y.find(off_y) == masks_Y.end()) masks_Y[off_y] = vector<uint64_t>(encoder.slot_count(), 0);
//                     masks_Y[off_y][i]++;
//                 }
//             }
//         }

//         // Map-Reduce 模式：并发处理掩码累加
//         vector<pair<int, vector<uint64_t>>> vec_masks_X(masks_X.begin(), masks_X.end());
//         vector<pair<int, vector<uint64_t>>> vec_masks_Y(masks_Y.begin(), masks_Y.end());

//         #pragma omp parallel
//         {
//             Evaluator thread_eval(context); BatchEncoder thread_encoder(context);
//             Ciphertext local_S_x; local_enc.encrypt_zero(local_S_x); 
            
//             #pragma omp for nowait schedule(dynamic)
//             for (size_t i = 0; i < vec_masks_X.size(); i++) {
//                 int d = vec_masks_X[i].first; Plaintext pt; 
//                 thread_encoder.encode(vec_masks_X[i].second, pt);
//                 Ciphertext temp = rot_X[d]; 
//                 thread_eval.multiply_plain_inplace(temp, pt); 
//                 thread_eval.add_inplace(local_S_x, temp);
//             }
//             #pragma omp critical(x_accumulate)
//             { local_eval.add_inplace(enc_S_x, local_S_x); }
//         }

//         #pragma omp parallel
//         {
//             Evaluator thread_eval(context); BatchEncoder thread_encoder(context);
//             Ciphertext local_S_y; local_enc.encrypt_zero(local_S_y);
            
//             #pragma omp for nowait schedule(dynamic)
//             for (size_t i = 0; i < vec_masks_Y.size(); i++) {
//                 int d = vec_masks_Y[i].first; Plaintext pt; 
//                 thread_encoder.encode(vec_masks_Y[i].second, pt);
//                 Ciphertext temp = rot_Y[d]; 
//                 thread_eval.multiply_plain_inplace(temp, pt); 
//                 thread_eval.add_inplace(local_S_y, temp);
//             }
//             #pragma omp critical(y_accumulate)
//             { local_eval.add_inplace(enc_S_y, local_S_y); }
//         }

//         vector<Ciphertext> all_terms;
//         all_terms.push_back(enc_S_x); all_terms.push_back(enc_S_y);
//         for(uint64_t j = 1; j <= 2; j++) {
//             vector<uint64_t> vec_j(encoder.slot_count(), j); Plaintext pt_j; local_enc_batch.encode(vec_j, pt_j);
//             Ciphertext temp_x, temp_y;
//             local_eval.sub_plain(enc_S_x, pt_j, temp_x); local_eval.sub_plain(enc_S_y, pt_j, temp_y);
//             all_terms.push_back(temp_x); all_terms.push_back(temp_y);
//         }

//         Ciphertext enc_L_n;
//         local_eval.multiply_many(all_terms, rk, enc_L_n);

//         #pragma omp critical(debug_print)
//         {
//             if (b == 0) {
//                 cout << "\n[Noise Budget] 经过 multiply_many 后的 enc_L_n 剩余噪声: " 
//                      << debug_dec.invariant_noise_budget(enc_L_n) << " bits" << endl;
//             }
//             Plaintext pt_debug; vector<uint64_t> dec_Ln;
//             debug_dec.decrypt(enc_L_n, pt_debug); encoder.decode(pt_debug, dec_Ln);
//             int batch_hit_count = 0;
//             for(int i = 0; i < curr_size; i++) {
//                 if (dec_Ln[i] != 0) { batch_hit_count += unique_dataset[start_idx + i].o_list.size(); }
//             }
//             global_fhe_hit_count += batch_hit_count;
//         }

//         vector<Ciphertext> local_batch_sketch(SKETCH_SIZE);
//         #pragma omp parallel for
//         for(int s = 0; s < SKETCH_SIZE; s++) {
//             Encryptor init_enc(context, pk); Evaluator init_eval(context);
//             init_enc.encrypt_zero(local_batch_sketch[s]);
//             init_eval.mod_switch_to_inplace(local_batch_sketch[s], enc_L_n.parms_id());
//         }

//         map<int, vector<uint64_t>> mask_out;
//         for (int i = 0; i < curr_size; i++) {
//             auto& rec = unique_dataset[start_idx + i];
//             for (const auto& kv : rec.bucket_counts) {
//                 int s = kv.first; int count = kv.second;
//                 if (mask_out.find(s) == mask_out.end()) {
//                     mask_out[s] = vector<uint64_t>(encoder.slot_count(), 0);
//                 }
//                 mask_out[s][i] = (count * server_blind_vec[s]) % plain_mod;
//             }
//         }

//         vector<pair<int, vector<uint64_t>>> mask_out_vec(mask_out.begin(), mask_out.end());
        
//         #pragma omp parallel for schedule(dynamic)
//         for (int idx = 0; idx < (int)mask_out_vec.size(); idx++) {
//             int s = mask_out_vec[idx].first;
//             Evaluator thread_eval(context); BatchEncoder thread_enc(context);
//             Plaintext pt_m; thread_enc.encode(mask_out_vec[idx].second, pt_m); 
//             Ciphertext masked_L_n;
//             thread_eval.multiply_plain(enc_L_n, pt_m, masked_L_n); 
//             thread_eval.add_inplace(local_batch_sketch[s], masked_L_n);
//         }
        
//         #pragma omp parallel for
//         for(int s = 0; s < SKETCH_SIZE; s++) {
//             Evaluator thread_eval(context);
//             thread_eval.mod_switch_to_inplace(local_batch_sketch[s], context.last_context_data()->parms_id());
//         }

//         #pragma omp critical(global_merge)
//         {
//             for(int s=0; s<SKETCH_SIZE; s++) {
//                 local_eval.add_inplace(batch_sketches[s], local_batch_sketch[s]);
//             }
//         }
//     } 

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 4 (All Batches Process & Merge): the time is " << duration.count()/1000 << " s\n";

//     cout << "\n================ 最终 FHE 汇总 ================" << endl;
//     cout << " => FHE 在 L_n 中识别出的总命中数: " << global_fhe_hit_count << endl;

//     auto end_time = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration_t = end_time - start_time;
//     std::cout << "\n[Total] The overall time is " << duration_t.count()/1000 << " s\n";
    
//     // ==========================================
//     // 阶段5：并发序列化、ZSTD压缩与零拷贝网络发送
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();

//     // 开启 ZSTD 压缩（极大降低网络带宽消耗，大幅提升 I/O 速度）
//     seal::compr_mode_type compr_mode = seal::compr_mode_type::zstd;

//     // 使用 seal_byte 数组替代 stringstream，避免内部隐式扩容和字符串深拷贝
//     vector<vector<seal::seal_byte>> serialized_sketches(SKETCH_SIZE);
//     vector<uint64_t> actual_sizes(SKETCH_SIZE, 0);
    
//     // 预先计算总载荷大小，预留 S_out 的 8 字节空间
//     uint64_t total_payload_size = sizeof(uint64_t); 

//     // reduction 保证多线程累加 total_payload_size 时的线程安全
//     #pragma omp parallel for reduction(+:total_payload_size)
//     for (int s = 0; s < SKETCH_SIZE; s++) {
//         // 1. 获取 ZSTD 压缩后的上限大小并一次性分配内存
//         size_t max_size = batch_sketches[s].save_size(compr_mode);
//         serialized_sketches[s].resize(max_size);
        
//         // 2. 直接向连续内存块写入序列化数据
//         actual_sizes[s] = batch_sketches[s].save(
//             serialized_sketches[s].data(), 
//             max_size, 
//             compr_mode
//         );
        
//         // 3. 累加所需的网络流总字节数：单个长度前缀(8 bytes) + 压缩后密文长度
//         total_payload_size += sizeof(uint64_t) + actual_sizes[s];
//     }

//     // 构建最终的网络发送缓冲块，一次性 Reserve，彻底消灭 string 动态扩容开销
//     string final_payload;
//     final_payload.reserve(total_payload_size);

//     uint64_t S_out = SKETCH_SIZE;
//     final_payload.append(reinterpret_cast<const char*>(&S_out), sizeof(S_out));

//     for (int s = 0; s < SKETCH_SIZE; s++) {
//         uint64_t len = actual_sizes[s];
//         final_payload.append(reinterpret_cast<const char*>(&len), sizeof(len));
//         final_payload.append(reinterpret_cast<const char*>(serialized_sketches[s].data()), len);
//     }

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 5 (Serialization & ZSTD Compression): the time is " << duration.count()/1000.0 << " s\n";

//     cout << "[Server] 已完成 ZSTD 高效打包，准备发送 " << SKETCH_SIZE << " 个密文..." << endl;
    
//     // 此时 final_payload 是一整块连续内存，交由 boost::asio 一次性推入网卡
//     send_data(socket, final_payload);
//     end_time = std::chrono::high_resolution_clock::now();
//     duration_t = end_time - start_time;
//     std::cout << "\n[Total] The overall time is " << duration_t.count()/1000.0 << " s\n";
    
//     // send_data(socket, ss_out.str());
//     return 0;
// }






// #include "common.h"
// #include "bloomfilter.h"
// #include "MurmurHash3.h"
// #include <sstream>
// #include <chrono>
// #include <omp.h>
// #include <vector>
// #include <random>
// #include <map>
// #include <fstream>
// #include <string>
// #include <algorithm>
// #include <iostream>

// using namespace std;
// using namespace seal;

// struct Record { int id; int x; int y; int o; };

// struct UniqueRecord { 
//     int x; 
//     int y; 
//     vector<int> o_list; 
//     map<int, int> bucket_counts; 
// };

// int main(int argc, char* argv[]) {
//     auto start_time = std::chrono::high_resolution_clock::now();

//     // 这版的问题，去重不够简洁，直接重复结合S_x结果，那这个可能就多出来点乘法操作
//     // 阶段4、阶段5，好多都能多线程
//     // 最后才解决传输sk问题

//     // ==========================================
//     // 阶段1：数据加载与采样
//     // ==========================================
//     auto start = std::chrono::high_resolution_clock::now();
//     if (argc != 2) { cerr << "Usage: ./server <listen_port>\n"; return 1; }

//     vector<Record> dataset;

//     std::random_device rd;
//     std::mt19937 gen(rd());
//     std::uniform_int_distribution<> dist_x(0, 100);
//     std::uniform_int_distribution<> dist_y(0, 100);
//     std::uniform_int_distribution<> dist_x_miss(0, 1000);
//     std::uniform_int_distribution<> dist_y_miss(0, 1000);
//     std::uniform_int_distribution<> dist_o(10000, 99999);

//     int dataset_choice = 0; 
//     std::string dataset_path;
//     int read_limit = 0;

//     if (dataset_choice == 0) {
//         dataset_path = "../dataset/spatial/quantize_spatial_1_20.csv";
//         read_limit = 21900;
//     } else {
//         dataset_path = "../dataset/brightkite/Brightkite_filter_quantized.csv";
//         read_limit = 115383;
//     }

//     double P = 0.2; 

//     struct CsvRow { int original_row; int x; int y; };
//     std::vector<CsvRow> all_csv_data;

//     std::ifstream file(dataset_path);
//     if (!file.is_open()) {
//         std::cerr << "[Error] 无法打开数据集文件: " << dataset_path << std::endl;
//         exit(1); 
//     }

//     std::string line;
//     int loaded_count = 0;
//     int current_row = 1; 

//     while (std::getline(file, line) && loaded_count < read_limit) {
//         std::stringstream ss(line);
//         std::string cell_x, cell_y;

//         if (std::getline(ss, cell_x, ',') && std::getline(ss, cell_y, ',')) {
//             try {
//                 int x = std::stoi(cell_x);
//                 int y = std::stoi(cell_y);
//                 all_csv_data.push_back({current_row, x, y});
//                 loaded_count++; 
//             } catch (const std::invalid_argument& e) {}
//         }
//         current_row++;
//     }
//     file.close();
//     std::cout << "[Server] 成功从 " << dataset_path << " 提取 " << loaded_count << " 条有效数据。" << std::endl;

//     int target_size = static_cast<int>(all_csv_data.size() * P);
//     if (target_size == 0 && !all_csv_data.empty()) { target_size = 1; }

//     std::shuffle(all_csv_data.begin(), all_csv_data.end(), gen);

//     for (int i = 0; i < target_size; i++) {
//         dataset.push_back({i, all_csv_data[i].x, all_csv_data[i].y, all_csv_data[i].original_row});
//     }

//     std::cout << "[Server] 按 P=" << P << " 比例随机抽取了 " << dataset.size() << " 条模拟数据参与 FHE 计算。" << std::endl;
    
//     auto end = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration = end - start;
//     std::cout << "Phase 1 (Data Loading): the time is " << duration.count()/1000 << " s\n";

//     boost::asio::io_context io_context; tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), stoi(argv[1])));
//     tcp::socket socket(io_context); acceptor.accept(socket);

//     SEALContext context = create_fhe_context(); BatchEncoder encoder(context);
//     uint64_t plain_mod = context.first_context_data()->parms().plain_modulus().value();

//     string recv_str = receive_data(socket); stringstream ss_in(recv_str);
//     PublicKey pk; pk.load(context, ss_in); RelinKeys rk; rk.load(context, ss_in); GaloisKeys gal_keys; gal_keys.load(context, ss_in);
//     SecretKey sk; sk.load(context, ss_in); Decryptor debug_dec(context, sk);

//     // ==========================================
//     // 阶段2：接收数据与降维去重
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();

//     int M; ss_in.read(reinterpret_cast<char*>(&M), sizeof(M));
//     uint64_t size_x, size_y;
//     ss_in.read(reinterpret_cast<char*>(&size_x), sizeof(size_x)); string str_x(size_x, '\0'); ss_in.read(&str_x[0], size_x); stringstream sx(str_x); Ciphertext enc_bf_x; enc_bf_x.load(context, sx);
//     ss_in.read(reinterpret_cast<char*>(&size_y), sizeof(size_y)); string str_y(size_y, '\0'); ss_in.read(&str_y[0], size_y); stringstream sy(str_y); Ciphertext enc_bf_y; enc_bf_y.load(context, sy);

//     cout << "\n[Noise Budget-1] 初始接收密文 enc_bf_x 剩余噪声: " 
//          << debug_dec.invariant_noise_budget(enc_bf_x) << " bits" << endl;

//     map<pair<int, int>, vector<int>> unique_map;
//     for (const auto& rec : dataset) {
//         unique_map[{rec.x, rec.y}].push_back(rec.o);
//     }
    
//     vector<UniqueRecord> unique_dataset;
//     for (const auto& kv : unique_map) {
//         UniqueRecord ur;
//         ur.x = kv.first.first;
//         ur.y = kv.first.second;
//         ur.o_list = kv.second;
//         for (int o_val : ur.o_list) {
//             int s = (int)hash_result(o_val, SKETCH_SIZE, 0);
//             ur.bucket_counts[s]++;
//         }
//         unique_dataset.push_back(ur);
//     }
//     int total_unique_records = unique_dataset.size();
    
//     cout << "[Server] 数据去重优化: 提取出 " << total_unique_records << " 个唯一的 (x, y) 组合以降低 FHE 计算开销。" << endl;

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 2 (Recv & Dedup): the time is " << duration.count()/1000 << " s\n";

//     // ==========================================
//     // 阶段3：哈希缓存与并发旋转预计算
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();

//     map<int, vector<int>> cache_hash_x;
//     map<int, vector<int>> cache_hash_y;
//     for (const auto& rec : unique_dataset) {
//         if (cache_hash_x.find(rec.x) == cache_hash_x.end()) {
//             vector<int> hx(3);
//             for (int k = 0; k < 3; k++) hx[k] = (int)hash_result(rec.x, M, k);
//             cache_hash_x[rec.x] = hx;
//         }
//         if (cache_hash_y.find(rec.y) == cache_hash_y.end()) {
//             vector<int> hy(3);
//             for (int k = 0; k < 3; k++) hy[k] = (int)hash_result(rec.y, M, k);
//             cache_hash_y[rec.y] = hy;
//         }
//     }

//     vector<uint64_t> server_blind_vec(SKETCH_SIZE, 0ULL);
//     std::uniform_int_distribution<uint64_t> dist_blind(1, 100);
//     for(int s = 0; s < SKETCH_SIZE; s++) {
//         server_blind_vec[s] = dist_blind(gen); 
//     }

//     int ROW_SIZE = encoder.slot_count() / 2; 
//     int num_batches = ceil((double)total_unique_records / ROW_SIZE); 

//     vector<bool> need_rot_X(ROW_SIZE, false); vector<bool> need_rot_Y(ROW_SIZE, false);
//     for (int b = 0; b < num_batches; b++) {
//         int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_unique_records - start_idx);
//         for (int i = 0; i < curr_size; i++) {
//             auto& rec = unique_dataset[start_idx + i];
//             const auto& hx = cache_hash_x[rec.x];
//             for (int k = 0; k < 3; k++) {
//                 int off_x = (hx[k] - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE; need_rot_X[off_x] = true;
//             }
//             const auto& hy = cache_hash_y[rec.y];
//             for (int k = 0; k < 3; k++) {
//                 int off_y = (hy[k] - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE; need_rot_Y[off_y] = true;
//             }
//         }
//     }

//     // 【修改点】：直接 OMP 并行遍历 ROW_SIZE，数据量大时大概率 4096 次全跑，取消 active_X 额外开销
//     vector<Ciphertext> rot_X(ROW_SIZE), rot_Y(ROW_SIZE);

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3 (Hash Cache): the time is " << duration.count()/1000 << " s\n";

//     start = std::chrono::high_resolution_clock::now();
    
//     // 【修改点】：统计实际不重叠的、需要的轮转步长集合，按需分配并行任务
//     vector<int> active_rot_X;
//     vector<int> active_rot_Y;
//     for(int d = 0; d < ROW_SIZE; d++) {
//         if(need_rot_X[d]) active_rot_X.push_back(d);
//         if(need_rot_Y[d]) active_rot_Y.push_back(d);
//     }

//     // 增加一条日志，明确告诉你到底实际 rotate 了多少次（不影响原有核心输出）
//     cout << "[Server] 轮转操作优化: 实际执行 X=" << active_rot_X.size() 
//          << " 次, Y=" << active_rot_Y.size() << " 次 (槽位上限 " << ROW_SIZE << ")" << endl;

    
//     // 仅对有效哈希位置关系进行 X 的并发轮转
//     #pragma omp parallel for schedule(dynamic)
//     for(size_t i = 0; i < active_rot_X.size(); i++) {
//         Evaluator local_eval(context);
//         int d = active_rot_X[i];
//         local_eval.rotate_rows(enc_bf_x, d, gal_keys, rot_X[d]);
//     }

//     // 仅对有效哈希位置关系进行 Y 的并发轮转
//     #pragma omp parallel for schedule(dynamic)
//     for(size_t i = 0; i < active_rot_Y.size(); i++) {
//         Evaluator local_eval(context);
//         int d = active_rot_Y[i];
//         local_eval.rotate_rows(enc_bf_y, d, gal_keys, rot_Y[d]);
//     }

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3 (Rotate): the time is " << duration.count()/1000 << " s\n";
    
//     start = std::chrono::high_resolution_clock::now();
//     vector<Ciphertext> batch_sketches(SKETCH_SIZE);
//     #pragma omp parallel for
//     for(int s = 0; s < SKETCH_SIZE; s++) {
//         Encryptor init_enc(context, pk); Evaluator init_eval(context);
//         init_enc.encrypt_zero(batch_sketches[s]);
//         init_eval.mod_switch_to_inplace(batch_sketches[s], context.last_context_data()->parms_id()); 
//     }

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3 (Batch Sketch Initialization): the time is " << duration.count()/1000 << " s\n";
    
//     int global_fhe_hit_count = 0;
//     std::cout << "\n[Server] The batch number is " << num_batches << " \n";

//     // ==========================================
//     // 阶段4：多 Batch 并发计算与 L_n 生成
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();
//     omp_set_nested(1); 
    
//     #pragma omp parallel for schedule(dynamic)
//     for (int b = 0; b < num_batches; b++) {
//         Evaluator local_eval(context); Encryptor local_enc(context, pk); BatchEncoder local_enc_batch(context);
//         int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_unique_records - start_idx);

//         Ciphertext enc_S_x, enc_S_y; local_enc.encrypt_zero(enc_S_x); local_enc.encrypt_zero(enc_S_y);

//         map<int, vector<int>> batch_x_to_i; map<int, vector<int>> batch_y_to_i;
//         for (int i = 0; i < curr_size; i++) {
//             batch_x_to_i[unique_dataset[start_idx + i].x].push_back(i);
//             batch_y_to_i[unique_dataset[start_idx + i].y].push_back(i);
//         }

//         map<int, vector<uint64_t>> masks_X; map<int, vector<uint64_t>> masks_Y;
//         for (const auto& kv : batch_x_to_i) {
//             int x = kv.first; const auto& indices = kv.second; const auto& hx = cache_hash_x[x]; 
//             for (int k = 0; k < 3; k++) {
//                 int t_x = hx[k];
//                 for (int i : indices) {
//                     int off_x = (t_x - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE;
//                     if (masks_X.find(off_x) == masks_X.end()) masks_X[off_x] = vector<uint64_t>(encoder.slot_count(), 0);
//                     masks_X[off_x][i]++;
//                 }
//             }
//         }
//         for (const auto& kv : batch_y_to_i) {
//             int y = kv.first; const auto& indices = kv.second; const auto& hy = cache_hash_y[y]; 
//             for (int k = 0; k < 3; k++) {
//                 int t_y = hy[k];
//                 for (int i : indices) {
//                     int off_y = (t_y - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE;
//                     if (masks_Y.find(off_y) == masks_Y.end()) masks_Y[off_y] = vector<uint64_t>(encoder.slot_count(), 0);
//                     masks_Y[off_y][i]++;
//                 }
//             }
//         }

//         // Map-Reduce 模式：并发处理掩码累加
//         vector<pair<int, vector<uint64_t>>> vec_masks_X(masks_X.begin(), masks_X.end());
//         vector<pair<int, vector<uint64_t>>> vec_masks_Y(masks_Y.begin(), masks_Y.end());

//         #pragma omp parallel
//         {
//             Evaluator thread_eval(context); BatchEncoder thread_encoder(context);
//             Ciphertext local_S_x; local_enc.encrypt_zero(local_S_x); 
            
//             #pragma omp for nowait schedule(dynamic)
//             for (size_t i = 0; i < vec_masks_X.size(); i++) {
//                 int d = vec_masks_X[i].first; Plaintext pt; 
//                 thread_encoder.encode(vec_masks_X[i].second, pt);
//                 Ciphertext temp = rot_X[d]; 
//                 thread_eval.multiply_plain_inplace(temp, pt); 
//                 thread_eval.add_inplace(local_S_x, temp);
//             }
//             #pragma omp critical(x_accumulate)
//             { local_eval.add_inplace(enc_S_x, local_S_x); }
//         }

//         #pragma omp parallel
//         {
//             Evaluator thread_eval(context); BatchEncoder thread_encoder(context);
//             Ciphertext local_S_y; local_enc.encrypt_zero(local_S_y);
            
//             #pragma omp for nowait schedule(dynamic)
//             for (size_t i = 0; i < vec_masks_Y.size(); i++) {
//                 int d = vec_masks_Y[i].first; Plaintext pt; 
//                 thread_encoder.encode(vec_masks_Y[i].second, pt);
//                 Ciphertext temp = rot_Y[d]; 
//                 thread_eval.multiply_plain_inplace(temp, pt); 
//                 thread_eval.add_inplace(local_S_y, temp);
//             }
//             #pragma omp critical(y_accumulate)
//             { local_eval.add_inplace(enc_S_y, local_S_y); }
//         }

//         vector<Ciphertext> all_terms;
//         all_terms.push_back(enc_S_x); all_terms.push_back(enc_S_y);
//         for(uint64_t j = 1; j <= 2; j++) {
//             vector<uint64_t> vec_j(encoder.slot_count(), j); Plaintext pt_j; local_enc_batch.encode(vec_j, pt_j);
//             Ciphertext temp_x, temp_y;
//             local_eval.sub_plain(enc_S_x, pt_j, temp_x); local_eval.sub_plain(enc_S_y, pt_j, temp_y);
//             all_terms.push_back(temp_x); all_terms.push_back(temp_y);
//         }

//         Ciphertext enc_L_n;
//         local_eval.multiply_many(all_terms, rk, enc_L_n);

//         #pragma omp critical(debug_print)
//         {
//             if (b == 0) {
//                 cout << "\n[Noise Budget] 经过 multiply_many 后的 enc_L_n 剩余噪声: " 
//                      << debug_dec.invariant_noise_budget(enc_L_n) << " bits" << endl;
//             }
//             Plaintext pt_debug; vector<uint64_t> dec_Ln;
//             debug_dec.decrypt(enc_L_n, pt_debug); encoder.decode(pt_debug, dec_Ln);
//             int batch_hit_count = 0;
//             for(int i = 0; i < curr_size; i++) {
//                 if (dec_Ln[i] != 0) { batch_hit_count += unique_dataset[start_idx + i].o_list.size(); }
//             }
//             global_fhe_hit_count += batch_hit_count;
//         }

//         vector<Ciphertext> local_batch_sketch(SKETCH_SIZE);
//         #pragma omp parallel for
//         for(int s = 0; s < SKETCH_SIZE; s++) {
//             Encryptor init_enc(context, pk); Evaluator init_eval(context);
//             init_enc.encrypt_zero(local_batch_sketch[s]);
//             init_eval.mod_switch_to_inplace(local_batch_sketch[s], enc_L_n.parms_id());
//         }

//         map<int, vector<uint64_t>> mask_out;
//         for (int i = 0; i < curr_size; i++) {
//             auto& rec = unique_dataset[start_idx + i];
//             for (const auto& kv : rec.bucket_counts) {
//                 int s = kv.first; int count = kv.second;
//                 if (mask_out.find(s) == mask_out.end()) {
//                     mask_out[s] = vector<uint64_t>(encoder.slot_count(), 0);
//                 }
//                 mask_out[s][i] = (count * server_blind_vec[s]) % plain_mod;
//             }
//         }

//         vector<pair<int, vector<uint64_t>>> mask_out_vec(mask_out.begin(), mask_out.end());
        
//         #pragma omp parallel for schedule(dynamic)
//         for (int idx = 0; idx < (int)mask_out_vec.size(); idx++) {
//             int s = mask_out_vec[idx].first;
//             Evaluator thread_eval(context); BatchEncoder thread_enc(context);
//             Plaintext pt_m; thread_enc.encode(mask_out_vec[idx].second, pt_m); 
//             Ciphertext masked_L_n;
//             thread_eval.multiply_plain(enc_L_n, pt_m, masked_L_n); 
//             thread_eval.add_inplace(local_batch_sketch[s], masked_L_n);
//         }
        
//         #pragma omp parallel for
//         for(int s = 0; s < SKETCH_SIZE; s++) {
//             Evaluator thread_eval(context);
//             thread_eval.mod_switch_to_inplace(local_batch_sketch[s], context.last_context_data()->parms_id());
//         }

//         #pragma omp critical(global_merge)
//         {
//             for(int s=0; s<SKETCH_SIZE; s++) {
//                 local_eval.add_inplace(batch_sketches[s], local_batch_sketch[s]);
//             }
//         }
//     } 

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 4 (All Batches Process & Merge): the time is " << duration.count()/1000 << " s\n";

//     cout << "\n================ 最终 FHE 汇总 ================" << endl;
//     cout << " => FHE 在 L_n 中识别出的总命中数: " << global_fhe_hit_count << endl;

//     auto end_time = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration_t = end_time - start_time;
//     std::cout << "\n[Total] The overall time is " << duration_t.count()/1000 << " s\n";
    
//     // ==========================================
//     // 阶段5：并发序列化与网络发送
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();
//     stringstream ss_out;
//     uint64_t S_out = SKETCH_SIZE;
//     ss_out.write(reinterpret_cast<const char*>(&S_out), sizeof(S_out));
    
//     vector<string> serialized_sketches(SKETCH_SIZE);
//     #pragma omp parallel for
//     for (int s = 0; s < SKETCH_SIZE; s++) {
//         stringstream stmp; 
//         batch_sketches[s].save(stmp);
//         serialized_sketches[s] = stmp.str();
//     }

//     for (int s = 0; s < SKETCH_SIZE; s++) {
//         uint64_t len = serialized_sketches[s].size();
//         ss_out.write(reinterpret_cast<const char*>(&len), sizeof(len));
//         ss_out.write(serialized_sketches[s].c_str(), len);
//     }

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 5 (Serialization): the time is " << duration.count()/1000 << " s\n";

//     cout << "[Server] 已打包 " << SKETCH_SIZE << " 个密文并发送!" << endl;
//     end_time = std::chrono::high_resolution_clock::now();
//     duration_t = end_time - start_time;
//     std::cout << "\n[Total] The overall time is " << duration_t.count()/1000 << " s\n";
    
//     send_data(socket, ss_out.str());
//     return 0;
// }







// #include "common.h"
// #include "bloomfilter.h"
// #include "MurmurHash3.h"
// #include <sstream>
// #include <chrono>
// #include <omp.h>
// #include <vector>
// #include <random>
// #include <map>
// #include <fstream>
// #include <string>
// #include <algorithm>
// #include <iostream>

// using namespace std;
// using namespace seal;

// struct Record { int id; int x; int y; int o; };

// struct UniqueRecord { 
//     int x; 
//     int y; 
//     vector<int> o_list; 
//     map<int, int> bucket_counts; 
// };

// int main(int argc, char* argv[]) {
//     auto start_time = std::chrono::high_resolution_clock::now();

//     // 这版的问题，去重不够简洁，直接重复结合S_x结果，那这个可能就多出来点乘法操作
//     // 阶段4、阶段5，好多都能多线程
//     // 最后才解决传输sk问题

//     // ==========================================
//     // 阶段1：数据加载与采样
//     // ==========================================
//     auto start = std::chrono::high_resolution_clock::now();
//     if (argc != 2) { cerr << "Usage: ./server <listen_port>\n"; return 1; }

//     vector<Record> dataset;

//     std::random_device rd;
//     std::mt19937 gen(rd());
//     std::uniform_int_distribution<> dist_x(0, 100);
//     std::uniform_int_distribution<> dist_y(0, 100);
//     std::uniform_int_distribution<> dist_x_miss(0, 1000);
//     std::uniform_int_distribution<> dist_y_miss(0, 1000);
//     std::uniform_int_distribution<> dist_o(10000, 99999);

//     int dataset_choice = 0; 
//     std::string dataset_path;
//     int read_limit = 0;

//     if (dataset_choice == 0) {
//         dataset_path = "../dataset/spatial/quantize_spatial_1_20.csv";
//         read_limit = 21900;
//     } else {
//         dataset_path = "../dataset/brightkite/Brightkite_filter_quantized.csv";
//         read_limit = 115383;
//     }

//     double P = 0.2; 

//     struct CsvRow { int original_row; int x; int y; };
//     std::vector<CsvRow> all_csv_data;

//     std::ifstream file(dataset_path);
//     if (!file.is_open()) {
//         std::cerr << "[Error] 无法打开数据集文件: " << dataset_path << std::endl;
//         exit(1); 
//     }

//     std::string line;
//     int loaded_count = 0;
//     int current_row = 1; 

//     while (std::getline(file, line) && loaded_count < read_limit) {
//         std::stringstream ss(line);
//         std::string cell_x, cell_y;

//         if (std::getline(ss, cell_x, ',') && std::getline(ss, cell_y, ',')) {
//             try {
//                 int x = std::stoi(cell_x);
//                 int y = std::stoi(cell_y);
//                 all_csv_data.push_back({current_row, x, y});
//                 loaded_count++; 
//             } catch (const std::invalid_argument& e) {}
//         }
//         current_row++;
//     }
//     file.close();
//     std::cout << "[Server] 成功从 " << dataset_path << " 提取 " << loaded_count << " 条有效数据。" << std::endl;

//     int target_size = static_cast<int>(all_csv_data.size() * P);
//     if (target_size == 0 && !all_csv_data.empty()) { target_size = 1; }

//     std::shuffle(all_csv_data.begin(), all_csv_data.end(), gen);

//     for (int i = 0; i < target_size; i++) {
//         dataset.push_back({i, all_csv_data[i].x, all_csv_data[i].y, all_csv_data[i].original_row});
//     }

//     std::cout << "[Server] 按 P=" << P << " 比例随机抽取了 " << dataset.size() << " 条模拟数据参与 FHE 计算。" << std::endl;
    
//     auto end = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration = end - start;
//     std::cout << "Phase 1 (Data Loading): the time is " << duration.count()/1000 << " s\n";

//     boost::asio::io_context io_context; tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), stoi(argv[1])));
//     tcp::socket socket(io_context); acceptor.accept(socket);

//     SEALContext context = create_fhe_context(); BatchEncoder encoder(context);
//     uint64_t plain_mod = context.first_context_data()->parms().plain_modulus().value();

//     string recv_str = receive_data(socket); stringstream ss_in(recv_str);
//     PublicKey pk; pk.load(context, ss_in); RelinKeys rk; rk.load(context, ss_in); GaloisKeys gal_keys; gal_keys.load(context, ss_in);
//     SecretKey sk; sk.load(context, ss_in); Decryptor debug_dec(context, sk);

//     // ==========================================
//     // 阶段2：接收数据与降维去重
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();

//     int M; ss_in.read(reinterpret_cast<char*>(&M), sizeof(M));
//     uint64_t size_x, size_y;
//     ss_in.read(reinterpret_cast<char*>(&size_x), sizeof(size_x)); string str_x(size_x, '\0'); ss_in.read(&str_x[0], size_x); stringstream sx(str_x); Ciphertext enc_bf_x; enc_bf_x.load(context, sx);
//     ss_in.read(reinterpret_cast<char*>(&size_y), sizeof(size_y)); string str_y(size_y, '\0'); ss_in.read(&str_y[0], size_y); stringstream sy(str_y); Ciphertext enc_bf_y; enc_bf_y.load(context, sy);

//     cout << "\n[Noise Budget-1] 初始接收密文 enc_bf_x 剩余噪声: " 
//          << debug_dec.invariant_noise_budget(enc_bf_x) << " bits" << endl;

//     map<pair<int, int>, vector<int>> unique_map;
//     for (const auto& rec : dataset) {
//         unique_map[{rec.x, rec.y}].push_back(rec.o);
//     }
    
//     vector<UniqueRecord> unique_dataset;
//     for (const auto& kv : unique_map) {
//         UniqueRecord ur;
//         ur.x = kv.first.first;
//         ur.y = kv.first.second;
//         ur.o_list = kv.second;
//         for (int o_val : ur.o_list) {
//             int s = (int)hash_result(o_val, SKETCH_SIZE, 0);
//             ur.bucket_counts[s]++;
//         }
//         unique_dataset.push_back(ur);
//     }
//     int total_unique_records = unique_dataset.size();
    
//     cout << "[Server] 数据去重优化: 提取出 " << total_unique_records << " 个唯一的 (x, y) 组合以降低 FHE 计算开销。" << endl;

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 2 (Recv & Dedup): the time is " << duration.count()/1000 << " s\n";

//     // ==========================================
//     // 阶段3：哈希缓存与并发旋转预计算
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();

//     map<int, vector<int>> cache_hash_x;
//     map<int, vector<int>> cache_hash_y;
//     for (const auto& rec : unique_dataset) {
//         if (cache_hash_x.find(rec.x) == cache_hash_x.end()) {
//             vector<int> hx(3);
//             for (int k = 0; k < 3; k++) hx[k] = (int)hash_result(rec.x, M, k);
//             cache_hash_x[rec.x] = hx;
//         }
//         if (cache_hash_y.find(rec.y) == cache_hash_y.end()) {
//             vector<int> hy(3);
//             for (int k = 0; k < 3; k++) hy[k] = (int)hash_result(rec.y, M, k);
//             cache_hash_y[rec.y] = hy;
//         }
//     }

//     vector<uint64_t> server_blind_vec(SKETCH_SIZE, 0ULL);
//     std::uniform_int_distribution<uint64_t> dist_blind(1, 100);
//     for(int s = 0; s < SKETCH_SIZE; s++) {
//         server_blind_vec[s] = dist_blind(gen); 
//     }

//     int ROW_SIZE = encoder.slot_count() / 2; 
//     int num_batches = ceil((double)total_unique_records / ROW_SIZE); 

//     vector<bool> need_rot_X(ROW_SIZE, false); vector<bool> need_rot_Y(ROW_SIZE, false);
//     for (int b = 0; b < num_batches; b++) {
//         int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_unique_records - start_idx);
//         for (int i = 0; i < curr_size; i++) {
//             auto& rec = unique_dataset[start_idx + i];
//             const auto& hx = cache_hash_x[rec.x];
//             for (int k = 0; k < 3; k++) {
//                 int off_x = (hx[k] - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE; need_rot_X[off_x] = true;
//             }
//             const auto& hy = cache_hash_y[rec.y];
//             for (int k = 0; k < 3; k++) {
//                 int off_y = (hy[k] - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE; need_rot_Y[off_y] = true;
//             }
//         }
//     }

//     // 【修改点】：直接 OMP 并行遍历 ROW_SIZE，数据量大时大概率 4096 次全跑，取消 active_X 额外开销
//     vector<Ciphertext> rot_X(ROW_SIZE), rot_Y(ROW_SIZE);

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3 (Hash Cache): the time is " << duration.count()/1000 << " s\n";

//     start = std::chrono::high_resolution_clock::now();
    
//     #pragma omp parallel for schedule(dynamic)
//     for(int d = 0; d < ROW_SIZE; d++) {
//         // 线程局部 Evaluator，绝对线程安全
//         Evaluator local_eval(context);
//         if(need_rot_X[d]) local_eval.rotate_rows(enc_bf_x, d, gal_keys, rot_X[d]);
//         if(need_rot_Y[d]) local_eval.rotate_rows(enc_bf_y, d, gal_keys, rot_Y[d]);
//     }

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3 (Rotate): the time is " << duration.count()/1000 << " s\n";
    
//     start = std::chrono::high_resolution_clock::now();
//     vector<Ciphertext> batch_sketches(SKETCH_SIZE);
//     #pragma omp parallel for
//     for(int s = 0; s < SKETCH_SIZE; s++) {
//         Encryptor init_enc(context, pk); Evaluator init_eval(context);
//         init_enc.encrypt_zero(batch_sketches[s]);
//         init_eval.mod_switch_to_inplace(batch_sketches[s], context.last_context_data()->parms_id()); 
//     }

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3 (Batch Sketch Initialization): the time is " << duration.count()/1000 << " s\n";
    
//     int global_fhe_hit_count = 0;
//     std::cout << "\n[Server] The batch number is " << num_batches << " \n";

//     // ==========================================
//     // 阶段4：多 Batch 并发计算与 L_n 生成
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();
//     omp_set_nested(1); 
    
//     #pragma omp parallel for schedule(dynamic)
//     for (int b = 0; b < num_batches; b++) {
//         Evaluator local_eval(context); Encryptor local_enc(context, pk); BatchEncoder local_enc_batch(context);
//         int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_unique_records - start_idx);

//         Ciphertext enc_S_x, enc_S_y; local_enc.encrypt_zero(enc_S_x); local_enc.encrypt_zero(enc_S_y);

//         map<int, vector<int>> batch_x_to_i; map<int, vector<int>> batch_y_to_i;
//         for (int i = 0; i < curr_size; i++) {
//             batch_x_to_i[unique_dataset[start_idx + i].x].push_back(i);
//             batch_y_to_i[unique_dataset[start_idx + i].y].push_back(i);
//         }

//         map<int, vector<uint64_t>> masks_X; map<int, vector<uint64_t>> masks_Y;
//         for (const auto& kv : batch_x_to_i) {
//             int x = kv.first; const auto& indices = kv.second; const auto& hx = cache_hash_x[x]; 
//             for (int k = 0; k < 3; k++) {
//                 int t_x = hx[k];
//                 for (int i : indices) {
//                     int off_x = (t_x - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE;
//                     if (masks_X.find(off_x) == masks_X.end()) masks_X[off_x] = vector<uint64_t>(encoder.slot_count(), 0);
//                     masks_X[off_x][i]++;
//                 }
//             }
//         }
//         for (const auto& kv : batch_y_to_i) {
//             int y = kv.first; const auto& indices = kv.second; const auto& hy = cache_hash_y[y]; 
//             for (int k = 0; k < 3; k++) {
//                 int t_y = hy[k];
//                 for (int i : indices) {
//                     int off_y = (t_y - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE;
//                     if (masks_Y.find(off_y) == masks_Y.end()) masks_Y[off_y] = vector<uint64_t>(encoder.slot_count(), 0);
//                     masks_Y[off_y][i]++;
//                 }
//             }
//         }

//         // Map-Reduce 模式：并发处理掩码累加
//         vector<pair<int, vector<uint64_t>>> vec_masks_X(masks_X.begin(), masks_X.end());
//         vector<pair<int, vector<uint64_t>>> vec_masks_Y(masks_Y.begin(), masks_Y.end());

//         #pragma omp parallel
//         {
//             Evaluator thread_eval(context); BatchEncoder thread_encoder(context);
//             Ciphertext local_S_x; local_enc.encrypt_zero(local_S_x); 
            
//             #pragma omp for nowait schedule(dynamic)
//             for (size_t i = 0; i < vec_masks_X.size(); i++) {
//                 int d = vec_masks_X[i].first; Plaintext pt; 
//                 thread_encoder.encode(vec_masks_X[i].second, pt);
//                 Ciphertext temp = rot_X[d]; 
//                 thread_eval.multiply_plain_inplace(temp, pt); 
//                 thread_eval.add_inplace(local_S_x, temp);
//             }
//             #pragma omp critical(x_accumulate)
//             { local_eval.add_inplace(enc_S_x, local_S_x); }
//         }

//         #pragma omp parallel
//         {
//             Evaluator thread_eval(context); BatchEncoder thread_encoder(context);
//             Ciphertext local_S_y; local_enc.encrypt_zero(local_S_y);
            
//             #pragma omp for nowait schedule(dynamic)
//             for (size_t i = 0; i < vec_masks_Y.size(); i++) {
//                 int d = vec_masks_Y[i].first; Plaintext pt; 
//                 thread_encoder.encode(vec_masks_Y[i].second, pt);
//                 Ciphertext temp = rot_Y[d]; 
//                 thread_eval.multiply_plain_inplace(temp, pt); 
//                 thread_eval.add_inplace(local_S_y, temp);
//             }
//             #pragma omp critical(y_accumulate)
//             { local_eval.add_inplace(enc_S_y, local_S_y); }
//         }

//         vector<Ciphertext> all_terms;
//         all_terms.push_back(enc_S_x); all_terms.push_back(enc_S_y);
//         for(uint64_t j = 1; j <= 2; j++) {
//             vector<uint64_t> vec_j(encoder.slot_count(), j); Plaintext pt_j; local_enc_batch.encode(vec_j, pt_j);
//             Ciphertext temp_x, temp_y;
//             local_eval.sub_plain(enc_S_x, pt_j, temp_x); local_eval.sub_plain(enc_S_y, pt_j, temp_y);
//             all_terms.push_back(temp_x); all_terms.push_back(temp_y);
//         }

//         Ciphertext enc_L_n;
//         local_eval.multiply_many(all_terms, rk, enc_L_n);

//         #pragma omp critical(debug_print)
//         {
//             if (b == 0) {
//                 cout << "\n[Noise Budget] 经过 multiply_many 后的 enc_L_n 剩余噪声: " 
//                      << debug_dec.invariant_noise_budget(enc_L_n) << " bits" << endl;
//             }
//             Plaintext pt_debug; vector<uint64_t> dec_Ln;
//             debug_dec.decrypt(enc_L_n, pt_debug); encoder.decode(pt_debug, dec_Ln);
//             int batch_hit_count = 0;
//             for(int i = 0; i < curr_size; i++) {
//                 if (dec_Ln[i] != 0) { batch_hit_count += unique_dataset[start_idx + i].o_list.size(); }
//             }
//             global_fhe_hit_count += batch_hit_count;
//         }

//         vector<Ciphertext> local_batch_sketch(SKETCH_SIZE);
//         #pragma omp parallel for
//         for(int s = 0; s < SKETCH_SIZE; s++) {
//             Encryptor init_enc(context, pk); Evaluator init_eval(context);
//             init_enc.encrypt_zero(local_batch_sketch[s]);
//             init_eval.mod_switch_to_inplace(local_batch_sketch[s], enc_L_n.parms_id());
//         }

//         map<int, vector<uint64_t>> mask_out;
//         for (int i = 0; i < curr_size; i++) {
//             auto& rec = unique_dataset[start_idx + i];
//             for (const auto& kv : rec.bucket_counts) {
//                 int s = kv.first; int count = kv.second;
//                 if (mask_out.find(s) == mask_out.end()) {
//                     mask_out[s] = vector<uint64_t>(encoder.slot_count(), 0);
//                 }
//                 mask_out[s][i] = (count * server_blind_vec[s]) % plain_mod;
//             }
//         }

//         vector<pair<int, vector<uint64_t>>> mask_out_vec(mask_out.begin(), mask_out.end());
        
//         #pragma omp parallel for schedule(dynamic)
//         for (int idx = 0; idx < (int)mask_out_vec.size(); idx++) {
//             int s = mask_out_vec[idx].first;
//             Evaluator thread_eval(context); BatchEncoder thread_enc(context);
//             Plaintext pt_m; thread_enc.encode(mask_out_vec[idx].second, pt_m); 
//             Ciphertext masked_L_n;
//             thread_eval.multiply_plain(enc_L_n, pt_m, masked_L_n); 
//             thread_eval.add_inplace(local_batch_sketch[s], masked_L_n);
//         }
        
//         #pragma omp parallel for
//         for(int s = 0; s < SKETCH_SIZE; s++) {
//             Evaluator thread_eval(context);
//             thread_eval.mod_switch_to_inplace(local_batch_sketch[s], context.last_context_data()->parms_id());
//         }

//         #pragma omp critical(global_merge)
//         {
//             for(int s=0; s<SKETCH_SIZE; s++) {
//                 local_eval.add_inplace(batch_sketches[s], local_batch_sketch[s]);
//             }
//         }
//     } 

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 4 (All Batches Process & Merge): the time is " << duration.count()/1000 << " s\n";

//     cout << "\n================ 最终 FHE 汇总 ================" << endl;
//     cout << " => FHE 在 L_n 中识别出的总命中数: " << global_fhe_hit_count << endl;
    
//     // ==========================================
//     // 阶段5：并发序列化与网络发送
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();
//     stringstream ss_out;
//     uint64_t S_out = SKETCH_SIZE;
//     ss_out.write(reinterpret_cast<const char*>(&S_out), sizeof(S_out));
    
//     vector<string> serialized_sketches(SKETCH_SIZE);
//     #pragma omp parallel for
//     for (int s = 0; s < SKETCH_SIZE; s++) {
//         stringstream stmp; 
//         batch_sketches[s].save(stmp);
//         serialized_sketches[s] = stmp.str();
//     }

//     for (int s = 0; s < SKETCH_SIZE; s++) {
//         uint64_t len = serialized_sketches[s].size();
//         ss_out.write(reinterpret_cast<const char*>(&len), sizeof(len));
//         ss_out.write(serialized_sketches[s].c_str(), len);
//     }

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 5 (Serialization): the time is " << duration.count()/1000 << " s\n";

//     cout << "[Server] 已打包 " << SKETCH_SIZE << " 个密文并发送!" << endl;
//     auto end_time = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration_t = end_time - start_time;
//     std::cout << "\n[Total] The overall time is " << duration_t.count()/1000 << " s\n";
    
//     send_data(socket, ss_out.str());
//     return 0;
// }










// #include "common.h"
// #include "bloomfilter.h"
// #include "MurmurHash3.h"
// #include <sstream>
// #include <chrono>
// #include <omp.h>
// #include <vector>
// #include <random>
// #include <map>
// #include <fstream>
// #include <string>
// #include <algorithm>
// #include <iostream>

// using namespace std;
// using namespace seal;

// struct Record { int id; int x; int y; int o; };

// struct UniqueRecord { 
//     int x; 
//     int y; 
//     vector<int> o_list; 
//     map<int, int> bucket_counts; 
// };

// int main(int argc, char* argv[]) {




//     // 这版的问题，去重不够简洁，直接重复结合S_x结果，那这个可能就多出来点乘法操作
//     // 阶段4、阶段5，好多都能多线程
//     // 最后才解决传输sk问题

//     auto start_time = std::chrono::high_resolution_clock::now();

//     // 阶段1  数据加载
//     auto start = std::chrono::high_resolution_clock::now();
//     if (argc != 2) { cerr << "Usage: ./server <listen_port>\n"; return 1; }

//     vector<Record> dataset;

//     std::random_device rd;
//     std::mt19937 gen(rd());
//     std::uniform_int_distribution<> dist_x(0, 100);
//     std::uniform_int_distribution<> dist_y(0, 100);
//     std::uniform_int_distribution<> dist_x_miss(0, 1000);
//     std::uniform_int_distribution<> dist_y_miss(0, 1000);
//     std::uniform_int_distribution<> dist_o(10000, 99999);

//     // ================= 数据集配置 =================
//     int dataset_choice = 0; 
//     std::string dataset_path;
//     int read_limit = 0;

//     if (dataset_choice == 0) {
//         dataset_path = "../dataset/spatial/quantize_spatial_1_20.csv";
//         read_limit = 21900;
//     } else {
//         dataset_path = "../dataset/brightkite/Brightkite_filter_quantized.csv";
//         read_limit = 115383;
//     }

//     double P = 0.2; 
//     // ==============================================

//     struct CsvRow {
//         int original_row;
//         int x;
//         int y;
//     };
//     std::vector<CsvRow> all_csv_data;

//     std::ifstream file(dataset_path);
//     if (!file.is_open()) {
//         std::cerr << "[Error] 无法打开数据集文件: " << dataset_path << std::endl;
//         exit(1); 
//     }

//     std::string line;
//     int loaded_count = 0;
//     int current_row = 1; 

//     while (std::getline(file, line) && loaded_count < read_limit) {
//         std::stringstream ss(line);
//         std::string cell_x, cell_y;

//         if (std::getline(ss, cell_x, ',') && std::getline(ss, cell_y, ',')) {
//             try {
//                 int x = std::stoi(cell_x);
//                 int y = std::stoi(cell_y);
//                 all_csv_data.push_back({current_row, x, y});
//                 loaded_count++; 
//             } catch (const std::invalid_argument& e) {
//             }
//         }
//         current_row++;
//     }
//     file.close();
//     std::cout << "[Server] 成功从 " << dataset_path << " 提取 " << loaded_count << " 条有效数据。" << std::endl;

//     int target_size = static_cast<int>(all_csv_data.size() * P);
//     if (target_size == 0 && !all_csv_data.empty()) {
//         target_size = 1; 
//     }

//     std::shuffle(all_csv_data.begin(), all_csv_data.end(), gen);

//     for (int i = 0; i < target_size; i++) {
//         dataset.push_back({i, all_csv_data[i].x, all_csv_data[i].y, all_csv_data[i].original_row});
//     }

//     std::cout << "[Server] 按 P=" << P << " 比例随机抽取了 " << dataset.size() << " 条模拟数据参与 FHE 计算。" << std::endl;
//     auto end = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration = end - start;
//     std::cout << "Phase 1: the time is " << duration.count()/1000 << " s\n";

//     boost::asio::io_context io_context; tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), stoi(argv[1])));
//     tcp::socket socket(io_context); acceptor.accept(socket);

//     SEALContext context = create_fhe_context(); BatchEncoder encoder(context);
//     uint64_t plain_mod = context.first_context_data()->parms().plain_modulus().value();

//     string recv_str = receive_data(socket); stringstream ss_in(recv_str);
//     PublicKey pk; pk.load(context, ss_in); RelinKeys rk; rk.load(context, ss_in); GaloisKeys gal_keys; gal_keys.load(context, ss_in);
//     SecretKey sk; sk.load(context, ss_in); Decryptor debug_dec(context, sk);

//     // 阶段2 接收数据
//     start = std::chrono::high_resolution_clock::now();

//     int M; ss_in.read(reinterpret_cast<char*>(&M), sizeof(M));
//     uint64_t size_x, size_y;
//     ss_in.read(reinterpret_cast<char*>(&size_x), sizeof(size_x)); string str_x(size_x, '\0'); ss_in.read(&str_x[0], size_x); stringstream sx(str_x); Ciphertext enc_bf_x; enc_bf_x.load(context, sx);
//     ss_in.read(reinterpret_cast<char*>(&size_y), sizeof(size_y)); string str_y(size_y, '\0'); ss_in.read(&str_y[0], size_y); stringstream sy(str_y); Ciphertext enc_bf_y; enc_bf_y.load(context, sy);

//     cout << "\n[Noise Budget-1] 初始接收密文 enc_bf_x 剩余噪声: " 
//          << debug_dec.invariant_noise_budget(enc_bf_x) << " bits" << endl;

//     cout << "\n[DEBUG-Server-启动检查] 收到 Client 传来的 M (BloomFilter 大小): " << M << endl;

//     map<pair<int, int>, vector<int>> unique_map;
//     for (const auto& rec : dataset) {
//         unique_map[{rec.x, rec.y}].push_back(rec.o);
//     }
    
//     vector<UniqueRecord> unique_dataset;
//     for (const auto& kv : unique_map) {
//         UniqueRecord ur;
//         ur.x = kv.first.first;
//         ur.y = kv.first.second;
//         ur.o_list = kv.second;
//         for (int o_val : ur.o_list) {
//             int s = (int)hash_result(o_val, SKETCH_SIZE, 0);
//             ur.bucket_counts[s]++;
//         }
//         unique_dataset.push_back(ur);
//     }
//     int total_unique_records = unique_dataset.size();
    
//     cout << "[Server] 数据去重优化: 提取出 " 
//          << total_unique_records << " 个唯一的 (x, y) 组合以降低 FHE 计算开销。" << endl;

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 2: the time is " << duration.count()/1000 << " s\n";

//     // 阶段3  数据处理，计算旋转
//     start = std::chrono::high_resolution_clock::now();

//     map<int, vector<int>> cache_hash_x;
//     map<int, vector<int>> cache_hash_y;
//     for (const auto& rec : unique_dataset) {
//         if (cache_hash_x.find(rec.x) == cache_hash_x.end()) {
//             vector<int> hx(3);
//             for (int k = 0; k < 3; k++) hx[k] = (int)hash_result(rec.x, M, k);
//             cache_hash_x[rec.x] = hx;
//         }
//         if (cache_hash_y.find(rec.y) == cache_hash_y.end()) {
//             vector<int> hy(3);
//             for (int k = 0; k < 3; k++) hy[k] = (int)hash_result(rec.y, M, k);
//             cache_hash_y[rec.y] = hy;
//         }
//     }
//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3-1: the time is " << duration.count()/1000 << " s\n";

//     cout << "\n[Server] 维度独立去重统计: 全局独立 X 坐标共 " << cache_hash_x.size() 
//          << " 个，全局独立 Y 坐标共 " << cache_hash_y.size() << " 个。" << endl;

//     vector<uint64_t> server_blind_vec(SKETCH_SIZE, 0ULL);
//     std::uniform_int_distribution<uint64_t> dist_blind(1, 100);
//     for(int s = 0; s < SKETCH_SIZE; s++) {
//         server_blind_vec[s] = dist_blind(gen); 
//     }
//     cout << "[Server] 已生成内部盲化向量，准备进行掩码融合优化..." << endl;

//     Evaluator evaluator_main(context); int ROW_SIZE = encoder.slot_count() / 2; 
    
//     int num_batches = ceil((double)total_unique_records / ROW_SIZE); 

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3-2: the time is " << duration.count()/1000 << " s\n";

//     vector<bool> need_rot_X(ROW_SIZE, false); vector<bool> need_rot_Y(ROW_SIZE, false);
//     for (int b = 0; b < num_batches; b++) {
//         int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_unique_records - start_idx);
//         for (int i = 0; i < curr_size; i++) {
//             auto& rec = unique_dataset[start_idx + i];
//             const auto& hx = cache_hash_x[rec.x];
//             for (int k = 0; k < 3; k++) {
//                 int off_x = (hx[k] - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE; need_rot_X[off_x] = true;
//             }
//             const auto& hy = cache_hash_y[rec.y];
//             for (int k = 0; k < 3; k++) {
//                 int off_y = (hy[k] - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE; need_rot_Y[off_y] = true;
//             }
//         }
//     }
//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3-3: the time is " << duration.count()/1000 << " s\n";

//     // 这块时间太长
//     vector<Ciphertext> rot_X(ROW_SIZE), rot_Y(ROW_SIZE);
//     #pragma omp parallel for
//     for(int d = 0; d < ROW_SIZE; d++) {
//         if(need_rot_X[d]) evaluator_main.rotate_rows(enc_bf_x, d, gal_keys, rot_X[d]);
//         if(need_rot_Y[d]) evaluator_main.rotate_rows(enc_bf_y, d, gal_keys, rot_Y[d]);
//     }

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3: the time is " << duration.count()/1000 << " s\n";
    
//     vector<Ciphertext> batch_sketches(SKETCH_SIZE);
//     int global_fhe_hit_count = 0;

//     std::cout << "the batch number is " << num_batches << " \n";

//     for (int b = 0; b < num_batches; b++) {
        
//         // 阶段4 计算L_n
//         start = std::chrono::high_resolution_clock::now();

//         Evaluator local_eval(context); Encryptor local_enc(context, pk);
//         int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_unique_records - start_idx);

//         Ciphertext enc_S_x, enc_S_y; local_enc.encrypt_zero(enc_S_x); local_enc.encrypt_zero(enc_S_y);

//         map<int, vector<int>> batch_x_to_i;
//         map<int, vector<int>> batch_y_to_i;
//         for (int i = 0; i < curr_size; i++) {
//             batch_x_to_i[unique_dataset[start_idx + i].x].push_back(i);
//             batch_y_to_i[unique_dataset[start_idx + i].y].push_back(i);
//         }

//         end = std::chrono::high_resolution_clock::now();
//         duration = end - start;
//         std::cout << "Phase 4-1: the time is " << duration.count()/1000 << " s\n";

//         map<int, vector<uint64_t>> masks_X;
//         map<int, vector<uint64_t>> masks_Y;

//         for (const auto& kv : batch_x_to_i) {
//             int x = kv.first; const auto& indices = kv.second;
//             const auto& hx = cache_hash_x[x]; 
//             for (int k = 0; k < 3; k++) {
//                 int t_x = hx[k];
//                 for (int i : indices) {
//                     int off_x = (t_x - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE;
//                     if (masks_X.find(off_x) == masks_X.end()) masks_X[off_x] = vector<uint64_t>(encoder.slot_count(), 0);
//                     masks_X[off_x][i]++;
//                 }
//             }
//         }

//         for (const auto& kv : batch_y_to_i) {
//             int y = kv.first; const auto& indices = kv.second;
//             const auto& hy = cache_hash_y[y]; 
//             for (int k = 0; k < 3; k++) {
//                 int t_y = hy[k];
//                 for (int i : indices) {
//                     int off_y = (t_y - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE;
//                     if (masks_Y.find(off_y) == masks_Y.end()) masks_Y[off_y] = vector<uint64_t>(encoder.slot_count(), 0);
//                     masks_Y[off_y][i]++;
//                 }
//             }
//         }

//         end = std::chrono::high_resolution_clock::now();
//         duration = end - start;
//         std::cout << "Phase 4-2: the time is " << duration.count()/1000 << " s\n";

//         // ==========================================
//         // 【多线程改进 1】：X 和 Y 维度独立同态累加并发，这块时间最长
//         // ==========================================

//         #pragma omp parallel sections
//         {
//             #pragma omp section
//             {
//                 Evaluator thread_eval_x(context); BatchEncoder thread_enc_x(context);
//                 for (const auto& kv : masks_X) {
//                     int d = kv.first; Plaintext pt; thread_enc_x.encode(kv.second, pt); 
//                     Ciphertext temp = rot_X[d]; thread_eval_x.multiply_plain_inplace(temp, pt); thread_eval_x.add_inplace(enc_S_x, temp);
//                 }
//             }
//             #pragma omp section
//             {
//                 Evaluator thread_eval_y(context); BatchEncoder thread_enc_y(context);
//                 for (const auto& kv : masks_Y) {
//                     int d = kv.first; Plaintext pt; thread_enc_y.encode(kv.second, pt); 
//                     Ciphertext temp = rot_Y[d]; thread_eval_y.multiply_plain_inplace(temp, pt); thread_eval_y.add_inplace(enc_S_y, temp);
//                 }
//             }
//         }

//         end = std::chrono::high_resolution_clock::now();
//         duration = end - start;
//         std::cout << "Phase 4-3: the time is " << duration.count()/1000 << " s\n";

//         vector<Ciphertext> all_terms;
//         all_terms.push_back(enc_S_x); all_terms.push_back(enc_S_y);
//         for(uint64_t j = 1; j <= 2; j++) {
//             vector<uint64_t> vec_j(encoder.slot_count(), j); Plaintext pt_j; encoder.encode(vec_j, pt_j);
//             Ciphertext temp_x, temp_y;
//             local_eval.sub_plain(enc_S_x, pt_j, temp_x); local_eval.sub_plain(enc_S_y, pt_j, temp_y);
//             all_terms.push_back(temp_x); all_terms.push_back(temp_y);
//         }

//         Ciphertext enc_L_n;
//         local_eval.multiply_many(all_terms, rk, enc_L_n);
//         end = std::chrono::high_resolution_clock::now();
//         duration = end - start;
//         std::cout << "Phase 4: the time is " << duration.count()/1000 << " s\n";

//         // 阶段5 内部调试
//         start = std::chrono::high_resolution_clock::now();

//         #pragma omp critical
//         {
//             if (b == 0) {
//                 cout << "\n[Noise Budget-4] 【核心瓶颈】经过 multiply_many 后的 enc_L_n 剩余噪声: " 
//                      << debug_dec.invariant_noise_budget(enc_L_n) << " bits" << endl;
//             }
//             Plaintext pt_debug; vector<uint64_t> dec_Ln;
//             debug_dec.decrypt(enc_L_n, pt_debug); encoder.decode(pt_debug, dec_Ln);
            
//             if (b == 0) {
//                 cout << "\n[DEBUG-核心探针] ======== Batch 0 抽样 ========" << endl;
//                 for (int i = 0; i < min(5, curr_size); i++) {
//                     cout << " => 组合: (x=" << unique_dataset[start_idx + i].x 
//                          << ", y=" << unique_dataset[start_idx + i].y << ") | 原始重复数: " 
//                          << unique_dataset[start_idx + i].o_list.size()
//                          << " | 算出的 L_n: " << dec_Ln[i] << endl;
//                 }
//             }

//             int batch_hit_count = 0;
//             for(int i = 0; i < curr_size; i++) {
//                 if (dec_Ln[i] != 0) {
//                     batch_hit_count += unique_dataset[start_idx + i].o_list.size();
//                 }
//             }
//             global_fhe_hit_count += batch_hit_count;
//         }

//         end = std::chrono::high_resolution_clock::now();
//         duration = end - start;
//         std::cout << "Phase 5: the time is " << duration.count()/1000 << " s\n";

//         // 计算LC sketch
//         start = std::chrono::high_resolution_clock::now();

//         vector<Ciphertext> batch_sketch_list(SKETCH_SIZE);
        
//         // ==========================================
//         // 【多线程改进 2】：并发初始化和对齐 1000 个桶
//         // ==========================================
//         #pragma omp parallel for
//         for(int s = 0; s < SKETCH_SIZE; s++) {
//             Encryptor thread_enc(context, pk); Evaluator thread_eval(context);
//             thread_enc.encrypt_zero(batch_sketch_list[s]);
//             thread_eval.mod_switch_to_inplace(batch_sketch_list[s], enc_L_n.parms_id());
//         }

//         map<int, vector<uint64_t>> mask_out;
//         for (int i = 0; i < curr_size; i++) {
//             auto& rec = unique_dataset[start_idx + i];
//             for (const auto& kv : rec.bucket_counts) {
//                 int s = kv.first;
//                 int count = kv.second;
//                 if (mask_out.find(s) == mask_out.end()) {
//                     mask_out[s] = vector<uint64_t>(encoder.slot_count(), 0);
//                 }
//                 mask_out[s][i] = (count * server_blind_vec[s]) % plain_mod;
//             }
//         }

//         // 将 map 转化为 vector 以支持 OMP 并行遍历
//         vector<pair<int, vector<uint64_t>>> mask_out_vec(mask_out.begin(), mask_out.end());
        
//         // ==========================================
//         // 【多线程改进 3】：并发盲化掩码注入同态乘法
//         // ==========================================
//         #pragma omp parallel for
//         for (int idx = 0; idx < (int)mask_out_vec.size(); idx++) {
//             int s = mask_out_vec[idx].first;
//             Evaluator thread_eval(context); BatchEncoder thread_enc(context);
//             Plaintext pt_m; thread_enc.encode(mask_out_vec[idx].second, pt_m); 
//             Ciphertext masked_L_n;
//             thread_eval.multiply_plain(enc_L_n, pt_m, masked_L_n); 
//             thread_eval.add_inplace(batch_sketch_list[s], masked_L_n);
//         }
        
//         // ==========================================
//         // 【多线程改进 4】：并发水位落地
//         // ==========================================
//         #pragma omp parallel for
//         for(int s = 0; s < SKETCH_SIZE; s++) {
//             Evaluator thread_eval(context);
//             thread_eval.mod_switch_to_inplace(batch_sketch_list[s], context.last_context_data()->parms_id());
//         }
        
//         if (b == 0) cout << "[Server] 正在按 List 模式生成首个 Batch..." << endl;
        
//         if (b == 0) batch_sketches = batch_sketch_list; 
//         else {
//             // ==========================================
//             // 【多线程改进 5】：跨批次合并并发
//             // ==========================================
//             #pragma omp parallel for
//             for(int s = 0; s < SKETCH_SIZE; s++) {
//                 Evaluator thread_eval(context);
//                 thread_eval.add_inplace(batch_sketches[s], batch_sketch_list[s]);
//             }
//         }
//         end = std::chrono::high_resolution_clock::now();
//         duration = end - start;
//         std::cout << "Phase : the time is " << duration.count()/1000 << " s\n";
//     }

//     cout << "\n================ 最终 FHE 汇总 ================" << endl;
//     cout << " => FHE 在 L_n 中识别出的总命中数: " << global_fhe_hit_count << " (预期: 50)" << endl;
    
//     stringstream ss_out;
//     uint64_t S_out = SKETCH_SIZE;
//     ss_out.write(reinterpret_cast<const char*>(&S_out), sizeof(S_out));
    
//     // ==========================================
//     // 【多线程改进 6】：并发执行极致耗时的 Serialization
//     // ==========================================
//     vector<string> serialized_sketches(SKETCH_SIZE);
//     #pragma omp parallel for
//     for (int s = 0; s < SKETCH_SIZE; s++) {
//         stringstream stmp; 
//         batch_sketches[s].save(stmp);
//         serialized_sketches[s] = stmp.str();
//     }

//     // 依然保持顺序写入 socket buffer
//     for (int s = 0; s < SKETCH_SIZE; s++) {
//         uint64_t len = serialized_sketches[s].size();
//         ss_out.write(reinterpret_cast<const char*>(&len), sizeof(len));
//         ss_out.write(serialized_sketches[s].c_str(), len);
//     }

//     cout << "[Server] 已打包 " << SKETCH_SIZE << " 个密文并发送!" << endl;
//     auto end_time = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration_t = end_time - start_time;
//     std::cout << "The time is " << duration_t.count()/1000 << " s\n";
//     send_data(socket, ss_out.str());
//     return 0;
// }




// #include "common.h"
// #include "bloomfilter.h"
// #include "MurmurHash3.h"
// #include <sstream>
// #include <chrono>
// #include <omp.h>
// #include <vector>
// #include <random>
// #include <map>
// #include <fstream>
// #include <string>
// #include <algorithm>
// #include <iostream>

// using namespace std;
// using namespace seal;

// struct Record { int id; int x; int y; int o; };

// // 这版的问题，去重不够简洁，直接重复结合S_x结果
// // 阶段4、阶段5，好多都能多线程
// // 最后才解决传输sk问题



// struct UniqueRecord { 
//     int x; 
//     int y; 
//     vector<int> o_list; 
//     map<int, int> bucket_counts; 
// };

// int main(int argc, char* argv[]) {
//     auto start_time = std::chrono::high_resolution_clock::now();

//     // 阶段1  数据加载
//     auto start = std::chrono::high_resolution_clock::now();
//     if (argc != 2) { cerr << "Usage: ./server <listen_port>\n"; return 1; }

//     vector<Record> dataset;

//     std::random_device rd;
//     std::mt19937 gen(rd());
//     std::uniform_int_distribution<> dist_x(0, 100);
//     std::uniform_int_distribution<> dist_y(0, 100);
//     std::uniform_int_distribution<> dist_x_miss(0, 1000);
//     std::uniform_int_distribution<> dist_y_miss(0, 1000);
//     std::uniform_int_distribution<> dist_o(10000, 99999);

//     // ================= 数据集配置 =================
//     int dataset_choice = 1; 
//     std::string dataset_path;
//     int read_limit = 0;

//     if (dataset_choice == 0) {
//         dataset_path = "../dataset/spatial/quantize_spatial_1_20.csv";
//         read_limit = 21900;
//     } else {
//         dataset_path = "../dataset/brightkite/Brightkite_filter_quantized.csv";
//         read_limit = 115383;
//     }

//     double P = 0.2; 
//     // ==============================================

//     struct CsvRow {
//         int original_row;
//         int x;
//         int y;
//     };
//     std::vector<CsvRow> all_csv_data;

//     // 1. 打开并读取选定的 CSV 文件
//     std::ifstream file(dataset_path);
//     if (!file.is_open()) {
//         std::cerr << "[Error] 无法打开数据集文件: " << dataset_path << std::endl;
//         exit(1); 
//     }

//     std::string line;
//     int loaded_count = 0;
//     int current_row = 1; 

//     while (std::getline(file, line) && loaded_count < read_limit) {
//         std::stringstream ss(line);
//         std::string cell_x, cell_y;

//         if (std::getline(ss, cell_x, ',') && std::getline(ss, cell_y, ',')) {
//             try {
//                 int x = std::stoi(cell_x);
//                 int y = std::stoi(cell_y);
//                 all_csv_data.push_back({current_row, x, y});
//                 loaded_count++; 
//             } catch (const std::invalid_argument& e) {
//             }
//         }
//         current_row++;
//     }
//     file.close();
//     std::cout << "[Server] 成功从 " << dataset_path << " 提取 " << loaded_count << " 条有效数据。" << std::endl;

//     int target_size = static_cast<int>(all_csv_data.size() * P);
//     if (target_size == 0 && !all_csv_data.empty()) {
//         target_size = 1; 
//     }

//     std::shuffle(all_csv_data.begin(), all_csv_data.end(), gen);

//     for (int i = 0; i < target_size; i++) {
//         dataset.push_back({i, all_csv_data[i].x, all_csv_data[i].y, all_csv_data[i].original_row});
//     }

//     std::cout << "[Server] 按 P=" << P << " 比例随机抽取了 " << dataset.size() << " 条模拟数据参与 FHE 计算。" << std::endl;
//     auto end = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration = end - start;
//     std::cout << "Phase 1: the time is " << duration.count()/1000 << " s\n";

    


//     boost::asio::io_context io_context; tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), stoi(argv[1])));
//     tcp::socket socket(io_context); acceptor.accept(socket);

//     SEALContext context = create_fhe_context(); BatchEncoder encoder(context);
//     uint64_t plain_mod = context.first_context_data()->parms().plain_modulus().value();

//     string recv_str = receive_data(socket); stringstream ss_in(recv_str);
//     PublicKey pk; pk.load(context, ss_in); RelinKeys rk; rk.load(context, ss_in); GaloisKeys gal_keys; gal_keys.load(context, ss_in);
//     SecretKey sk; sk.load(context, ss_in); Decryptor debug_dec(context, sk);

//     // 阶段2 接收数据
//     start = std::chrono::high_resolution_clock::now();

//     int M; ss_in.read(reinterpret_cast<char*>(&M), sizeof(M));
//     uint64_t size_x, size_y;
//     ss_in.read(reinterpret_cast<char*>(&size_x), sizeof(size_x)); string str_x(size_x, '\0'); ss_in.read(&str_x[0], size_x); stringstream sx(str_x); Ciphertext enc_bf_x; enc_bf_x.load(context, sx);
//     ss_in.read(reinterpret_cast<char*>(&size_y), sizeof(size_y)); string str_y(size_y, '\0'); ss_in.read(&str_y[0], size_y); stringstream sy(str_y); Ciphertext enc_bf_y; enc_bf_y.load(context, sy);

//     cout << "\n[Noise Budget-1] 初始接收密文 enc_bf_x 剩余噪声: " 
//          << debug_dec.invariant_noise_budget(enc_bf_x) << " bits" << endl;

//     cout << "\n[DEBUG-Server-启动检查] 收到 Client 传来的 M (BloomFilter 大小): " << M << endl;

//     cout << "[DEBUG-Server-哈希对齐自检] 数据 42 的 3 个 Hash 索引: ";
//     for (int k = 0; k < 3; k++) {
//         cout << (int)hash_result(42, M, k) << " ";
//     }
//     cout << "\n" << endl;

//     // ==========================================
//     // 【核心优化】：明文域 (x, y) 组合去重预聚合 
//     // ==========================================
//     map<pair<int, int>, vector<int>> unique_map;
//     for (const auto& rec : dataset) {
//         unique_map[{rec.x, rec.y}].push_back(rec.o);
//     }
    
//     vector<UniqueRecord> unique_dataset;
//     for (const auto& kv : unique_map) {
//         UniqueRecord ur;
//         ur.x = kv.first.first;
//         ur.y = kv.first.second;
//         ur.o_list = kv.second;
//         // 提前预处理 blind mask 的桶归属，避免后续循环内 O(N*1000) 重复计算
//         for (int o_val : ur.o_list) {
//             int s = (int)hash_result(o_val, SKETCH_SIZE, 0);
//             ur.bucket_counts[s]++;
//         }
//         unique_dataset.push_back(ur);
//     }
//     int total_unique_records = unique_dataset.size();
    
//     cout << "[Server] 数据去重优化: 提取出 " 
//          << total_unique_records << " 个唯一的 (x, y) 组合以降低 FHE 计算开销。" << endl;

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 2: the time is " << duration.count()/1000 << " s\n";


//     // 阶段3  数据处理，比如计算旋转，加速后边的计算
//     start = std::chrono::high_resolution_clock::now();


//     // --- 独立维度哈希缓存 (X/Y 去重，相同直接复用) ---
//     map<int, vector<int>> cache_hash_x;
//     map<int, vector<int>> cache_hash_y;
//     for (const auto& rec : unique_dataset) {
//         if (cache_hash_x.find(rec.x) == cache_hash_x.end()) {
//             vector<int> hx(3);
//             for (int k = 0; k < 3; k++) hx[k] = (int)hash_result(rec.x, M, k);
//             cache_hash_x[rec.x] = hx;
//         }
//         if (cache_hash_y.find(rec.y) == cache_hash_y.end()) {
//             vector<int> hy(3);
//             for (int k = 0; k < 3; k++) hy[k] = (int)hash_result(rec.y, M, k);
//             cache_hash_y[rec.y] = hy;
//         }
//     }

//     // ==========================================
//     // 【新增统计】：展示维度去重效果
//     // ==========================================
//     cout << "\n[Server] 维度独立去重统计: 全局独立 X 坐标共 " << cache_hash_x.size() 
//          << " 个，全局独立 Y 坐标共 " << cache_hash_y.size() 
//          << " 个 (相同 X 或 Y 仅计算 1 次哈希映射)。" << endl;

//     // --- 全局盲化向量 ---
//     vector<uint64_t> server_blind_vec(SKETCH_SIZE, 0ULL);
//     std::uniform_int_distribution<uint64_t> dist_blind(1, 100);
//     for(int s = 0; s < SKETCH_SIZE; s++) {
//         server_blind_vec[s] = dist_blind(gen); 
//     }
//     cout << "[Server] 已生成内部盲化向量，准备进行掩码融合优化..." << endl;

//     Evaluator evaluator_main(context); int ROW_SIZE = encoder.slot_count() / 2; 
    
//     int num_batches = ceil((double)total_unique_records / ROW_SIZE); 

//     vector<bool> need_rot_X(ROW_SIZE, false); vector<bool> need_rot_Y(ROW_SIZE, false);
//     for (int b = 0; b < num_batches; b++) {
//         int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_unique_records - start_idx);
//         for (int i = 0; i < curr_size; i++) {
//             auto& rec = unique_dataset[start_idx + i];
//             const auto& hx = cache_hash_x[rec.x];
//             for (int k = 0; k < 3; k++) {
//                 int off_x = (hx[k] - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE; need_rot_X[off_x] = true;
//             }
//             const auto& hy = cache_hash_y[rec.y];
//             for (int k = 0; k < 3; k++) {
//                 int off_y = (hy[k] - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE; need_rot_Y[off_y] = true;
//             }
//         }
//     }

//     vector<Ciphertext> rot_X(ROW_SIZE), rot_Y(ROW_SIZE);
//     #pragma omp parallel for
//     for(int d = 0; d < ROW_SIZE; d++) {
//         if(need_rot_X[d]) evaluator_main.rotate_rows(enc_bf_x, d, gal_keys, rot_X[d]);
//         if(need_rot_Y[d]) evaluator_main.rotate_rows(enc_bf_y, d, gal_keys, rot_Y[d]);
//     }


//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3: the time is " << duration.count()/1000 << " s\n";
//     vector<Ciphertext> batch_sketches(SKETCH_SIZE);
//     int global_fhe_hit_count = 0;

//     std::cout << "the batch number is " << num_batches << " \n";

    
//     for (int b = 0; b < num_batches; b++) {


        


//         // 阶段4 计算L_n
//         start = std::chrono::high_resolution_clock::now();

//         Evaluator local_eval(context); Encryptor local_enc(context, pk);
//         int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_unique_records - start_idx);

//         Ciphertext enc_S_x, enc_S_y; local_enc.encrypt_zero(enc_S_x); local_enc.encrypt_zero(enc_S_y);

//         // 1. 同维归类聚合 (相同 X/Y 直接批量注入掩码，去掉遍历查找的不必要计算)
//         map<int, vector<int>> batch_x_to_i;
//         map<int, vector<int>> batch_y_to_i;
//         for (int i = 0; i < curr_size; i++) {
//             batch_x_to_i[unique_dataset[start_idx + i].x].push_back(i);
//             batch_y_to_i[unique_dataset[start_idx + i].y].push_back(i);
//         }

//         map<int, vector<uint64_t>> masks_X;
//         map<int, vector<uint64_t>> masks_Y;

//         for (const auto& kv : batch_x_to_i) {
//             int x = kv.first; const auto& indices = kv.second;
//             const auto& hx = cache_hash_x[x]; // 相同x直接复用前边结果
//             for (int k = 0; k < 3; k++) {
//                 int t_x = hx[k];
//                 for (int i : indices) {
//                     int off_x = (t_x - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE;
//                     if (masks_X.find(off_x) == masks_X.end()) masks_X[off_x] = vector<uint64_t>(encoder.slot_count(), 0);
//                     masks_X[off_x][i]++;
//                 }
//             }
//         }

//         for (const auto& kv : batch_y_to_i) {
//             int y = kv.first; const auto& indices = kv.second;
//             const auto& hy = cache_hash_y[y]; // 相同y直接复用前边结果
//             for (int k = 0; k < 3; k++) {
//                 int t_y = hy[k];
//                 for (int i : indices) {
//                     int off_y = (t_y - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE;
//                     if (masks_Y.find(off_y) == masks_Y.end()) masks_Y[off_y] = vector<uint64_t>(encoder.slot_count(), 0);
//                     masks_Y[off_y][i]++;
//                 }
//             }
//         }

//         // 2. 稀疏 Mask 同态累加（自动跳过空槽，避免盲目遍历 ROW_SIZE 次）
//         for (const auto& kv : masks_X) {
//             int d = kv.first;
//             Plaintext pt; encoder.encode(kv.second, pt); 
//             Ciphertext temp = rot_X[d]; local_eval.multiply_plain_inplace(temp, pt); local_eval.add_inplace(enc_S_x, temp);
//         }
//         for (const auto& kv : masks_Y) {
//             int d = kv.first;
//             Plaintext pt; encoder.encode(kv.second, pt); 
//             Ciphertext temp = rot_Y[d]; local_eval.multiply_plain_inplace(temp, pt); local_eval.add_inplace(enc_S_y, temp);
//         }

//         vector<Ciphertext> all_terms;
//         all_terms.push_back(enc_S_x); all_terms.push_back(enc_S_y);
//         for(uint64_t j = 1; j <= 2; j++) {
//             vector<uint64_t> vec_j(encoder.slot_count(), j); Plaintext pt_j; encoder.encode(vec_j, pt_j);
//             Ciphertext temp_x, temp_y;
//             local_eval.sub_plain(enc_S_x, pt_j, temp_x); local_eval.sub_plain(enc_S_y, pt_j, temp_y);
//             all_terms.push_back(temp_x); all_terms.push_back(temp_y);
//         }

//         Ciphertext enc_L_n;
//         local_eval.multiply_many(all_terms, rk, enc_L_n);
//         end = std::chrono::high_resolution_clock::now();
//         duration = end - start;
//         std::cout << "Phase 4: the time is " << duration.count()/1000 << " s\n";

//         // 阶段5 内部调试
//         start = std::chrono::high_resolution_clock::now();

//         #pragma omp critical
//         {
//             if (b == 0) {
//                 cout << "\n[Noise Budget-4] 【核心瓶颈】经过 multiply_many 后的 enc_L_n 剩余噪声: " 
//                      << debug_dec.invariant_noise_budget(enc_L_n) << " bits" << endl;
//             }
//             Plaintext pt_debug; vector<uint64_t> dec_Ln;
//             debug_dec.decrypt(enc_L_n, pt_debug); encoder.decode(pt_debug, dec_Ln);
            
//             if (b == 0) {
//                 cout << "\n[DEBUG-核心探针] ======== Batch 0 抽样 ========" << endl;
//                 for (int i = 0; i < min(5, curr_size); i++) {
//                     cout << " => 组合: (x=" << unique_dataset[start_idx + i].x 
//                          << ", y=" << unique_dataset[start_idx + i].y << ") | 原始重复数: " 
//                          << unique_dataset[start_idx + i].o_list.size()
//                          << " | 算出的 L_n: " << dec_Ln[i] << endl;
//                 }
//             }

//             int batch_hit_count = 0;
//             for(int i = 0; i < curr_size; i++) {
//                 if (dec_Ln[i] != 0) {
//                     batch_hit_count += unique_dataset[start_idx + i].o_list.size();
//                 }
//             }
//             global_fhe_hit_count += batch_hit_count;
//         }


//         end = std::chrono::high_resolution_clock::now();
//         duration = end - start;
//         std::cout << "Phase 5: the time is " << duration.count()/1000 << " s\n";


//         // 计算LC sketch
//         start = std::chrono::high_resolution_clock::now();

//         vector<Ciphertext> batch_sketch_list(SKETCH_SIZE);
//         for(int s = 0; s < SKETCH_SIZE; s++) {
//             local_enc.encrypt_zero(batch_sketch_list[s]);
//             local_eval.mod_switch_to_inplace(batch_sketch_list[s], enc_L_n.parms_id());
//         }

//         // 3. 利用之前在 UniqueRecord 中缓存好的 bucket_counts，实现稀疏降维计算
//         map<int, vector<uint64_t>> mask_out;
//         for (int i = 0; i < curr_size; i++) {
//             auto& rec = unique_dataset[start_idx + i];
//             for (const auto& kv : rec.bucket_counts) {
//                 int s = kv.first;
//                 int count = kv.second;
//                 if (mask_out.find(s) == mask_out.end()) {
//                     mask_out[s] = vector<uint64_t>(encoder.slot_count(), 0);
//                 }
//                 mask_out[s][i] = (count * server_blind_vec[s]) % plain_mod;
//             }
//         }

//         for (const auto& kv : mask_out) {
//             int s = kv.first;
//             Plaintext pt_m; encoder.encode(kv.second, pt_m); 
//             Ciphertext masked_L_n;
//             local_eval.multiply_plain(enc_L_n, pt_m, masked_L_n); 
//             local_eval.add_inplace(batch_sketch_list[s], masked_L_n);
//         }
        
//         for(int s = 0; s < SKETCH_SIZE; s++) {
//             local_eval.mod_switch_to_inplace(batch_sketch_list[s], context.last_context_data()->parms_id());
//         }
        
//         if (b == 0) cout << "[Server] 正在按 List 模式生成首个 Batch..." << endl;
        
//         if (b == 0) batch_sketches = batch_sketch_list; 
//         else {
//             for(int s=0; s<SKETCH_SIZE; s++) local_eval.add_inplace(batch_sketches[s], batch_sketch_list[s]);
//         }
//         end = std::chrono::high_resolution_clock::now();
//         duration = end - start;
//         std::cout << "Phase : the time is " << duration.count()/1000 << " s\n";
//     }

//     cout << "\n================ 最终 FHE 汇总 ================" << endl;
//     cout << " => FHE 在 L_n 中识别出的总命中数: " << global_fhe_hit_count << " (预期: 50)" << endl;
    
//     stringstream ss_out;
//     uint64_t S_out = SKETCH_SIZE;
//     ss_out.write(reinterpret_cast<const char*>(&S_out), sizeof(S_out));
    
//     for (int s = 0; s < SKETCH_SIZE; s++) {
//         stringstream stmp; 
//         batch_sketches[s].save(stmp);
//         string str = stmp.str();
//         uint64_t len = str.size();
//         ss_out.write(reinterpret_cast<const char*>(&len), sizeof(len));
//         ss_out.write(str.c_str(), len);
//     }

//     cout << "[Server] 已打包 " << SKETCH_SIZE << " 个密文并发送!" << endl;
//     auto end_time = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration_t = end_time - start_time;
//     std::cout << "The time is " << duration_t.count()/1000 << " s\n";
//     send_data(socket, ss_out.str());
//     return 0;
// }







// #include "common.h"
// #include "bloomfilter.h"
// #include "MurmurHash3.h"
// #include <sstream>
// #include <chrono>
// #include <omp.h>
// #include <vector>
// #include <random>
// #include <map>
// #include <fstream>
// #include <string>
// #include <algorithm>
// #include <iostream>

// using namespace std;
// using namespace seal;

// struct Record { int id; int x; int y; int o; };

// // 标注最全版
// struct UniqueRecord { 
//     int x; 
//     int y; 
//     vector<int> o_list; 
//     map<int, int> bucket_counts; 
// };

// int main(int argc, char* argv[]) {
//     auto start_time = std::chrono::high_resolution_clock::now();

//     // 阶段1  数据加载
//     auto start = std::chrono::high_resolution_clock::now();
//     if (argc != 2) { cerr << "Usage: ./server <listen_port>\n"; return 1; }

//     vector<Record> dataset;

//     std::random_device rd;
//     std::mt19937 gen(rd());
//     std::uniform_int_distribution<> dist_x(0, 100);
//     std::uniform_int_distribution<> dist_y(0, 100);
//     std::uniform_int_distribution<> dist_x_miss(0, 1000);
//     std::uniform_int_distribution<> dist_y_miss(0, 1000);
//     std::uniform_int_distribution<> dist_o(10000, 99999);

//     // ================= 数据集配置 =================
//     int dataset_choice = 1; 
//     std::string dataset_path;
//     int read_limit = 0;

//     if (dataset_choice == 0) {
//         dataset_path = "../dataset/spatial/quantize_spatial_1_20.csv";
//         read_limit = 21900;
//     } else {
//         dataset_path = "../dataset/brightkite/Brightkite_filter_quantized.csv";
//         read_limit = 115383;
//     }

//     double P = 0.2; 
//     // ==============================================

//     struct CsvRow {
//         int original_row;
//         int x;
//         int y;
//     };
//     std::vector<CsvRow> all_csv_data;

//     // 1. 打开并读取选定的 CSV 文件
//     std::ifstream file(dataset_path);
//     if (!file.is_open()) {
//         std::cerr << "[Error] 无法打开数据集文件: " << dataset_path << std::endl;
//         exit(1); 
//     }

//     std::string line;
//     int loaded_count = 0;
//     int current_row = 1; 

//     while (std::getline(file, line) && loaded_count < read_limit) {
//         std::stringstream ss(line);
//         std::string cell_x, cell_y;

//         if (std::getline(ss, cell_x, ',') && std::getline(ss, cell_y, ',')) {
//             try {
//                 int x = std::stoi(cell_x);
//                 int y = std::stoi(cell_y);
//                 all_csv_data.push_back({current_row, x, y});
//                 loaded_count++; 
//             } catch (const std::invalid_argument& e) {
//             }
//         }
//         current_row++;
//     }
//     file.close();
//     std::cout << "[Server] 成功从 " << dataset_path << " 提取 " << loaded_count << " 条有效数据。" << std::endl;

//     int target_size = static_cast<int>(all_csv_data.size() * P);
//     if (target_size == 0 && !all_csv_data.empty()) {
//         target_size = 1; 
//     }

//     std::shuffle(all_csv_data.begin(), all_csv_data.end(), gen);

//     for (int i = 0; i < target_size; i++) {
//         dataset.push_back({i, all_csv_data[i].x, all_csv_data[i].y, all_csv_data[i].original_row});
//     }

//     std::cout << "[Server] 按 P=" << P << " 比例随机抽取了 " << dataset.size() << " 条模拟数据参与 FHE 计算。" << std::endl;
//     auto end = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration = end - start;
//     std::cout << "Phase 1: the time is " << duration.count()/1000 << " s\n";

    


//     boost::asio::io_context io_context; tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), stoi(argv[1])));
//     tcp::socket socket(io_context); acceptor.accept(socket);

//     SEALContext context = create_fhe_context(); BatchEncoder encoder(context);
//     uint64_t plain_mod = context.first_context_data()->parms().plain_modulus().value();

//     string recv_str = receive_data(socket); stringstream ss_in(recv_str);
//     PublicKey pk; pk.load(context, ss_in); RelinKeys rk; rk.load(context, ss_in); GaloisKeys gal_keys; gal_keys.load(context, ss_in);
//     SecretKey sk; sk.load(context, ss_in); Decryptor debug_dec(context, sk);

//     // 阶段2 接收数据
//     start = std::chrono::high_resolution_clock::now();

//     int M; ss_in.read(reinterpret_cast<char*>(&M), sizeof(M));
//     uint64_t size_x, size_y;
//     ss_in.read(reinterpret_cast<char*>(&size_x), sizeof(size_x)); string str_x(size_x, '\0'); ss_in.read(&str_x[0], size_x); stringstream sx(str_x); Ciphertext enc_bf_x; enc_bf_x.load(context, sx);
//     ss_in.read(reinterpret_cast<char*>(&size_y), sizeof(size_y)); string str_y(size_y, '\0'); ss_in.read(&str_y[0], size_y); stringstream sy(str_y); Ciphertext enc_bf_y; enc_bf_y.load(context, sy);

//     cout << "\n[Noise Budget-1] 初始接收密文 enc_bf_x 剩余噪声: " 
//          << debug_dec.invariant_noise_budget(enc_bf_x) << " bits" << endl;

//     cout << "\n[DEBUG-Server-启动检查] 收到 Client 传来的 M (BloomFilter 大小): " << M << endl;

//     cout << "[DEBUG-Server-哈希对齐自检] 数据 42 的 3 个 Hash 索引: ";
//     for (int k = 0; k < 3; k++) {
//         cout << (int)hash_result(42, M, k) << " ";
//     }
//     cout << "\n" << endl;

//     // ==========================================
//     // 【核心优化】：明文域 (x, y) 组合去重预聚合 
//     // ==========================================
//     map<pair<int, int>, vector<int>> unique_map;
//     for (const auto& rec : dataset) {
//         unique_map[{rec.x, rec.y}].push_back(rec.o);
//     }
    
//     vector<UniqueRecord> unique_dataset;
//     for (const auto& kv : unique_map) {
//         UniqueRecord ur;
//         ur.x = kv.first.first;
//         ur.y = kv.first.second;
//         ur.o_list = kv.second;
//         // 提前预处理 blind mask 的桶归属，避免后续循环内 O(N*1000) 重复计算
//         for (int o_val : ur.o_list) {
//             int s = (int)hash_result(o_val, SKETCH_SIZE, 0);
//             ur.bucket_counts[s]++;
//         }
//         unique_dataset.push_back(ur);
//     }
//     int total_unique_records = unique_dataset.size();
    
//     cout << "[Server] 数据去重优化: 提取出 " 
//          << total_unique_records << " 个唯一的 (x, y) 组合以降低 FHE 计算开销。" << endl;

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 2: the time is " << duration.count()/1000 << " s\n";


//     // 阶段3  数据处理，比如计算旋转，加速后边的计算
//     start = std::chrono::high_resolution_clock::now();


//     // --- 独立维度哈希缓存 (X/Y 去重，相同直接复用) ---
//     map<int, vector<int>> cache_hash_x;
//     map<int, vector<int>> cache_hash_y;
//     for (const auto& rec : unique_dataset) {
//         if (cache_hash_x.find(rec.x) == cache_hash_x.end()) {
//             vector<int> hx(3);
//             for (int k = 0; k < 3; k++) hx[k] = (int)hash_result(rec.x, M, k);
//             cache_hash_x[rec.x] = hx;
//         }
//         if (cache_hash_y.find(rec.y) == cache_hash_y.end()) {
//             vector<int> hy(3);
//             for (int k = 0; k < 3; k++) hy[k] = (int)hash_result(rec.y, M, k);
//             cache_hash_y[rec.y] = hy;
//         }
//     }

//     // ==========================================
//     // 【新增统计】：展示维度去重效果
//     // ==========================================
//     cout << "\n[Server] 维度独立去重统计: 全局独立 X 坐标共 " << cache_hash_x.size() 
//          << " 个，全局独立 Y 坐标共 " << cache_hash_y.size() 
//          << " 个 (相同 X 或 Y 仅计算 1 次哈希映射)。" << endl;

//     // --- 全局盲化向量 ---
//     vector<uint64_t> server_blind_vec(SKETCH_SIZE, 0ULL);
//     std::uniform_int_distribution<uint64_t> dist_blind(1, 100);
//     for(int s = 0; s < SKETCH_SIZE; s++) {
//         server_blind_vec[s] = dist_blind(gen); 
//     }
//     cout << "[Server] 已生成内部盲化向量，准备进行掩码融合优化..." << endl;

//     Evaluator evaluator_main(context); int ROW_SIZE = encoder.slot_count() / 2; 
    
//     int num_batches = ceil((double)total_unique_records / ROW_SIZE); 

//     vector<bool> need_rot_X(ROW_SIZE, false); vector<bool> need_rot_Y(ROW_SIZE, false);
//     for (int b = 0; b < num_batches; b++) {
//         int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_unique_records - start_idx);
//         for (int i = 0; i < curr_size; i++) {
//             auto& rec = unique_dataset[start_idx + i];
//             const auto& hx = cache_hash_x[rec.x];
//             for (int k = 0; k < 3; k++) {
//                 int off_x = (hx[k] - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE; need_rot_X[off_x] = true;
//             }
//             const auto& hy = cache_hash_y[rec.y];
//             for (int k = 0; k < 3; k++) {
//                 int off_y = (hy[k] - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE; need_rot_Y[off_y] = true;
//             }
//         }
//     }

//     vector<Ciphertext> rot_X(ROW_SIZE), rot_Y(ROW_SIZE);
//     #pragma omp parallel for
//     for(int d = 0; d < ROW_SIZE; d++) {
//         if(need_rot_X[d]) evaluator_main.rotate_rows(enc_bf_x, d, gal_keys, rot_X[d]);
//         if(need_rot_Y[d]) evaluator_main.rotate_rows(enc_bf_y, d, gal_keys, rot_Y[d]);
//     }


//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3: the time is " << duration.count()/1000 << " s\n";
//     vector<Ciphertext> batch_sketches(SKETCH_SIZE);
//     int global_fhe_hit_count = 0;

//     std::cout << "the batch number is " << num_batches << " \n";
//     for (int b = 0; b < num_batches; b++) {


        


//         // 阶段4 计算L_n
//         start = std::chrono::high_resolution_clock::now();

//         Evaluator local_eval(context); Encryptor local_enc(context, pk);
//         int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_unique_records - start_idx);

//         Ciphertext enc_S_x, enc_S_y; local_enc.encrypt_zero(enc_S_x); local_enc.encrypt_zero(enc_S_y);

//         // 1. 同维归类聚合 (相同 X/Y 直接批量注入掩码，去掉遍历查找的不必要计算)
//         map<int, vector<int>> batch_x_to_i;
//         map<int, vector<int>> batch_y_to_i;
//         for (int i = 0; i < curr_size; i++) {
//             batch_x_to_i[unique_dataset[start_idx + i].x].push_back(i);
//             batch_y_to_i[unique_dataset[start_idx + i].y].push_back(i);
//         }

//         map<int, vector<uint64_t>> masks_X;
//         map<int, vector<uint64_t>> masks_Y;

//         for (const auto& kv : batch_x_to_i) {
//             int x = kv.first; const auto& indices = kv.second;
//             const auto& hx = cache_hash_x[x]; // 相同x直接复用前边结果
//             for (int k = 0; k < 3; k++) {
//                 int t_x = hx[k];
//                 for (int i : indices) {
//                     int off_x = (t_x - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE;
//                     if (masks_X.find(off_x) == masks_X.end()) masks_X[off_x] = vector<uint64_t>(encoder.slot_count(), 0);
//                     masks_X[off_x][i]++;
//                 }
//             }
//         }

//         for (const auto& kv : batch_y_to_i) {
//             int y = kv.first; const auto& indices = kv.second;
//             const auto& hy = cache_hash_y[y]; // 相同y直接复用前边结果
//             for (int k = 0; k < 3; k++) {
//                 int t_y = hy[k];
//                 for (int i : indices) {
//                     int off_y = (t_y - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE;
//                     if (masks_Y.find(off_y) == masks_Y.end()) masks_Y[off_y] = vector<uint64_t>(encoder.slot_count(), 0);
//                     masks_Y[off_y][i]++;
//                 }
//             }
//         }

//         // 2. 稀疏 Mask 同态累加（自动跳过空槽，避免盲目遍历 ROW_SIZE 次）
//         for (const auto& kv : masks_X) {
//             int d = kv.first;
//             Plaintext pt; encoder.encode(kv.second, pt); 
//             Ciphertext temp = rot_X[d]; local_eval.multiply_plain_inplace(temp, pt); local_eval.add_inplace(enc_S_x, temp);
//         }
//         for (const auto& kv : masks_Y) {
//             int d = kv.first;
//             Plaintext pt; encoder.encode(kv.second, pt); 
//             Ciphertext temp = rot_Y[d]; local_eval.multiply_plain_inplace(temp, pt); local_eval.add_inplace(enc_S_y, temp);
//         }

//         vector<Ciphertext> all_terms;
//         all_terms.push_back(enc_S_x); all_terms.push_back(enc_S_y);
//         for(uint64_t j = 1; j <= 2; j++) {
//             vector<uint64_t> vec_j(encoder.slot_count(), j); Plaintext pt_j; encoder.encode(vec_j, pt_j);
//             Ciphertext temp_x, temp_y;
//             local_eval.sub_plain(enc_S_x, pt_j, temp_x); local_eval.sub_plain(enc_S_y, pt_j, temp_y);
//             all_terms.push_back(temp_x); all_terms.push_back(temp_y);
//         }

//         Ciphertext enc_L_n;
//         local_eval.multiply_many(all_terms, rk, enc_L_n);
//         end = std::chrono::high_resolution_clock::now();
//         duration = end - start;
//         std::cout << "Phase 4: the time is " << duration.count()/1000 << " s\n";

//         // 阶段5 内部调试
//         start = std::chrono::high_resolution_clock::now();

//         #pragma omp critical
//         {
//             if (b == 0) {
//                 cout << "\n[Noise Budget-4] 【核心瓶颈】经过 multiply_many 后的 enc_L_n 剩余噪声: " 
//                      << debug_dec.invariant_noise_budget(enc_L_n) << " bits" << endl;
//             }
//             Plaintext pt_debug; vector<uint64_t> dec_Ln;
//             debug_dec.decrypt(enc_L_n, pt_debug); encoder.decode(pt_debug, dec_Ln);
            
//             if (b == 0) {
//                 cout << "\n[DEBUG-核心探针] ======== Batch 0 抽样 ========" << endl;
//                 for (int i = 0; i < min(5, curr_size); i++) {
//                     cout << " => 组合: (x=" << unique_dataset[start_idx + i].x 
//                          << ", y=" << unique_dataset[start_idx + i].y << ") | 原始重复数: " 
//                          << unique_dataset[start_idx + i].o_list.size()
//                          << " | 算出的 L_n: " << dec_Ln[i] << endl;
//                 }
//             }

//             int batch_hit_count = 0;
//             for(int i = 0; i < curr_size; i++) {
//                 if (dec_Ln[i] != 0) {
//                     batch_hit_count += unique_dataset[start_idx + i].o_list.size();
//                 }
//             }
//             global_fhe_hit_count += batch_hit_count;
//         }


//         end = std::chrono::high_resolution_clock::now();
//         duration = end - start;
//         std::cout << "Phase 5: the time is " << duration.count()/1000 << " s\n";


//         // 计算LC sketch
//         start = std::chrono::high_resolution_clock::now();

//         vector<Ciphertext> batch_sketch_list(SKETCH_SIZE);
//         for(int s = 0; s < SKETCH_SIZE; s++) {
//             local_enc.encrypt_zero(batch_sketch_list[s]);
//             local_eval.mod_switch_to_inplace(batch_sketch_list[s], enc_L_n.parms_id());
//         }

//         // 3. 利用之前在 UniqueRecord 中缓存好的 bucket_counts，实现稀疏降维计算
//         map<int, vector<uint64_t>> mask_out;
//         for (int i = 0; i < curr_size; i++) {
//             auto& rec = unique_dataset[start_idx + i];
//             for (const auto& kv : rec.bucket_counts) {
//                 int s = kv.first;
//                 int count = kv.second;
//                 if (mask_out.find(s) == mask_out.end()) {
//                     mask_out[s] = vector<uint64_t>(encoder.slot_count(), 0);
//                 }
//                 mask_out[s][i] = (count * server_blind_vec[s]) % plain_mod;
//             }
//         }

//         for (const auto& kv : mask_out) {
//             int s = kv.first;
//             Plaintext pt_m; encoder.encode(kv.second, pt_m); 
//             Ciphertext masked_L_n;
//             local_eval.multiply_plain(enc_L_n, pt_m, masked_L_n); 
//             local_eval.add_inplace(batch_sketch_list[s], masked_L_n);
//         }
        
//         for(int s = 0; s < SKETCH_SIZE; s++) {
//             local_eval.mod_switch_to_inplace(batch_sketch_list[s], context.last_context_data()->parms_id());
//         }
        
//         if (b == 0) cout << "[Server] 正在按 List 模式生成首个 Batch..." << endl;
        
//         if (b == 0) batch_sketches = batch_sketch_list; 
//         else {
//             for(int s=0; s<SKETCH_SIZE; s++) local_eval.add_inplace(batch_sketches[s], batch_sketch_list[s]);
//         }
//         end = std::chrono::high_resolution_clock::now();
//         duration = end - start;
//         std::cout << "Phase : the time is " << duration.count()/1000 << " s\n";
//     }

//     cout << "\n================ 最终 FHE 汇总 ================" << endl;
//     cout << " => FHE 在 L_n 中识别出的总命中数: " << global_fhe_hit_count << " (预期: 50)" << endl;
    
//     stringstream ss_out;
//     uint64_t S_out = SKETCH_SIZE;
//     ss_out.write(reinterpret_cast<const char*>(&S_out), sizeof(S_out));
    
//     for (int s = 0; s < SKETCH_SIZE; s++) {
//         stringstream stmp; 
//         batch_sketches[s].save(stmp);
//         string str = stmp.str();
//         uint64_t len = str.size();
//         ss_out.write(reinterpret_cast<const char*>(&len), sizeof(len));
//         ss_out.write(str.c_str(), len);
//     }

//     cout << "[Server] 已打包 " << SKETCH_SIZE << " 个密文并发送!" << endl;
//     auto end_time = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration_t = end_time - start_time;
//     std::cout << "The time is " << duration_t.count()/1000 << " s\n";
//     send_data(socket, ss_out.str());
//     return 0;
// }









// // #include "common.h"
// // #include "bloomfilter.h"
// // #include "MurmurHash3.h"
// // #include <sstream>
// // #include <chrono>
// // #include <omp.h>
// // #include <vector>
// // #include <random>
// // #include <map>

// // #include <fstream>

// // #include <string>

// // #include <algorithm>
// // #include <iostream>

// // using namespace std;
// // using namespace seal;

// // struct Record { int id; int x; int y; int o; };

// // // 新增：用于存储唯一组合的结构体
// // struct UniqueRecord { 
// //     int x; 
// //     int y; 
// //     vector<int> o_list; 
// // };

// // int main(int argc, char* argv[]) {
// //     if (argc != 2) { cerr << "Usage: ./server <listen_port>\n"; return 1; }
// //     // 数据输入完成，但去重去的是(x,y)，这个多很多计算


// //     vector<Record> dataset;

// //     // 第 63 行：这里已经定义了 rd 和 gen
// //     std::random_device rd;
// //     std::mt19937 gen(rd());
// //     std::uniform_int_distribution<> dist_x(0, 100);
// //     std::uniform_int_distribution<> dist_y(0, 100);
// //     std::uniform_int_distribution<> dist_x_miss(0, 1000);
// //     std::uniform_int_distribution<> dist_y_miss(0, 1000);
// //     std::uniform_int_distribution<> dist_o(10000, 99999);


// //     // ================= 数据集配置 =================
// //     // 0: 代表使用 spatial 数据集 (上限 21900 条)
// //     // 1: 代表使用 brightkite 数据集 (上限 115383 条)
// //     int dataset_choice = 0; 
    
// //     std::string dataset_path;
// //     int read_limit = 0;

// //     if (dataset_choice == 0) {
// //         dataset_path = "../dataset/spatial/quantize_spatial_1_20.csv";
// //         read_limit = 21900;
// //     } else {
// //         dataset_path = "../dataset/brightkite/Brightkite_filter_quantized.csv";
// //         read_limit = 115383;
// //     }

// //     double P = 0.2; // 抽取比例 (例如 0.2 代表从截取的数据中再抽取 20%)
// //     // ==============================================

// //     struct CsvRow {
// //         int original_row;
// //         int x;
// //         int y;
// //     };
// //     std::vector<CsvRow> all_csv_data;

// //     // 1. 打开并读取选定的 CSV 文件
// //     std::ifstream file(dataset_path);
// //     if (!file.is_open()) {
// //         std::cerr << "[Error] 无法打开数据集文件: " << dataset_path << std::endl;
// //         exit(1); 
// //     }

// //     std::string line;
// //     int loaded_count = 0;
// //     int current_row = 1; // 记录原始文件的行数作为 o

// //     // 只要没读满 read_limit 条，就一直往下读
// //     while (std::getline(file, line) && loaded_count < read_limit) {
// //         std::stringstream ss(line);
// //         std::string cell_x, cell_y;

// //         if (std::getline(ss, cell_x, ',') && std::getline(ss, cell_y, ',')) {
// //             try {
// //                 int x = std::stoi(cell_x);
// //                 int y = std::stoi(cell_y);
// //                 all_csv_data.push_back({current_row, x, y});
// //                 loaded_count++; // 只有成功转换的数据才算作一条
// //             } catch (const std::invalid_argument& e) {
// //                 // 跳过表头或无效行
// //             }
// //         }
// //         current_row++;
// //     }
// //     file.close();
// //     std::cout << "[Server] 成功从 " << dataset_path << " 提取 " << loaded_count << " 条有效数据。" << std::endl;

// //     // 2. 按比例 P 计算需要抽取的最终目标数量
// //     int target_size = static_cast<int>(all_csv_data.size() * P);
// //     if (target_size == 0 && !all_csv_data.empty()) {
// //         target_size = 1; 
// //     }

// //     // 3. 将单一数据集完全打乱 (复用已有的 gen)
// //     std::shuffle(all_csv_data.begin(), all_csv_data.end(), gen);

// //     // 4. 截取前 target_size 个数据推入真正的 dataset 中
// //     for (int i = 0; i < target_size; i++) {
// //         dataset.push_back({i, all_csv_data[i].x, all_csv_data[i].y, all_csv_data[i].original_row});
// //     }

// //     std::cout << "[Server] 按 P=" << P << " 比例随机抽取了 " << dataset.size() << " 条模拟数据参与 FHE 计算。" << std::endl;

// //     boost::asio::io_context io_context; tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), stoi(argv[1])));
// //     tcp::socket socket(io_context); acceptor.accept(socket);

// //     SEALContext context = create_fhe_context(); BatchEncoder encoder(context);
// //     uint64_t plain_mod = context.first_context_data()->parms().plain_modulus().value();

// //     string recv_str = receive_data(socket); stringstream ss_in(recv_str);
// //     PublicKey pk; pk.load(context, ss_in); RelinKeys rk; rk.load(context, ss_in); GaloisKeys gal_keys; gal_keys.load(context, ss_in);
// //     SecretKey sk; sk.load(context, ss_in); Decryptor debug_dec(context, sk);

// //     int M; ss_in.read(reinterpret_cast<char*>(&M), sizeof(M));
// //     uint64_t size_x, size_y;
// //     ss_in.read(reinterpret_cast<char*>(&size_x), sizeof(size_x)); string str_x(size_x, '\0'); ss_in.read(&str_x[0], size_x); stringstream sx(str_x); Ciphertext enc_bf_x; enc_bf_x.load(context, sx);
// //     ss_in.read(reinterpret_cast<char*>(&size_y), sizeof(size_y)); string str_y(size_y, '\0'); ss_in.read(&str_y[0], size_y); stringstream sy(str_y); Ciphertext enc_bf_y; enc_bf_y.load(context, sy);

// //     cout << "\n[Noise Budget-1] 初始接收密文 enc_bf_x 剩余噪声: " 
// //          << debug_dec.invariant_noise_budget(enc_bf_x) << " bits" << endl;

// //     cout << "\n[DEBUG-Server-启动检查] 收到 Client 传来的 M (BloomFilter 大小): " << M << endl;

// //     cout << "[DEBUG-Server-哈希对齐自检] 数据 42 的 3 个 Hash 索引: ";
// //     for (int k = 0; k < 3; k++) {
// //         cout << (int)hash_result(42, M, k) << " ";
// //     }
// //     cout << "\n" << endl;

    
    
// //     // ==========================================
// //     // 【核心优化】：明文域 (x, y) 组合去重预聚合
// //     // ==========================================
// //     map<pair<int, int>, vector<int>> unique_map;
// //     for (const auto& rec : dataset) {
// //         unique_map[{rec.x, rec.y}].push_back(rec.o);
// //     }
    
// //     vector<UniqueRecord> unique_dataset;
// //     for (const auto& kv : unique_map) {
// //         unique_dataset.push_back({kv.first.first, kv.first.second, kv.second});
// //     }
// //     int total_unique_records = unique_dataset.size();
    
// //     cout << "[Server] 数据去重优化: 提取出 " 
// //          << total_unique_records << " 个唯一的 (x, y) 组合以降低 FHE 计算开销。" << endl;

// //     // --- 全局盲化向量 ---
// //     vector<uint64_t> server_blind_vec(SKETCH_SIZE, 0ULL);
// //     std::uniform_int_distribution<uint64_t> dist_blind(1, 100);
// //     for(int s = 0; s < SKETCH_SIZE; s++) {
// //         server_blind_vec[s] = dist_blind(gen); 
// //     }
// //     cout << "[Server] 已生成内部盲化向量，准备进行掩码融合优化..." << endl;

// //     Evaluator evaluator_main(context); int ROW_SIZE = encoder.slot_count() / 2; 
    
// //     // 注意：接下来的所有 batch 拆分都基于去重后的 total_unique_records
// //     int num_batches = ceil((double)total_unique_records / ROW_SIZE); 

// //     vector<bool> need_rot_X(ROW_SIZE, false); vector<bool> need_rot_Y(ROW_SIZE, false);
// //     for (int b = 0; b < num_batches; b++) {
// //         int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_unique_records - start_idx);
// //         for (int i = 0; i < curr_size; i++) {
// //             auto& rec = unique_dataset[start_idx + i];
// //             for (int k = 0; k < 3; k++) {
// //                 int off_x = ((int)hash_result(rec.x, M, k) - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE; need_rot_X[off_x] = true;
// //                 int off_y = ((int)hash_result(rec.y, M, k) - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE; need_rot_Y[off_y] = true;
// //             }
// //         }
// //     }

// //     vector<Ciphertext> rot_X(ROW_SIZE), rot_Y(ROW_SIZE);
// //     #pragma omp parallel for
// //     for(int d = 0; d < ROW_SIZE; d++) {
// //         if(need_rot_X[d]) evaluator_main.rotate_rows(enc_bf_x, d, gal_keys, rot_X[d]);
// //         if(need_rot_Y[d]) evaluator_main.rotate_rows(enc_bf_y, d, gal_keys, rot_Y[d]);
// //     }

// //     vector<Ciphertext> batch_sketches(SKETCH_SIZE); // 现在是 List 模式，总外层结果为 List
// //     int global_fhe_hit_count = 0;

// //     for (int b = 0; b < num_batches; b++) {
// //         Evaluator local_eval(context); Encryptor local_enc(context, pk);
// //         int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_unique_records - start_idx);

// //         Ciphertext enc_S_x, enc_S_y; local_enc.encrypt_zero(enc_S_x); local_enc.encrypt_zero(enc_S_y);

// //         for (int d = 0; d < ROW_SIZE; d++) {
// //             vector<uint64_t> mask_X(encoder.slot_count(), 0); vector<uint64_t> mask_Y(encoder.slot_count(), 0);
// //             bool has_x = false, has_y = false;
// //             for (int i = 0; i < curr_size; i++) {
// //                 auto& rec = unique_dataset[start_idx + i]; // 使用唯一组合
// //                 for (int k = 0; k < 3; k++) {
// //                     int t_x = (int)hash_result(rec.x, M, k); int off_x = (t_x - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE;
// //                     if (off_x == d) { mask_X[i]++; has_x = true; }
                    
// //                     int t_y = (int)hash_result(rec.y, M, k); int off_y = (t_y - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE;
// //                     if (off_y == d) { mask_Y[i]++; has_y = true; }
// //                 }
// //             }
// //             if (has_x) { Plaintext pt; encoder.encode(mask_X, pt); Ciphertext temp = rot_X[d]; local_eval.multiply_plain_inplace(temp, pt); local_eval.add_inplace(enc_S_x, temp); }
// //             if (has_y) { Plaintext pt; encoder.encode(mask_Y, pt); Ciphertext temp = rot_Y[d]; local_eval.multiply_plain_inplace(temp, pt); local_eval.add_inplace(enc_S_y, temp); }
// //         }

// //         vector<Ciphertext> all_terms;
// //         all_terms.push_back(enc_S_x); all_terms.push_back(enc_S_y);
// //         for(uint64_t j = 1; j <= 2; j++) {
// //             vector<uint64_t> vec_j(encoder.slot_count(), j); Plaintext pt_j; encoder.encode(vec_j, pt_j);
// //             Ciphertext temp_x, temp_y;
// //             local_eval.sub_plain(enc_S_x, pt_j, temp_x); local_eval.sub_plain(enc_S_y, pt_j, temp_y);
// //             all_terms.push_back(temp_x); all_terms.push_back(temp_y);
// //         }

// //         Ciphertext enc_L_n;
// //         local_eval.multiply_many(all_terms, rk, enc_L_n);

// //         #pragma omp critical
// //         {
// //             if (b == 0) {
// //                 cout << "\n[Noise Budget-4] 【核心瓶颈】经过 multiply_many 后的 enc_L_n 剩余噪声: " 
// //                      << debug_dec.invariant_noise_budget(enc_L_n) << " bits" << endl;
// //             }
// //             Plaintext pt_debug; vector<uint64_t> dec_Ln;
// //             debug_dec.decrypt(enc_L_n, pt_debug); encoder.decode(pt_debug, dec_Ln);
            
// //             if (b == 0) {
// //                 cout << "\n[DEBUG-核心探针] ======== Batch 0 抽样 ========" << endl;
// //                 for (int i = 0; i < min(5, curr_size); i++) {
// //                     cout << " => 组合: (x=" << unique_dataset[start_idx + i].x 
// //                          << ", y=" << unique_dataset[start_idx + i].y << ") | 原始重复数: " 
// //                          << unique_dataset[start_idx + i].o_list.size()
// //                          << " | 算出的 L_n: " << dec_Ln[i] << endl;
// //                 }
// //             }

// //             // 计算该批次能找回的总实际原始数据数
// //             int batch_hit_count = 0;
// //             for(int i = 0; i < curr_size; i++) {
// //                 if (dec_Ln[i] != 0) {
// //                     batch_hit_count += unique_dataset[start_idx + i].o_list.size();
// //                 }
// //             }
// //             global_fhe_hit_count += batch_hit_count;
// //         }

// //         // 1. 初始化当前 Batch 的密文 List
// //         vector<Ciphertext> batch_sketch_list(SKETCH_SIZE);
// //         for(int s = 0; s < SKETCH_SIZE; s++) {
// //             local_enc.encrypt_zero(batch_sketch_list[s]);
// //             local_eval.mod_switch_to_inplace(batch_sketch_list[s], enc_L_n.parms_id());
// //         }

// //         // 2. 提取与盲化（使用去重后的组合及其权重）
// //         for (int s = 0; s < SKETCH_SIZE; s++) {
// //             vector<uint64_t> mask(encoder.slot_count(), 0); 
// //             bool has_out = false;
// //             for (int i = 0; i < curr_size; i++) {
// //                 auto& rec = unique_dataset[start_idx + i];
                
// //                 // 核心逻辑：统计这个唯一的 (x, y) 下，有多少个原始 o 掉进了桶 s
// //                 int bucket_match_count = 0;
// //                 for (int o_val : rec.o_list) {
// //                     int o_i = (int)hash_result(o_val, SKETCH_SIZE, 0); 
// //                     if (o_i == s) bucket_match_count++;
// //                 }
                
// //                 // 如果命中，将 数量 * 盲化因子 填入 mask，一次乘法等于 N 次累加！
// //                 if (bucket_match_count > 0) { 
// //                     mask[i] = (bucket_match_count * server_blind_vec[s]) % plain_mod; 
// //                     has_out = true; 
// //                 }
// //             }
// //             if (has_out) {
// //                 Plaintext pt_m; encoder.encode(mask, pt_m); 
// //                 Ciphertext masked_L_n;
// //                 local_eval.multiply_plain(enc_L_n, pt_m, masked_L_n); 
// //                 local_eval.add_inplace(batch_sketch_list[s], masked_L_n);
// //             }
// //         }
        
// //         // 3. 安全落地压缩
// //         for(int s = 0; s < SKETCH_SIZE; s++) {
// //             local_eval.mod_switch_to_inplace(batch_sketch_list[s], context.last_context_data()->parms_id());
// //         }
        
// //         if (b == 0) cout << "[Server] 正在按 List 模式生成首个 Batch..." << endl;
        
// //         if (b == 0) batch_sketches = batch_sketch_list; 
// //         else {
// //             for(int s=0; s<SKETCH_SIZE; s++) local_eval.add_inplace(batch_sketches[s], batch_sketch_list[s]);
// //         }
// //     }

// //     cout << "\n================ 最终 FHE 汇总 ================" << endl;
// //     cout << " => FHE 在 L_n 中识别出的总命中数: " << global_fhe_hit_count  << endl;
    
// //     // 序列化并发送密文 List
// //     stringstream ss_out;
// //     uint64_t S_out = SKETCH_SIZE;
// //     ss_out.write(reinterpret_cast<const char*>(&S_out), sizeof(S_out));
    
// //     for (int s = 0; s < SKETCH_SIZE; s++) {
// //         stringstream stmp; 
// //         batch_sketches[s].save(stmp);
// //         string str = stmp.str();
// //         uint64_t len = str.size();
// //         ss_out.write(reinterpret_cast<const char*>(&len), sizeof(len));
// //         ss_out.write(str.c_str(), len);
// //     }

// //     cout << "[Server] 已打包 " << SKETCH_SIZE << " 个密文并发送!" << endl;
// //     send_data(socket, ss_out.str());
// //     return 0;
// // }








// // #include "common.h"
// // #include "bloomfilter.h"
// // #include "MurmurHash3.h"
// // #include <sstream>
// // #include <chrono>
// // #include <omp.h>
// // #include <vector>
// // #include <random>
// // #include <map>



// // using namespace std;
// // using namespace seal;

// // struct Record { int id; int x; int y; int o; };

// // // 新增：用于存储唯一组合的结构体
// // struct UniqueRecord { 
// //     int x; 
// //     int y; 
// //     vector<int> o_list; 
// // };

// // int main(int argc, char* argv[]) {
// //     if (argc != 2) { cerr << "Usage: ./server <listen_port>\n"; return 1; }

// //     boost::asio::io_context io_context; tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), stoi(argv[1])));
// //     tcp::socket socket(io_context); acceptor.accept(socket);

// //     SEALContext context = create_fhe_context(); BatchEncoder encoder(context);
// //     uint64_t plain_mod = context.first_context_data()->parms().plain_modulus().value();

// //     string recv_str = receive_data(socket); stringstream ss_in(recv_str);
// //     PublicKey pk; pk.load(context, ss_in); RelinKeys rk; rk.load(context, ss_in); GaloisKeys gal_keys; gal_keys.load(context, ss_in);
// //     SecretKey sk; sk.load(context, ss_in); Decryptor debug_dec(context, sk);

// //     int M; ss_in.read(reinterpret_cast<char*>(&M), sizeof(M));
// //     uint64_t size_x, size_y;
// //     ss_in.read(reinterpret_cast<char*>(&size_x), sizeof(size_x)); string str_x(size_x, '\0'); ss_in.read(&str_x[0], size_x); stringstream sx(str_x); Ciphertext enc_bf_x; enc_bf_x.load(context, sx);
// //     ss_in.read(reinterpret_cast<char*>(&size_y), sizeof(size_y)); string str_y(size_y, '\0'); ss_in.read(&str_y[0], size_y); stringstream sy(str_y); Ciphertext enc_bf_y; enc_bf_y.load(context, sy);

// //     cout << "\n[Noise Budget-1] 初始接收密文 enc_bf_x 剩余噪声: " 
// //          << debug_dec.invariant_noise_budget(enc_bf_x) << " bits" << endl;

// //     cout << "\n[DEBUG-Server-启动检查] 收到 Client 传来的 M (BloomFilter 大小): " << M << endl;

// //     cout << "[DEBUG-Server-哈希对齐自检] 数据 42 的 3 个 Hash 索引: ";
// //     for (int k = 0; k < 3; k++) {
// //         cout << (int)hash_result(42, M, k) << " ";
// //     }
// //     cout << "\n" << endl;

// //     vector<Record> dataset;
// //     int total_records = 1001;
// //     int target_hit_count = 50; 

// //     std::random_device rd;
// //     std::mt19937 gen(rd());
// //     std::uniform_int_distribution<> dist_x(0, 100);
// //     std::uniform_int_distribution<> dist_y(0, 100);
// //     std::uniform_int_distribution<> dist_x_miss(0, 1000);
// //     std::uniform_int_distribution<> dist_y_miss(0, 1000);
// //     std::uniform_int_distribution<> dist_o(10000, 99999);

// //     for (int i = 0; i < total_records; i++) {
// //         if (i < target_hit_count) {
// //             int x = dist_x(gen);
// //             int y = dist_y(gen);
// //             if (x > 100) x = 100; 
// //             if (y > 100) y = 100;
// //             dataset.push_back({i, x, y, (int)dist_o(gen)});
// //         } else {
// //             int x = dist_x_miss(gen);
// //             int y = dist_y_miss(gen);
// //             if (x <= 100 && y <= 100) x += 100; 
// //             dataset.push_back({i, x, y, (int)dist_o(gen)});
// //         }
// //     }
// //     cout << "[Server] 成功生成 " << dataset.size() << " 条模拟数据。" << endl;
    
// //     // ==========================================
// //     // 【核心优化】：明文域 (x, y) 组合去重预聚合
// //     // ==========================================
// //     map<pair<int, int>, vector<int>> unique_map;
// //     for (const auto& rec : dataset) {
// //         unique_map[{rec.x, rec.y}].push_back(rec.o);
// //     }
    
// //     vector<UniqueRecord> unique_dataset;
// //     for (const auto& kv : unique_map) {
// //         unique_dataset.push_back({kv.first.first, kv.first.second, kv.second});
// //     }
// //     int total_unique_records = unique_dataset.size();
    
// //     cout << "[Server] 数据去重优化: 从 " << total_records << " 条原始数据，提取出 " 
// //          << total_unique_records << " 个唯一的 (x, y) 组合以降低 FHE 计算开销。" << endl;

// //     // --- 全局盲化向量 ---
// //     vector<uint64_t> server_blind_vec(SKETCH_SIZE, 0ULL);
// //     std::uniform_int_distribution<uint64_t> dist_blind(1, 100);
// //     for(int s = 0; s < SKETCH_SIZE; s++) {
// //         server_blind_vec[s] = dist_blind(gen); 
// //     }
// //     cout << "[Server] 已生成内部盲化向量，准备进行掩码融合优化..." << endl;

// //     Evaluator evaluator_main(context); int ROW_SIZE = encoder.slot_count() / 2; 
    
// //     // 注意：接下来的所有 batch 拆分都基于去重后的 total_unique_records
// //     int num_batches = ceil((double)total_unique_records / ROW_SIZE); 

// //     vector<bool> need_rot_X(ROW_SIZE, false); vector<bool> need_rot_Y(ROW_SIZE, false);
// //     for (int b = 0; b < num_batches; b++) {
// //         int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_unique_records - start_idx);
// //         for (int i = 0; i < curr_size; i++) {
// //             auto& rec = unique_dataset[start_idx + i];
// //             for (int k = 0; k < 3; k++) {
// //                 int off_x = ((int)hash_result(rec.x, M, k) - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE; need_rot_X[off_x] = true;
// //                 int off_y = ((int)hash_result(rec.y, M, k) - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE; need_rot_Y[off_y] = true;
// //             }
// //         }
// //     }

// //     vector<Ciphertext> rot_X(ROW_SIZE), rot_Y(ROW_SIZE);
// //     #pragma omp parallel for
// //     for(int d = 0; d < ROW_SIZE; d++) {
// //         if(need_rot_X[d]) evaluator_main.rotate_rows(enc_bf_x, d, gal_keys, rot_X[d]);
// //         if(need_rot_Y[d]) evaluator_main.rotate_rows(enc_bf_y, d, gal_keys, rot_Y[d]);
// //     }

// //     vector<Ciphertext> batch_sketches(SKETCH_SIZE); // 现在是 List 模式，总外层结果为 List
// //     int global_fhe_hit_count = 0;

// //     for (int b = 0; b < num_batches; b++) {
// //         Evaluator local_eval(context); Encryptor local_enc(context, pk);
// //         int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_unique_records - start_idx);

// //         Ciphertext enc_S_x, enc_S_y; local_enc.encrypt_zero(enc_S_x); local_enc.encrypt_zero(enc_S_y);

// //         for (int d = 0; d < ROW_SIZE; d++) {
// //             vector<uint64_t> mask_X(encoder.slot_count(), 0); vector<uint64_t> mask_Y(encoder.slot_count(), 0);
// //             bool has_x = false, has_y = false;
// //             for (int i = 0; i < curr_size; i++) {
// //                 auto& rec = unique_dataset[start_idx + i]; // 使用唯一组合
// //                 for (int k = 0; k < 3; k++) {
// //                     int t_x = (int)hash_result(rec.x, M, k); int off_x = (t_x - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE;
// //                     if (off_x == d) { mask_X[i]++; has_x = true; }
                    
// //                     int t_y = (int)hash_result(rec.y, M, k); int off_y = (t_y - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE;
// //                     if (off_y == d) { mask_Y[i]++; has_y = true; }
// //                 }
// //             }
// //             if (has_x) { Plaintext pt; encoder.encode(mask_X, pt); Ciphertext temp = rot_X[d]; local_eval.multiply_plain_inplace(temp, pt); local_eval.add_inplace(enc_S_x, temp); }
// //             if (has_y) { Plaintext pt; encoder.encode(mask_Y, pt); Ciphertext temp = rot_Y[d]; local_eval.multiply_plain_inplace(temp, pt); local_eval.add_inplace(enc_S_y, temp); }
// //         }

// //         vector<Ciphertext> all_terms;
// //         all_terms.push_back(enc_S_x); all_terms.push_back(enc_S_y);
// //         for(uint64_t j = 1; j <= 2; j++) {
// //             vector<uint64_t> vec_j(encoder.slot_count(), j); Plaintext pt_j; encoder.encode(vec_j, pt_j);
// //             Ciphertext temp_x, temp_y;
// //             local_eval.sub_plain(enc_S_x, pt_j, temp_x); local_eval.sub_plain(enc_S_y, pt_j, temp_y);
// //             all_terms.push_back(temp_x); all_terms.push_back(temp_y);
// //         }

// //         Ciphertext enc_L_n;
// //         local_eval.multiply_many(all_terms, rk, enc_L_n);

// //         #pragma omp critical
// //         {
// //             if (b == 0) {
// //                 cout << "\n[Noise Budget-4] 【核心瓶颈】经过 multiply_many 后的 enc_L_n 剩余噪声: " 
// //                      << debug_dec.invariant_noise_budget(enc_L_n) << " bits" << endl;
// //             }
// //             Plaintext pt_debug; vector<uint64_t> dec_Ln;
// //             debug_dec.decrypt(enc_L_n, pt_debug); encoder.decode(pt_debug, dec_Ln);
            
// //             if (b == 0) {
// //                 cout << "\n[DEBUG-核心探针] ======== Batch 0 抽样 ========" << endl;
// //                 for (int i = 0; i < min(5, curr_size); i++) {
// //                     cout << " => 组合: (x=" << unique_dataset[start_idx + i].x 
// //                          << ", y=" << unique_dataset[start_idx + i].y << ") | 原始重复数: " 
// //                          << unique_dataset[start_idx + i].o_list.size()
// //                          << " | 算出的 L_n: " << dec_Ln[i] << endl;
// //                 }
// //             }

// //             // 计算该批次能找回的总实际原始数据数
// //             int batch_hit_count = 0;
// //             for(int i = 0; i < curr_size; i++) {
// //                 if (dec_Ln[i] != 0) {
// //                     batch_hit_count += unique_dataset[start_idx + i].o_list.size();
// //                 }
// //             }
// //             global_fhe_hit_count += batch_hit_count;
// //         }

// //         // 1. 初始化当前 Batch 的密文 List
// //         vector<Ciphertext> batch_sketch_list(SKETCH_SIZE);
// //         for(int s = 0; s < SKETCH_SIZE; s++) {
// //             local_enc.encrypt_zero(batch_sketch_list[s]);
// //             local_eval.mod_switch_to_inplace(batch_sketch_list[s], enc_L_n.parms_id());
// //         }

// //         // 2. 提取与盲化（使用去重后的组合及其权重）
// //         for (int s = 0; s < SKETCH_SIZE; s++) {
// //             vector<uint64_t> mask(encoder.slot_count(), 0); 
// //             bool has_out = false;
// //             for (int i = 0; i < curr_size; i++) {
// //                 auto& rec = unique_dataset[start_idx + i];
                
// //                 // 核心逻辑：统计这个唯一的 (x, y) 下，有多少个原始 o 掉进了桶 s
// //                 int bucket_match_count = 0;
// //                 for (int o_val : rec.o_list) {
// //                     int o_i = (int)hash_result(o_val, SKETCH_SIZE, 0); 
// //                     if (o_i == s) bucket_match_count++;
// //                 }
                
// //                 // 如果命中，将 数量 * 盲化因子 填入 mask，一次乘法等于 N 次累加！
// //                 if (bucket_match_count > 0) { 
// //                     mask[i] = (bucket_match_count * server_blind_vec[s]) % plain_mod; 
// //                     has_out = true; 
// //                 }
// //             }
// //             if (has_out) {
// //                 Plaintext pt_m; encoder.encode(mask, pt_m); 
// //                 Ciphertext masked_L_n;
// //                 local_eval.multiply_plain(enc_L_n, pt_m, masked_L_n); 
// //                 local_eval.add_inplace(batch_sketch_list[s], masked_L_n);
// //             }
// //         }
        
// //         // 3. 安全落地压缩
// //         for(int s = 0; s < SKETCH_SIZE; s++) {
// //             local_eval.mod_switch_to_inplace(batch_sketch_list[s], context.last_context_data()->parms_id());
// //         }
        
// //         if (b == 0) cout << "[Server] 正在按 List 模式生成首个 Batch..." << endl;
        
// //         if (b == 0) batch_sketches = batch_sketch_list; 
// //         else {
// //             for(int s=0; s<SKETCH_SIZE; s++) local_eval.add_inplace(batch_sketches[s], batch_sketch_list[s]);
// //         }
// //     }

// //     cout << "\n================ 最终 FHE 汇总 ================" << endl;
// //     cout << " => FHE 在 L_n 中识别出的总命中数: " << global_fhe_hit_count << endl;
    
// //     // 序列化并发送密文 List
// //     stringstream ss_out;
// //     uint64_t S_out = SKETCH_SIZE;
// //     ss_out.write(reinterpret_cast<const char*>(&S_out), sizeof(S_out));
    
// //     for (int s = 0; s < SKETCH_SIZE; s++) {
// //         stringstream stmp; 
// //         batch_sketches[s].save(stmp);
// //         string str = stmp.str();
// //         uint64_t len = str.size();
// //         ss_out.write(reinterpret_cast<const char*>(&len), sizeof(len));
// //         ss_out.write(str.c_str(), len);
// //     }

// //     cout << "[Server] 已打包 " << SKETCH_SIZE << " 个密文并发送!" << endl;
// //     send_data(socket, ss_out.str());
// //     return 0;
// // }








// // #include "common.h"
// // #include "bloomfilter.h"
// // #include "MurmurHash3.h"
// // #include <sstream>
// // #include <chrono>
// // #include <omp.h>
// // #include <vector>
// // #include <random>

// // using namespace std;
// // using namespace seal;

// // struct Record { int id; int x; int y; int o; };

// // int main(int argc, char* argv[]) {
// //     if (argc != 2) { cerr << "Usage: ./server <listen_port>\n"; return 1; }

// //     boost::asio::io_context io_context; tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), stoi(argv[1])));
// //     tcp::socket socket(io_context); acceptor.accept(socket);

// //     SEALContext context = create_fhe_context(); BatchEncoder encoder(context);
// //     uint64_t plain_mod = context.first_context_data()->parms().plain_modulus().value();

// //     string recv_str = receive_data(socket); stringstream ss_in(recv_str);
// //     PublicKey pk; pk.load(context, ss_in); RelinKeys rk; rk.load(context, ss_in); GaloisKeys gal_keys; gal_keys.load(context, ss_in);
// //     SecretKey sk; sk.load(context, ss_in); Decryptor debug_dec(context, sk);

// //     int M; ss_in.read(reinterpret_cast<char*>(&M), sizeof(M));
// //     uint64_t size_x, size_y;
// //     ss_in.read(reinterpret_cast<char*>(&size_x), sizeof(size_x)); string str_x(size_x, '\0'); ss_in.read(&str_x[0], size_x); stringstream sx(str_x); Ciphertext enc_bf_x; enc_bf_x.load(context, sx);
// //     ss_in.read(reinterpret_cast<char*>(&size_y), sizeof(size_y)); string str_y(size_y, '\0'); ss_in.read(&str_y[0], size_y); stringstream sy(str_y); Ciphertext enc_bf_y; enc_bf_y.load(context, sy);

// //     // ==========================================
// //     // 【注入点 1】：监控初始接收的密文噪声
// //     // ==========================================
// //     cout << "\n[Noise Budget-1] 初始接收密文 enc_bf_x 剩余噪声: " 
// //          << debug_dec.invariant_noise_budget(enc_bf_x) << " bits" << endl;

// //     cout << "\n[DEBUG-Server-启动检查] 收到 Client 传来的 M (BloomFilter 大小): " << M << endl;

// //     // 【极其重要的哈希探针验证】：打印 42 的 7 个哈希值，看看跟 Client 算得一不一样！
// //     cout << "[DEBUG-Server-哈希对齐自检] 数据 42 的 3 个 Hash 索引: ";
// //     for (int k = 0; k < 3; k++) {
// //         cout << (int)hash_result(42, M, k) << " ";
// //     }
// //     cout << "\n" << endl;

// //     vector<Record> dataset;
// //     int total_records = 1001;
// //     int target_hit_count = 50; 

// //     std::random_device rd;
// //     std::mt19937 gen(rd());
// //     std::uniform_int_distribution<> dist_x(0, 100);
// //     std::uniform_int_distribution<> dist_y(0, 100);
// //     std::uniform_int_distribution<> dist_x_miss(0, 1000);
// //     std::uniform_int_distribution<> dist_y_miss(0, 1000);
// //     std::uniform_int_distribution<> dist_o(10000, 99999);

// //     for (int i = 0; i < total_records; i++) {
// //         if (i < target_hit_count) {
// //             // 生成必中数据 (确保在 0~100 的 client 插入范围内)
// //             int x = dist_x(gen);
// //             int y = dist_y(gen);
// //             // 确保不生成超出范围的随机数
// //             if (x > 100) x = 100; 
// //             if (y > 100) y = 100;
// //             dataset.push_back({i, x, y, (int)dist_o(gen)});
// //         } else {
// //             int x = dist_x_miss(gen);
// //             int y = dist_y_miss(gen);
// //             if (x <= 100 && y <= 100) x += 100; 
// //             dataset.push_back({i, x, y, (int)dist_o(gen)});
// //         }
// //     }
// //     cout << "[Server] 成功生成 " << dataset.size() << " 条模拟数据。" << endl;
    

// //     // --- 【新增：生成全局盲化向量】 ---
// //     // 提前生成好针对每个 Sketch 桶的随机乘数，用于后续掩码融合
// //     vector<uint64_t> server_blind_vec(SKETCH_SIZE, 0ULL);
// //     std::uniform_int_distribution<uint64_t> dist_blind(1, 100);
// //     for(int s = 0; s < SKETCH_SIZE; s++) {
// //         server_blind_vec[s] = dist_blind(gen); // 复用上方已有的随机数生成器 gen
// //     }
// //     cout << "[Server] 已生成内部盲化向量，准备进行掩码融合优化..." << endl;

// //     Evaluator evaluator_main(context); int ROW_SIZE = encoder.slot_count() / 2; 
// //     int num_batches = ceil((double)total_records / ROW_SIZE); 

// //     vector<bool> need_rot_X(ROW_SIZE, false); vector<bool> need_rot_Y(ROW_SIZE, false);
// //     for (int b = 0; b < num_batches; b++) {
// //         int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_records - start_idx);
// //         for (int i = 0; i < curr_size; i++) {
// //             auto& rec = dataset[start_idx + i];
// //             for (int k = 0; k < 3; k++) {
// //                 // 【核心对齐】：严格使用 Client 传来的 M 作为哈希长度！
// //                 int off_x = ((int)hash_result(rec.x, M, k) - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE; need_rot_X[off_x] = true;
// //                 int off_y = ((int)hash_result(rec.y, M, k) - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE; need_rot_Y[off_y] = true;
// //             }
// //         }
// //     }

// //     vector<Ciphertext> rot_X(ROW_SIZE), rot_Y(ROW_SIZE);
// //     #pragma omp parallel for
// //     for(int d = 0; d < ROW_SIZE; d++) {
// //         if(need_rot_X[d]) evaluator_main.rotate_rows(enc_bf_x, d, gal_keys, rot_X[d]);
// //         if(need_rot_Y[d]) evaluator_main.rotate_rows(enc_bf_y, d, gal_keys, rot_Y[d]);
// //     }

// //     // ==========================================
// //     // 【注入点 2】：监控旋转后的噪声消耗
// //     // ==========================================
// //     for(int d = 0; d < ROW_SIZE; d++) {
// //         if(need_rot_X[d]) {
// //             cout << "[Noise Budget-2] 经过 rotate_rows 后的 rot_X[" << d << "] 剩余噪声: " 
// //                  << debug_dec.invariant_noise_budget(rot_X[d]) << " bits" << endl;
// //             break;
// //         }
// //     }

// //     vector<Ciphertext> batch_sketches(num_batches);
// //     int global_fhe_hit_count = 0;

// //     for (int b = 0; b < num_batches; b++) {
// //         Evaluator local_eval(context); Encryptor local_enc(context, pk);
// //         int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_records - start_idx);

// //         Ciphertext enc_S_x, enc_S_y; local_enc.encrypt_zero(enc_S_x); local_enc.encrypt_zero(enc_S_y);

// //         for (int d = 0; d < ROW_SIZE; d++) {
// //             vector<uint64_t> mask_X(encoder.slot_count(), 0); vector<uint64_t> mask_Y(encoder.slot_count(), 0);
// //             bool has_x = false, has_y = false;
// //             for (int i = 0; i < curr_size; i++) {
// //                 auto& rec = dataset[start_idx + i];
// //                 for (int k = 0; k < 3; k++) {
// //                     int t_x = (int)hash_result(rec.x, M, k); int off_x = (t_x - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE;
// //                     if (off_x == d) { mask_X[i]++; has_x = true; }
                    
// //                     int t_y = (int)hash_result(rec.y, M, k); int off_y = (t_y - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE;
// //                     if (off_y == d) { mask_Y[i]++; has_y = true; }
// //                 }
// //             }
// //             if (has_x) { Plaintext pt; encoder.encode(mask_X, pt); Ciphertext temp = rot_X[d]; local_eval.multiply_plain_inplace(temp, pt); local_eval.add_inplace(enc_S_x, temp); }
// //             if (has_y) { Plaintext pt; encoder.encode(mask_Y, pt); Ciphertext temp = rot_Y[d]; local_eval.multiply_plain_inplace(temp, pt); local_eval.add_inplace(enc_S_y, temp); }
// //         }

// //         // ==========================================
// //         // 【注入点 3】：监控密文-明文乘法及累加后的噪声
// //         // ==========================================
// //         if (b == 0) {
// //             cout << "\n[Noise Budget-3] 经过明文乘法与累加后的 enc_S_x 剩余噪声: " 
// //                  << debug_dec.invariant_noise_budget(enc_S_x) << " bits" << endl;
// //         }
        
// //         vector<Ciphertext> all_terms;
// //         all_terms.push_back(enc_S_x); all_terms.push_back(enc_S_y);
// //         for(uint64_t j = 1; j <= 2; j++) {
// //             vector<uint64_t> vec_j(encoder.slot_count(), j); Plaintext pt_j; encoder.encode(vec_j, pt_j);
// //             Ciphertext temp_x, temp_y;
// //             local_eval.sub_plain(enc_S_x, pt_j, temp_x); local_eval.sub_plain(enc_S_y, pt_j, temp_y);
// //             all_terms.push_back(temp_x); all_terms.push_back(temp_y);
// //         }

// //         Ciphertext enc_L_n;
// //         local_eval.multiply_many(all_terms, rk, enc_L_n);

// //         #pragma omp critical
// //         {
// //             // ==========================================
// //             // 【注入点 4】：监控灾难级消耗区（14次连乘之后）
// //             // ==========================================
// //             if (b == 0) {
// //                 cout << "[Noise Budget-4] 【核心瓶颈】经过 multiply_many (14密文连乘) 后的 enc_L_n 剩余噪声: " 
// //                      << debug_dec.invariant_noise_budget(enc_L_n) << " bits" << endl;
// //             }
// //             Plaintext pt_debug; vector<uint64_t> dec_Sx, dec_Sy, dec_Ln;
// //             debug_dec.decrypt(enc_S_x, pt_debug); encoder.decode(pt_debug, dec_Sx);
// //             debug_dec.decrypt(enc_S_y, pt_debug); encoder.decode(pt_debug, dec_Sy);
// //             debug_dec.decrypt(enc_L_n, pt_debug); encoder.decode(pt_debug, dec_Ln);
            
// //             if (b == 0) {
// //                 cout << "\n[DEBUG-核心探针] ======== Batch 0 命中数据抽样 ========" << endl;
// //                 for (int i = 0; i < 5; i++) {
// //                     cout << " => 数据 ID: " << dataset[start_idx + i].id 
// //                          << " (x=" << dataset[start_idx + i].x << ", y=" << dataset[start_idx + i].y << ")"
// //                          << " | 算出 S_x: " << dec_Sx[i] << ", S_y: " << dec_Sy[i] 
// //                          << " | L_n: " << dec_Ln[i] << endl;
// //                 }
                
// //                 cout << "\n[DEBUG-核心探针] ======== Batch 0 不中数据抽样 ========" << endl;
// //                 for (int i = 50; i < 53; i++) {
// //                     cout << " => 数据 ID: " << dataset[start_idx + i].id 
// //                          << " (x=" << dataset[start_idx + i].x << ", y=" << dataset[start_idx + i].y << ")"
// //                          << " | 算出 S_x: " << dec_Sx[i] << ", S_y: " << dec_Sy[i] 
// //                          << " | L_n: " << dec_Ln[i] << endl;
// //                 }
// //             }

// //             int batch_hit_count = 0;
// //             for(int i = 0; i < curr_size; i++) {
// //                 if (dec_Ln[i] != 0) batch_hit_count++;
// //             }
// //             global_fhe_hit_count += batch_hit_count;
// //         }

// //         // 1. 初始化当前 Batch 的密文 List，注意保持与 enc_L_n 同等的安全层级
// //         vector<Ciphertext> batch_sketch_list(SKETCH_SIZE);
// //         for(int s = 0; s < SKETCH_SIZE; s++) {
// //             local_enc.encrypt_zero(batch_sketch_list[s]);
// //             local_eval.mod_switch_to_inplace(batch_sketch_list[s], enc_L_n.parms_id());
// //         }

// //         // 2. 提取与盲化（此时 enc_L_n 模数 q 够大，完全吃得消明文乘法的噪声增长）
// //         for (int s = 0; s < SKETCH_SIZE; s++) {
// //             vector<uint64_t> mask(encoder.slot_count(), 0); 
// //             bool has_out = false;
// //             for (int i = 0; i < curr_size; i++) {
// //                 int o_i = (int)hash_result(dataset[start_idx + i].o, SKETCH_SIZE, 0); 
// //                 if (o_i == s) { 
// //                     mask[i] = server_blind_vec[s]; // 融合盲化乘子
// //                     has_out = true; 
// //                 }
// //             }
// //             if (has_out) {
// //                 Plaintext pt_m; encoder.encode(mask, pt_m); 
// //                 Ciphertext masked_L_n;
// //                 local_eval.multiply_plain(enc_L_n, pt_m, masked_L_n); 
// //                 local_eval.add_inplace(batch_sketch_list[s], masked_L_n);
// //             }
// //         }
        
// //         // 3. 【核心修复】：在计算全部安全落地后，再统一降级压缩体积
// //         for(int s = 0; s < SKETCH_SIZE; s++) {
// //             local_eval.mod_switch_to_inplace(batch_sketch_list[s], context.last_context_data()->parms_id());
// //         }
        
// //         if (b == 0) cout << "[Server] 正在按 List 模式生成首个 Batch..." << endl;
        
// //         if (b == 0) batch_sketches = batch_sketch_list; 
// //         else {
// //             for(int s=0; s<SKETCH_SIZE; s++) local_eval.add_inplace(batch_sketches[s], batch_sketch_list[s]);
// //         }
// //     }

// //     cout << "\n================ 最终 FHE 汇总 ================" << endl;
// //     cout << " => FHE 在 L_n 中识别出的总命中数: " << global_fhe_hit_count << " (预期: 50)" << endl;
    
// //     // 序列化并发送密文 List
// //     stringstream ss_out;
// //     uint64_t S_out = SKETCH_SIZE;
// //     ss_out.write(reinterpret_cast<const char*>(&S_out), sizeof(S_out));
    
// //     for (int s = 0; s < SKETCH_SIZE; s++) {
// //         stringstream stmp; 
// //         batch_sketches[s].save(stmp);
// //         string str = stmp.str();
// //         uint64_t len = str.size();
// //         ss_out.write(reinterpret_cast<const char*>(&len), sizeof(len));
// //         ss_out.write(str.c_str(), len);
// //     }

// //     cout << "[Server] 已打包 " << SKETCH_SIZE << " 个密文并发送!" << endl;
// //     send_data(socket, ss_out.str());
// //     return 0;
// // }



// // #include "common.h"
// // #include "bloomfilter.h"
// // #include "MurmurHash3.h"
// // #include <sstream>
// // #include <chrono>
// // #include <omp.h>
// // #include <vector>
// // #include <random>

// // using namespace std;
// // using namespace seal;

// // struct Record { int id; int x; int y; int o; };

// // int main(int argc, char* argv[]) {
// //     if (argc != 2) { cerr << "Usage: ./server <listen_port>\n"; return 1; }

// //     boost::asio::io_context io_context; tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), stoi(argv[1])));
// //     tcp::socket socket(io_context); acceptor.accept(socket);

// //     SEALContext context = create_fhe_context(); BatchEncoder encoder(context);
// //     uint64_t plain_mod = context.first_context_data()->parms().plain_modulus().value();

// //     string recv_str = receive_data(socket); stringstream ss_in(recv_str);
// //     PublicKey pk; pk.load(context, ss_in); RelinKeys rk; rk.load(context, ss_in); GaloisKeys gal_keys; gal_keys.load(context, ss_in);
// //     SecretKey sk; sk.load(context, ss_in); Decryptor debug_dec(context, sk);

// //     int M; ss_in.read(reinterpret_cast<char*>(&M), sizeof(M));
// //     uint64_t size_x, size_y;
// //     ss_in.read(reinterpret_cast<char*>(&size_x), sizeof(size_x)); string str_x(size_x, '\0'); ss_in.read(&str_x[0], size_x); stringstream sx(str_x); Ciphertext enc_bf_x; enc_bf_x.load(context, sx);
// //     ss_in.read(reinterpret_cast<char*>(&size_y), sizeof(size_y)); string str_y(size_y, '\0'); ss_in.read(&str_y[0], size_y); stringstream sy(str_y); Ciphertext enc_bf_y; enc_bf_y.load(context, sy);

// //     // ==========================================
// //     // 【注入点 1】：监控初始接收的密文噪声
// //     // ==========================================
// //     cout << "\n[Noise Budget-1] 初始接收密文 enc_bf_x 剩余噪声: " 
// //          << debug_dec.invariant_noise_budget(enc_bf_x) << " bits" << endl;

// //     cout << "\n[DEBUG-Server-启动检查] 收到 Client 传来的 M (BloomFilter 大小): " << M << endl;

// //     // 【极其重要的哈希探针验证】：打印 42 的 7 个哈希值，看看跟 Client 算得一不一样！
// //     cout << "[DEBUG-Server-哈希对齐自检] 数据 42 的 3 个 Hash 索引: ";
// //     for (int k = 0; k < 3; k++) {
// //         cout << (int)hash_result(42, M, k) << " ";
// //     }
// //     cout << "\n" << endl;

// //     vector<Record> dataset;
// //     int total_records = 1001;
// //     int target_hit_count = 50; 

// //     std::random_device rd;
// //     std::mt19937 gen(rd());
// //     std::uniform_int_distribution<> dist_x(0, 100);
// //     std::uniform_int_distribution<> dist_y(0, 100);
// //     std::uniform_int_distribution<> dist_x_miss(0, 1000);
// //     std::uniform_int_distribution<> dist_y_miss(0, 1000);
// //     std::uniform_int_distribution<> dist_o(10000, 99999);

// //     for (int i = 0; i < total_records; i++) {
// //         if (i < target_hit_count) {
// //             // 生成必中数据 (确保在 0~100 的 client 插入范围内)
// //             int x = dist_x(gen);
// //             int y = dist_y(gen);
// //             // 确保不生成超出范围的随机数
// //             if (x > 100) x = 100; 
// //             if (y > 100) y = 100;
// //             dataset.push_back({i, x, y, (int)dist_o(gen)});
// //         } else {
// //             int x = dist_x_miss(gen);
// //             int y = dist_y_miss(gen);
// //             if (x <= 100 && y <= 100) x += 100; 
// //             dataset.push_back({i, x, y, (int)dist_o(gen)});
// //         }
// //     }
// //     cout << "[Server] 成功生成 " << dataset.size() << " 条模拟数据。" << endl;
    

// //     // --- 【新增：生成全局盲化向量】 ---
// //     // 提前生成好针对每个 Sketch 桶的随机乘数，用于后续掩码融合
// //     vector<uint64_t> server_blind_vec(SKETCH_SIZE, 0ULL);
// //     std::uniform_int_distribution<uint64_t> dist_blind(1, 100);
// //     for(int s = 0; s < SKETCH_SIZE; s++) {
// //         server_blind_vec[s] = dist_blind(gen); // 复用上方已有的随机数生成器 gen
// //     }
// //     cout << "[Server] 已生成内部盲化向量，准备进行掩码融合优化..." << endl;

// //     Evaluator evaluator_main(context); int ROW_SIZE = encoder.slot_count() / 2; 
// //     int num_batches = ceil((double)total_records / ROW_SIZE); 

// //     vector<bool> need_rot_X(ROW_SIZE, false); vector<bool> need_rot_Y(ROW_SIZE, false);
// //     for (int b = 0; b < num_batches; b++) {
// //         int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_records - start_idx);
// //         for (int i = 0; i < curr_size; i++) {
// //             auto& rec = dataset[start_idx + i];
// //             for (int k = 0; k < 3; k++) {
// //                 // 【核心对齐】：严格使用 Client 传来的 M 作为哈希长度！
// //                 int off_x = ((int)hash_result(rec.x, M, k) - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE; need_rot_X[off_x] = true;
// //                 int off_y = ((int)hash_result(rec.y, M, k) - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE; need_rot_Y[off_y] = true;
// //             }
// //         }
// //     }

// //     vector<Ciphertext> rot_X(ROW_SIZE), rot_Y(ROW_SIZE);
// //     #pragma omp parallel for
// //     for(int d = 0; d < ROW_SIZE; d++) {
// //         if(need_rot_X[d]) evaluator_main.rotate_rows(enc_bf_x, d, gal_keys, rot_X[d]);
// //         if(need_rot_Y[d]) evaluator_main.rotate_rows(enc_bf_y, d, gal_keys, rot_Y[d]);
// //     }

// //     // ==========================================
// //     // 【注入点 2】：监控旋转后的噪声消耗
// //     // ==========================================
// //     for(int d = 0; d < ROW_SIZE; d++) {
// //         if(need_rot_X[d]) {
// //             cout << "[Noise Budget-2] 经过 rotate_rows 后的 rot_X[" << d << "] 剩余噪声: " 
// //                  << debug_dec.invariant_noise_budget(rot_X[d]) << " bits" << endl;
// //             break;
// //         }
// //     }

// //     vector<Ciphertext> batch_sketches(num_batches);
// //     int global_fhe_hit_count = 0;

// //     for (int b = 0; b < num_batches; b++) {
// //         Evaluator local_eval(context); Encryptor local_enc(context, pk);
// //         int start_idx = b * ROW_SIZE; int curr_size = min(ROW_SIZE, total_records - start_idx);

// //         Ciphertext enc_S_x, enc_S_y; local_enc.encrypt_zero(enc_S_x); local_enc.encrypt_zero(enc_S_y);

// //         for (int d = 0; d < ROW_SIZE; d++) {
// //             vector<uint64_t> mask_X(encoder.slot_count(), 0); vector<uint64_t> mask_Y(encoder.slot_count(), 0);
// //             bool has_x = false, has_y = false;
// //             for (int i = 0; i < curr_size; i++) {
// //                 auto& rec = dataset[start_idx + i];
// //                 for (int k = 0; k < 3; k++) {
// //                     int t_x = (int)hash_result(rec.x, M, k); int off_x = (t_x - i) % ROW_SIZE; if (off_x < 0) off_x += ROW_SIZE;
// //                     if (off_x == d) { mask_X[i]++; has_x = true; }
                    
// //                     int t_y = (int)hash_result(rec.y, M, k); int off_y = (t_y - i) % ROW_SIZE; if (off_y < 0) off_y += ROW_SIZE;
// //                     if (off_y == d) { mask_Y[i]++; has_y = true; }
// //                 }
// //             }
// //             if (has_x) { Plaintext pt; encoder.encode(mask_X, pt); Ciphertext temp = rot_X[d]; local_eval.multiply_plain_inplace(temp, pt); local_eval.add_inplace(enc_S_x, temp); }
// //             if (has_y) { Plaintext pt; encoder.encode(mask_Y, pt); Ciphertext temp = rot_Y[d]; local_eval.multiply_plain_inplace(temp, pt); local_eval.add_inplace(enc_S_y, temp); }
// //         }

// //         // ==========================================
// //         // 【注入点 3】：监控密文-明文乘法及累加后的噪声
// //         // ==========================================
// //         if (b == 0) {
// //             cout << "\n[Noise Budget-3] 经过明文乘法与累加后的 enc_S_x 剩余噪声: " 
// //                  << debug_dec.invariant_noise_budget(enc_S_x) << " bits" << endl;
// //         }
        
// //         vector<Ciphertext> all_terms;
// //         all_terms.push_back(enc_S_x); all_terms.push_back(enc_S_y);
// //         for(uint64_t j = 1; j <= 2; j++) {
// //             vector<uint64_t> vec_j(encoder.slot_count(), j); Plaintext pt_j; encoder.encode(vec_j, pt_j);
// //             Ciphertext temp_x, temp_y;
// //             local_eval.sub_plain(enc_S_x, pt_j, temp_x); local_eval.sub_plain(enc_S_y, pt_j, temp_y);
// //             all_terms.push_back(temp_x); all_terms.push_back(temp_y);
// //         }

// //         Ciphertext enc_L_n;
// //         local_eval.multiply_many(all_terms, rk, enc_L_n);

// //         #pragma omp critical
// //         {
// //             // ==========================================
// //             // 【注入点 4】：监控灾难级消耗区（14次连乘之后）
// //             // ==========================================
// //             if (b == 0) {
// //                 cout << "[Noise Budget-4] 【核心瓶颈】经过 multiply_many (14密文连乘) 后的 enc_L_n 剩余噪声: " 
// //                      << debug_dec.invariant_noise_budget(enc_L_n) << " bits" << endl;
// //             }
// //             Plaintext pt_debug; vector<uint64_t> dec_Sx, dec_Sy, dec_Ln;
// //             debug_dec.decrypt(enc_S_x, pt_debug); encoder.decode(pt_debug, dec_Sx);
// //             debug_dec.decrypt(enc_S_y, pt_debug); encoder.decode(pt_debug, dec_Sy);
// //             debug_dec.decrypt(enc_L_n, pt_debug); encoder.decode(pt_debug, dec_Ln);
            
// //             if (b == 0) {
// //                 cout << "\n[DEBUG-核心探针] ======== Batch 0 命中数据抽样 ========" << endl;
// //                 for (int i = 0; i < 5; i++) {
// //                     cout << " => 数据 ID: " << dataset[start_idx + i].id 
// //                          << " (x=" << dataset[start_idx + i].x << ", y=" << dataset[start_idx + i].y << ")"
// //                          << " | 算出 S_x: " << dec_Sx[i] << ", S_y: " << dec_Sy[i] 
// //                          << " | L_n: " << dec_Ln[i] << endl;
// //                 }
                
// //                 cout << "\n[DEBUG-核心探针] ======== Batch 0 不中数据抽样 ========" << endl;
// //                 for (int i = 50; i < 53; i++) {
// //                     cout << " => 数据 ID: " << dataset[start_idx + i].id 
// //                          << " (x=" << dataset[start_idx + i].x << ", y=" << dataset[start_idx + i].y << ")"
// //                          << " | 算出 S_x: " << dec_Sx[i] << ", S_y: " << dec_Sy[i] 
// //                          << " | L_n: " << dec_Ln[i] << endl;
// //                 }
// //             }

// //             int batch_hit_count = 0;
// //             for(int i = 0; i < curr_size; i++) {
// //                 if (dec_Ln[i] != 0) batch_hit_count++;
// //             }
// //             global_fhe_hit_count += batch_hit_count;
// //         }

// //         Ciphertext enc_sketch_b; local_enc.encrypt_zero(enc_sketch_b); 
// //         local_eval.mod_switch_to_inplace(enc_sketch_b, enc_L_n.parms_id());
        
// //         for (int d = 0; d < ROW_SIZE; d++) {
// //             vector<uint64_t> mask(encoder.slot_count(), 0); bool has_out = false;
// //             for (int i = 0; i < curr_size; i++) {
// //                 int o_i = (int)hash_result(dataset[start_idx + i].o, SKETCH_SIZE, 0); 
// //                 int d_out = (i - o_i) % ROW_SIZE; if (d_out < 0) d_out += ROW_SIZE;
// //                 // 【核心优化】：将原本的 1 替换为对应桶的随机盲化因子
// //                 if (d_out == d) { mask[o_i] = server_blind_vec[o_i]; has_out = true; }
// //             }
// //             if (has_out) {
// //                 Plaintext pt_m; encoder.encode(mask, pt_m); Ciphertext rot;
// //                 local_eval.rotate_rows(enc_L_n, d, gal_keys, rot); 
// //                 local_eval.multiply_plain_inplace(rot, pt_m); local_eval.add_inplace(enc_sketch_b, rot);
// //             }
// //         }




// //         // ==========================================
// //         // 【注入点 5】：监控最终 Sketch 输出前的噪声
// //         // ==========================================
// //         if (b == 0) {
// //             cout << "\n[Noise Budget-5] 最终准备输出的单 Batch 结果 enc_sketch_b 剩余噪声: " 
// //                  << debug_dec.invariant_noise_budget(enc_sketch_b) << " bits\n" << endl;
// //         }
// //         batch_sketches[b] = enc_sketch_b;
// //     }

// //     cout << "\n================ 最终 FHE 解密汇总 ================" << endl;
// //     cout << " => FHE 在 L_n 中识别出的总命中数: " << global_fhe_hit_count << " (预期: 50)" << endl;
// //     cout << "=====================================================\n" << endl;

// //     Ciphertext global_sketch = batch_sketches[0];
// //     for (int b = 1; b < num_batches; b++) { evaluator_main.add_inplace(global_sketch, batch_sketches[b]); }

// //     stringstream ss_out; global_sketch.save(ss_out); send_data(socket, ss_out.str());
// //     return 0;
// // }