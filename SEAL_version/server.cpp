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
        std::cerr << "[Error] " << dataset_path << std::endl;
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
    

    int target_size = static_cast<int>(all_csv_data.size() * P);
    if (target_size == 0 && !all_csv_data.empty()) { target_size = 1; }

    std::shuffle(all_csv_data.begin(), all_csv_data.end(), gen);

    for (int i = 0; i < target_size; i++) {
        dataset.push_back({i, all_csv_data[i].x, all_csv_data[i].y, all_csv_data[i].original_row});
    }

    
    
    

    boost::asio::io_context io_context; tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), stoi(argv[1])));
    tcp::socket socket(io_context); acceptor.accept(socket);

    SEALContext context = create_fhe_context(); BatchEncoder encoder(context);
    uint64_t plain_mod = context.first_context_data()->parms().plain_modulus().value();

    string recv_str = receive_data(socket); 
    
    
    stringstream ss_in(recv_str);

    
    

    
    uint32_t session_seed;
    ss_in.read(reinterpret_cast<char*>(&session_seed), sizeof(session_seed));
    

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

    

    
    
    vector<int> active_rot_X;
    vector<int> active_rot_Y;
    for(int d = 0; d < ROW_SIZE; d++) {
        if(need_rot_X[d]) active_rot_X.push_back(d);
        if(need_rot_Y[d]) active_rot_Y.push_back(d);
    }

    

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

        
        int SHIFT_BITS = 9; 
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

    
    
    
    
    
    
    

    seal::compr_mode_type compr_mode = seal::compr_mode_type::zstd;

    
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

    
    
    
    send_data(socket, final_payload);
    
    
    return 0;
}
