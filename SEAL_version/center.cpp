#include "common.h"
#include <sstream>
#include <vector>
#include <random>
#include <algorithm>

using namespace std;

int main(int argc, char* argv[]) {
    if (argc != 4) { cerr << "Usage: ./center <listen_port> <server_ip> <server_port>\n"; return 1; }

    boost::asio::io_context io_context;
    tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), stoi(argv[1])));
    cout << "[Center] 启动，等待 Client 连接端口 " << argv[1] << "..." << endl;
    tcp::socket client_socket(io_context); acceptor.accept(client_socket);

    tcp::socket server_socket(io_context); tcp::resolver resolver(io_context);
    boost::asio::connect(server_socket, resolver.resolve(argv[2], argv[3]));

    // 阶段1 接收 Client 密文并注入同步随机种子，透传给 Server
    auto start = std::chrono::high_resolution_clock::now();
    string client_req = receive_data(client_socket);
    cout << "[Comm] Center 接收到 Client 请求数据量: " << client_req.size() / 1024.0 / 1024.0 << " MB" << endl;

    // 【核心】生成 Query 级别的同步随机种子
    uint32_t session_seed = std::random_device{}();
    string new_req;
    new_req.append(reinterpret_cast<const char*>(&session_seed), sizeof(session_seed));
    new_req.append(client_req);

    send_data(server_socket, new_req);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration = end - start;
    std::cout << "Phase 1: the time is " << duration.count()/1000 << " s\n";

    cout << "[Center] 等待 Server 计算完成..." << endl;
    string server_res = receive_data(server_socket);
    cout << "[Comm] Center 接收到 Server 结果数据量: " << server_res.size() / 1024.0 / 1024.0 << " MB" << endl;

    // ==========================================
    // 阶段2：零拷贝读取与解析 (Zero-Copy Parsing)
    // ==========================================
    start = std::chrono::high_resolution_clock::now();
    cout << "[Center] 收到密文块 List，准备进行宏观混淆洗牌 (Shuffle)..." << endl;
    
    const char* ptr = server_res.data();
    uint64_t S;
    memcpy(&S, ptr, sizeof(S));
    ptr += sizeof(S);

    struct SketchBlock {
        const char* data_ptr;
        uint64_t len;
    };
    vector<SketchBlock> sketch_blocks(S);
    
    uint64_t total_payload_size = sizeof(S);
    for(uint64_t s = 0; s < S; s++) {
        uint64_t len;
        memcpy(&len, ptr, sizeof(len));
        
        sketch_blocks[s].len = len;
        sketch_blocks[s].data_ptr = ptr + sizeof(len);
        
        ptr += sizeof(len) + len;
        total_payload_size += sizeof(len) + len; 
    }

    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "Phase 2 (Zero-Copy Parse): the time is " << duration.count()/1000.0 << " s\n";

    // ==========================================
    // 阶段3：指针混淆洗牌 (Pointer Shuffle)
    // ==========================================
    start = std::chrono::high_resolution_clock::now();

    std::random_device rd_main;
    std::mt19937_64 gen_main(rd_main());
    std::shuffle(sketch_blocks.begin(), sketch_blocks.end(), gen_main);

    end = std::chrono::high_resolution_clock::now();
    duration = end - start;
    std::cout << "Phase 3 (Pointer Shuffle): the time is " << duration.count()/1000.0 << " s\n";

    // ==========================================
    // 阶段4：一次性组装并发包
    // ==========================================
    auto start_time = std::chrono::high_resolution_clock::now();
    
    string final_payload;
    final_payload.reserve(total_payload_size);
    
    final_payload.append(reinterpret_cast<const char*>(&S), sizeof(S));
    for(uint64_t s = 0; s < S; s++) {
        uint64_t len = sketch_blocks[s].len;
        final_payload.append(reinterpret_cast<const char*>(&len), sizeof(len));
        final_payload.append(sketch_blocks[s].data_ptr, len);
    }
    
    cout << "[Comm] Center 发送给 Client 的宏观混淆数据量: " << final_payload.size() / 1024.0 / 1024.0 << " MB" << endl;
    cout << "[Center] 洗牌完毕，发送连续内存块给 Client..." << endl;
    send_data(client_socket, final_payload);

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration_t = end_time - start_time;
    std::cout << "The time is " << duration_t.count()/1000.0 << " s\n";

    return 0;
}






// #include "common.h"
// #include <sstream>
// #include <vector>
// #include <random>
// #include <algorithm>

// using namespace std;


// // 最终版，无打包

// int main(int argc, char* argv[]) {
//     if (argc != 4) { cerr << "Usage: ./center <listen_port> <server_ip> <server_port>\n"; return 1; }

//     boost::asio::io_context io_context;
//     tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), stoi(argv[1])));
//     cout << "[Center] 启动，等待 Client 连接端口 " << argv[1] << "..." << endl;
//     tcp::socket client_socket(io_context); acceptor.accept(client_socket);

//     tcp::socket server_socket(io_context); tcp::resolver resolver(io_context);
//     boost::asio::connect(server_socket, resolver.resolve(argv[2], argv[3]));

    
//     // 阶段1 接收 Client 密文并透传给 Server
//     auto start = std::chrono::high_resolution_clock::now();
//     string client_req = receive_data(client_socket);
//     send_data(server_socket, client_req);
//     auto end = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration = end - start;
//     std::cout << "Phase 1: the time is " << duration.count()/1000 << " s\n";

    
//     cout << "[Center] 等待 Server 计算完成..." << endl;
//     string server_res = receive_data(server_socket);


//     // ==========================================
//     // 阶段2：零拷贝读取与解析 (Zero-Copy Parsing)
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();
    
//     cout << "[Center] 收到 Server 传来的密文 List，准备进行零拷贝混淆洗牌 (Shuffle)..." << endl;
    
//     // 直接获取底层连续内存的指针
//     const char* ptr = server_res.data();
    
//     uint64_t S;
//     memcpy(&S, ptr, sizeof(S)); // 安全读取，避免内存未对齐问题
//     ptr += sizeof(S);

//     // 使用轻量级结构体记录指针和长度，坚决不进行数据深拷贝
//     struct SketchBlock {
//         const char* data_ptr;
//         uint64_t len;
//     };
//     vector<SketchBlock> sketch_blocks(S);
    
//     uint64_t total_payload_size = sizeof(S);
//     for(uint64_t s = 0; s < S; s++) {
//         uint64_t len;
//         memcpy(&len, ptr, sizeof(len));
        
//         sketch_blocks[s].len = len;
//         sketch_blocks[s].data_ptr = ptr + sizeof(len);
        
//         ptr += sizeof(len) + len;
//         total_payload_size += sizeof(len) + len; // 顺便计算好发往 Client 的总包大小
//     }

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 2 (Zero-Copy Parse): the time is " << duration.count()/1000.0 << " s\n";

//     // ==========================================
//     // 阶段3：指针混淆洗牌 (Pointer Shuffle)
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();

//     // 此时打乱的仅仅是 2000 个结构体指针，速度在纳秒级
//     std::random_device rd_main;
//     std::mt19937_64 gen_main(rd_main());
//     std::shuffle(sketch_blocks.begin(), sketch_blocks.end(), gen_main);

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3 (Pointer Shuffle): the time is " << duration.count()/1000.0 << " s\n";

//     // ==========================================
//     // 阶段4：一次性组装并发包
//     // ==========================================
//     auto start_time = std::chrono::high_resolution_clock::now();
    
//     string final_payload;
//     final_payload.reserve(total_payload_size); // 一次性开辟物理内存，杜绝扩容
    
//     final_payload.append(reinterpret_cast<const char*>(&S), sizeof(S));
//     for(uint64_t s = 0; s < S; s++) {
//         uint64_t len = sketch_blocks[s].len;
//         final_payload.append(reinterpret_cast<const char*>(&len), sizeof(len));
//         final_payload.append(sketch_blocks[s].data_ptr, len);
//     }
    
//     cout << "[Center] 洗牌完毕，发送连续内存块给 Client..." << endl;
//     send_data(client_socket, final_payload);

//     auto end_time = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration_t = end_time - start_time;
//     std::cout << "The time is " << duration_t.count()/1000.0 << " s\n";

//     return 0;
// }



// #include "common.h"
// #include <sstream>
// #include <vector>
// #include <random>
// #include <algorithm>

// using namespace std;


// // 这版的问题，去重不够简洁
// // 最后才解决传输sk问题
// // 这版改的是通信过程

// int main(int argc, char* argv[]) {
//     if (argc != 4) { cerr << "Usage: ./center <listen_port> <server_ip> <server_port>\n"; return 1; }

//     boost::asio::io_context io_context;
//     tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), stoi(argv[1])));
//     cout << "[Center] 启动，等待 Client 连接端口 " << argv[1] << "..." << endl;
//     tcp::socket client_socket(io_context); acceptor.accept(client_socket);

//     tcp::socket server_socket(io_context); tcp::resolver resolver(io_context);
//     boost::asio::connect(server_socket, resolver.resolve(argv[2], argv[3]));

    
//     // 阶段1 接收 Client 密文并透传给 Server
//     auto start = std::chrono::high_resolution_clock::now();
//     string client_req = receive_data(client_socket);
//     send_data(server_socket, client_req);
//     auto end = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration = end - start;
//     std::cout << "Phase 1: the time is " << duration.count()/1000 << " s\n";

    
//     cout << "[Center] 等待 Server 计算完成..." << endl;
//     string server_res = receive_data(server_socket);


//     // ==========================================
//     // 阶段2：零拷贝读取与解析 (Zero-Copy Parsing)
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();
    
//     cout << "[Center] 收到 Server 传来的密文 List，准备进行零拷贝混淆洗牌 (Shuffle)..." << endl;
    
//     // 直接获取底层连续内存的指针
//     const char* ptr = server_res.data();
    
//     uint64_t S;
//     memcpy(&S, ptr, sizeof(S)); // 安全读取，避免内存未对齐问题
//     ptr += sizeof(S);

//     // 使用轻量级结构体记录指针和长度，坚决不进行数据深拷贝
//     struct SketchBlock {
//         const char* data_ptr;
//         uint64_t len;
//     };
//     vector<SketchBlock> sketch_blocks(S);
    
//     uint64_t total_payload_size = sizeof(S);
//     for(uint64_t s = 0; s < S; s++) {
//         uint64_t len;
//         memcpy(&len, ptr, sizeof(len));
        
//         sketch_blocks[s].len = len;
//         sketch_blocks[s].data_ptr = ptr + sizeof(len);
        
//         ptr += sizeof(len) + len;
//         total_payload_size += sizeof(len) + len; // 顺便计算好发往 Client 的总包大小
//     }

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 2 (Zero-Copy Parse): the time is " << duration.count()/1000.0 << " s\n";

//     // ==========================================
//     // 阶段3：指针混淆洗牌 (Pointer Shuffle)
//     // ==========================================
//     start = std::chrono::high_resolution_clock::now();

//     // 此时打乱的仅仅是 2000 个结构体指针，速度在纳秒级
//     std::random_device rd_main;
//     std::mt19937_64 gen_main(rd_main());
//     std::shuffle(sketch_blocks.begin(), sketch_blocks.end(), gen_main);

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3 (Pointer Shuffle): the time is " << duration.count()/1000.0 << " s\n";

//     // ==========================================
//     // 阶段4：一次性组装并发包
//     // ==========================================
//     auto start_time = std::chrono::high_resolution_clock::now();
    
//     string final_payload;
//     final_payload.reserve(total_payload_size); // 一次性开辟物理内存，杜绝扩容
    
//     final_payload.append(reinterpret_cast<const char*>(&S), sizeof(S));
//     for(uint64_t s = 0; s < S; s++) {
//         uint64_t len = sketch_blocks[s].len;
//         final_payload.append(reinterpret_cast<const char*>(&len), sizeof(len));
//         final_payload.append(sketch_blocks[s].data_ptr, len);
//     }
    
//     cout << "[Center] 洗牌完毕，发送连续内存块给 Client..." << endl;
//     send_data(client_socket, final_payload);

//     auto end_time = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration_t = end_time - start_time;
//     std::cout << "The time is " << duration_t.count()/1000.0 << " s\n";

//     return 0;
// }




// #include "common.h"
// #include <sstream>
// #include <vector>
// #include <random>
// #include <algorithm>

// using namespace std;


// // 这版的问题，去重不够简洁
// // 最后才解决传输sk问题

// int main(int argc, char* argv[]) {
//     if (argc != 4) { cerr << "Usage: ./center <listen_port> <server_ip> <server_port>\n"; return 1; }

//     boost::asio::io_context io_context;
//     tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), stoi(argv[1])));
//     cout << "[Center] 启动，等待 Client 连接端口 " << argv[1] << "..." << endl;
//     tcp::socket client_socket(io_context); acceptor.accept(client_socket);

//     tcp::socket server_socket(io_context); tcp::resolver resolver(io_context);
//     boost::asio::connect(server_socket, resolver.resolve(argv[2], argv[3]));

    
//     // 阶段1 接收 Client 密文并透传给 Server
//     auto start = std::chrono::high_resolution_clock::now();
//     string client_req = receive_data(client_socket);
//     send_data(server_socket, client_req);
//     auto end = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration = end - start;
//     std::cout << "Phase 1: the time is " << duration.count()/1000 << " s\n";

    
//     cout << "[Center] 等待 Server 计算完成..." << endl;
//     string server_res = receive_data(server_socket);


//     // 阶段2 读取接收的数据
//     start = std::chrono::high_resolution_clock::now();
    
//     cout << "[Center] 收到 Server 传来的密文 List，准备进行混淆洗牌 (Shuffle)..." << endl;
//     stringstream ss_in(server_res);
//     uint64_t S;
//     ss_in.read(reinterpret_cast<char*>(&S), sizeof(S)); // 读取列表长度

//     // 将每个密文作为纯粹的二进制字符串读取
//     vector<string> sketches_str(S);
//     for(uint64_t s = 0; s < S; s++) {
//         uint64_t len;
//         ss_in.read(reinterpret_cast<char*>(&len), sizeof(len));
//         sketches_str[s].resize(len);
//         ss_in.read(&sketches_str[s][0], len);
//     }

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 2: the time is " << duration.count()/1000 << " s\n";


//     // 阶段3 混淆打乱数组
//     start = std::chrono::high_resolution_clock::now();


    
//     std::random_device rd_main;
//     std::mt19937_64 gen_main(rd_main());
//     std::shuffle(sketches_str.begin(), sketches_str.end(), gen_main);


//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3: the time is " << duration.count()/1000 << " s\n";

    
//     // 将sketch打包给server

//     auto start_time = std::chrono::high_resolution_clock::now();
//     stringstream ss_out;
//     ss_out.write(reinterpret_cast<const char*>(&S), sizeof(S));
//     for(uint64_t s = 0; s < S; s++) {
//         uint64_t len = sketches_str[s].size();
//         ss_out.write(reinterpret_cast<const char*>(&len), sizeof(len));
//         ss_out.write(sketches_str[s].c_str(), len);
//     }
    
//     cout << "[Center] 洗牌完毕，发送混淆后的密文 List 给 Client..." << endl;
//     send_data(client_socket, ss_out.str());

//     auto end_time = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration_t = end_time - start_time;
//     std::cout << "The time is " << duration_t.count()/1000 << " s\n";

//     return 0;
// }






// #include "common.h"
// #include <sstream>
// #include <vector>
// #include <random>
// #include <algorithm>

// using namespace std;



// // 标注最全版

// int main(int argc, char* argv[]) {
//     if (argc != 4) { cerr << "Usage: ./center <listen_port> <server_ip> <server_port>\n"; return 1; }

//     boost::asio::io_context io_context;
//     tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), stoi(argv[1])));
//     cout << "[Center] 启动，等待 Client 连接端口 " << argv[1] << "..." << endl;
//     tcp::socket client_socket(io_context); acceptor.accept(client_socket);

//     tcp::socket server_socket(io_context); tcp::resolver resolver(io_context);
//     boost::asio::connect(server_socket, resolver.resolve(argv[2], argv[3]));

    
//     // 阶段1 接收 Client 密文并透传给 Server
//     auto start = std::chrono::high_resolution_clock::now();
//     string client_req = receive_data(client_socket);
//     send_data(server_socket, client_req);
//     auto end = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration = end - start;
//     std::cout << "Phase 1: the time is " << duration.count()/1000 << " s\n";

    
//     cout << "[Center] 等待 Server 计算完成..." << endl;
//     string server_res = receive_data(server_socket);


//     // 阶段2 读取接收的数据
//     start = std::chrono::high_resolution_clock::now();
    
//     cout << "[Center] 收到 Server 传来的密文 List，准备进行混淆洗牌 (Shuffle)..." << endl;
//     stringstream ss_in(server_res);
//     uint64_t S;
//     ss_in.read(reinterpret_cast<char*>(&S), sizeof(S)); // 读取列表长度

//     // 将每个密文作为纯粹的二进制字符串读取
//     vector<string> sketches_str(S);
//     for(uint64_t s = 0; s < S; s++) {
//         uint64_t len;
//         ss_in.read(reinterpret_cast<char*>(&len), sizeof(len));
//         sketches_str[s].resize(len);
//         ss_in.read(&sketches_str[s][0], len);
//     }

//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 2: the time is " << duration.count()/1000 << " s\n";


//     // 阶段3 混淆打乱数组
//     start = std::chrono::high_resolution_clock::now();


    
//     std::random_device rd_main;
//     std::mt19937_64 gen_main(rd_main());
//     std::shuffle(sketches_str.begin(), sketches_str.end(), gen_main);


//     end = std::chrono::high_resolution_clock::now();
//     duration = end - start;
//     std::cout << "Phase 3: the time is " << duration.count()/1000 << " s\n";

    
//     // 将sketch打包给server

//     auto start_time = std::chrono::high_resolution_clock::now();
//     stringstream ss_out;
//     ss_out.write(reinterpret_cast<const char*>(&S), sizeof(S));
//     for(uint64_t s = 0; s < S; s++) {
//         uint64_t len = sketches_str[s].size();
//         ss_out.write(reinterpret_cast<const char*>(&len), sizeof(len));
//         ss_out.write(sketches_str[s].c_str(), len);
//     }
    
//     cout << "[Center] 洗牌完毕，发送混淆后的密文 List 给 Client..." << endl;
//     send_data(client_socket, ss_out.str());

//     auto end_time = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration_t = end_time - start_time;
//     std::cout << "The time is " << duration_t.count()/1000 << " s\n";

//     return 0;
// }





// // #include "common.h"
// // #include <sstream>
// // #include <omp.h>

// // using namespace std;
// // using namespace seal;

// // int main(int argc, char* argv[]) {
// //     if (argc != 4) { cerr << "Usage: ./center <listen_port> <server_ip> <server_port>\n"; return 1; }

// //     boost::asio::io_context io_context;
// //     tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), stoi(argv[1])));
// //     cout << "[Center] 启动，等待 Client 连接端口 " << argv[1] << "..." << endl;
// //     tcp::socket client_socket(io_context); acceptor.accept(client_socket);

// //     tcp::socket server_socket(io_context); tcp::resolver resolver(io_context);
// //     boost::asio::connect(server_socket, resolver.resolve(argv[2], argv[3]));

// //     // 1. 接收 Client 密文并透传给 Server
// //     string client_req = receive_data(client_socket);
// //     send_data(server_socket, client_req);

// //     // 2. 等待 Server 计算完成 (Server 已经完成了掩码盲化)
// //     cout << "[Center] 等待 Server 计算完成..." << endl;
// //     string server_res = receive_data(server_socket);

// //     // 3. 直接透传回 Client
// //     cout << "[Center] Server 处理完毕 (已内建盲化)，直接向 Client 返回结果..." << endl;
// //     send_data(client_socket, server_res);

// //     return 0;
// // }


