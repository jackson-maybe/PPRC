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
    
    tcp::socket client_socket(io_context); acceptor.accept(client_socket);

    tcp::socket server_socket(io_context); tcp::resolver resolver(io_context);
    boost::asio::connect(server_socket, resolver.resolve(argv[2], argv[3]));

    
    
    string client_req = receive_data(client_socket);
    

    
    uint32_t session_seed = std::random_device{}();
    string new_req;
    new_req.append(reinterpret_cast<const char*>(&session_seed), sizeof(session_seed));
    new_req.append(client_req);

    send_data(server_socket, new_req);
    
    
    string server_res = receive_data(server_socket);
    
    
    
    
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

    
    

    
    

    std::random_device rd_main;
    std::mt19937_64 gen_main(rd_main());
    std::shuffle(sketch_blocks.begin(), sketch_blocks.end(), gen_main);

   
    

    
    
    
    string final_payload;
    final_payload.reserve(total_payload_size);
    
    final_payload.append(reinterpret_cast<const char*>(&S), sizeof(S));
    for(uint64_t s = 0; s < S; s++) {
        uint64_t len = sketch_blocks[s].len;
        final_payload.append(reinterpret_cast<const char*>(&len), sizeof(len));
        final_payload.append(sketch_blocks[s].data_ptr, len);
    }
    
    
    send_data(client_socket, final_payload);

    
    

    return 0;
}

