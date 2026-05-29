cmake_minimum_required(VERSION 3.14)
project(FHE_Project)

# 启用 C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 寻找 SEAL 库
find_package(SEAL 4.1 REQUIRED)

# 寻找 Boost 系统和网络库
find_package(Boost REQUIRED COMPONENTS system)

# 寻找 OpenMP 多线程库
find_package(OpenMP REQUIRED)

# 编译 client (链接 SEAL, Boost, OpenMP)
add_executable(client client.cpp bloomfilter.cpp MurmurHash3.cpp)
target_link_libraries(client SEAL::seal Boost::system OpenMP::OpenMP_CXX)

# 编译 center (链接 SEAL, Boost, OpenMP)
add_executable(center center.cpp)
target_link_libraries(center SEAL::seal Boost::system OpenMP::OpenMP_CXX)

# 编译 server (链接 SEAL, Boost, OpenMP)
add_executable(server server.cpp bloomfilter.cpp MurmurHash3.cpp)
target_link_libraries(server SEAL::seal Boost::system OpenMP::OpenMP_CXX)




# cmake_minimum_required(VERSION 3.14)
# project(FHE_Project)

# # 启用 C++17
# set(CMAKE_CXX_STANDARD 17)
# set(CMAKE_CXX_STANDARD_REQUIRED ON)

# # 寻找 SEAL 库
# find_package(SEAL 4.1 REQUIRED)

# # 寻找 Boost 系统和网络库
# find_package(Boost REQUIRED COMPONENTS system)

# # ==========================================
# # 新增：寻找 OpenMP 多线程库
# # ==========================================
# find_package(OpenMP REQUIRED)

# # 编译 client
# add_executable(client client.cpp bloomfilter.cpp MurmurHash3.cpp)
# target_link_libraries(client SEAL::seal Boost::system)

# # 编译 center
# add_executable(center center.cpp)
# target_link_libraries(center SEAL::seal Boost::system)

# # 编译 server (注意末尾加上了 OpenMP::OpenMP_CXX)
# add_executable(server server.cpp bloomfilter.cpp MurmurHash3.cpp)
# target_link_libraries(server SEAL::seal Boost::system OpenMP::OpenMP_CXX)



# cmake_minimum_required(VERSION 3.14)
# project(FHE_Project)

# # 启用 C++17
# set(CMAKE_CXX_STANDARD 17)
# set(CMAKE_CXX_STANDARD_REQUIRED ON)

# # 寻找 SEAL 库
# find_package(SEAL 4.1 REQUIRED)

# # 寻找 Boost 系统和网络库
# find_package(Boost REQUIRED COMPONENTS system)

# # 编译 client (加上 bloomfilter.cpp 和 MurmurHash3.cpp)
# add_executable(client client.cpp bloomfilter.cpp MurmurHash3.cpp)
# target_link_libraries(client SEAL::seal Boost::system)

# # 编译 center (Center 只需要透传和盲化，不需要布隆过滤器逻辑)
# add_executable(center center.cpp)
# target_link_libraries(center SEAL::seal Boost::system)

# # 编译 server (加上 bloomfilter.cpp 和 MurmurHash3.cpp)
# add_executable(server server.cpp bloomfilter.cpp MurmurHash3.cpp)
# target_link_libraries(server SEAL::seal Boost::system)


# cmake_minimum_required(VERSION 3.14)
# project(FHE_Project)

# # 启用 C++17
# set(CMAKE_CXX_STANDARD 17)
# set(CMAKE_CXX_STANDARD_REQUIRED ON)

# # 寻找 SEAL 库
# find_package(SEAL 4.1 REQUIRED)

# # 寻找 Boost 系统和网络库
# find_package(Boost REQUIRED COMPONENTS system)

# # 编译 client
# add_executable(client client.cpp)
# target_link_libraries(client SEAL::seal Boost::system)

# # 编译 center (重点在这里：必须加上 SEAL::seal)
# add_executable(center center.cpp)
# target_link_libraries(center SEAL::seal Boost::system)

# # 编译 server
# add_executable(server server.cpp)
# target_link_libraries(server SEAL::seal Boost::system)