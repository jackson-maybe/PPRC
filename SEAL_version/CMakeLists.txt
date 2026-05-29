cmake_minimum_required(VERSION 3.14)
project(FHE_Project)


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


find_package(SEAL 4.1 REQUIRED)


find_package(Boost REQUIRED COMPONENTS system)


find_package(OpenMP REQUIRED)


add_executable(client client.cpp bloomfilter.cpp MurmurHash3.cpp)
target_link_libraries(client SEAL::seal Boost::system OpenMP::OpenMP_CXX)


add_executable(center center.cpp)
target_link_libraries(center SEAL::seal Boost::system OpenMP::OpenMP_CXX)


add_executable(server server.cpp bloomfilter.cpp MurmurHash3.cpp)
target_link_libraries(server SEAL::seal Boost::system OpenMP::OpenMP_CXX)





# # 编译 center (重点在这里：必须加上 SEAL::seal)
# add_executable(center center.cpp)
# target_link_libraries(center SEAL::seal Boost::system)

# # 编译 server
# add_executable(server server.cpp)
# target_link_libraries(server SEAL::seal Boost::system)
