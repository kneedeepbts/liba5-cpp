cmake_minimum_required(VERSION 3.20)
project(liba5)

set(CMAKE_CXX_STANDARD 20)

find_package(spdlog)

add_library(liba5 library.cpp kasumi.cpp kasumi.h a53gsm.cpp a53gsm.h kgcore.cpp kgcore.h gea3.cpp gea3.h a53ecsd.cpp a53ecsd.h a54gsm.cpp a54gsm.h a54ecsd.cpp a54ecsd.h gea4.cpp gea4.h milenage.cpp milenage.h rijndael.cpp rijndael.h utilities.cpp utilities.h)

target_link_libraries(liba5 spdlog::spdlog)

add_subdirectory(tests)
