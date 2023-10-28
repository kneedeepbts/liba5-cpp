cmake_minimum_required(VERSION 3.20)
project(liba5)

set(CMAKE_CXX_STANDARD 20)

find_package(spdlog)

add_library(liba5 src/library.cpp src/kasumi.cpp src/kasumi.h src/a53gsm.cpp src/a53gsm.h src/kgcore.cpp src/kgcore.h src/gea3.cpp src/gea3.h src/a53ecsd.cpp src/a53ecsd.h src/a54gsm.cpp src/a54gsm.h src/a54ecsd.cpp src/a54ecsd.h src/gea4.cpp src/gea4.h src/milenage.cpp src/milenage.h src/rijndael.cpp src/rijndael.h src/utilities.cpp src/utilities.h)

target_link_libraries(liba5 spdlog::spdlog)

add_subdirectory(tests)
