cmake_minimum_required(VERSION 3.20)
project(liba5)

set(CMAKE_CXX_STANDARD 20)

add_subdirectory(src)
#find_package(spdlog)
#
#add_library(liba5
#        src/library.cpp
#        src/kasumi.cpp
#        src/a53gsm.cpp
#        src/kgcore.cpp
#        src/gea3.cpp
#        src/a53ecsd.cpp
#        src/a54gsm.cpp
#        src/a54ecsd.cpp
#        src/gea4.cpp
#        src/milenage.cpp
#        src/rijndael.cpp
#        src/utilities.cpp
#)
#
#target_link_libraries(liba5 spdlog::spdlog)

add_subdirectory(tests)
