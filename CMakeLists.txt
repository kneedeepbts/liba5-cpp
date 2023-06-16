cmake_minimum_required(VERSION 3.20)
project(liba5)

set(CMAKE_CXX_STANDARD 20)

include_directories(include)

add_library(liba5 library.cpp kasumi.cpp kasumi.h a53gsm.cpp a53gsm.h kgcore.cpp kgcore.h)

add_subdirectory(tests)
