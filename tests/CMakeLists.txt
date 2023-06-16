add_executable(test_liba5 test_library.cpp test_kasumi.cpp test_kgcore.cpp test_a53gsm.cpp)
target_link_libraries(test_liba5 liba5)
