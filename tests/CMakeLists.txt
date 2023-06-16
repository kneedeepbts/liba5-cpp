add_executable(test_liba5 test_library.cpp test_kasumi.cpp test_kgcore.cpp test_a53gsm.cpp test_gea3.cpp test_a53ecsd.cpp test_a54gsm.cpp test_a54ecsd.cpp test_gea4.cpp)
target_link_libraries(test_liba5 liba5)
