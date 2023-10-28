find_package(spdlog)

add_library(liba5
        library.cpp
        kasumi.cpp
        a53gsm.cpp
        kgcore.cpp
        gea3.cpp
        a53ecsd.cpp
        a54gsm.cpp
        a54ecsd.cpp
        gea4.cpp
        milenage.cpp
        rijndael.cpp
        utilities.cpp
)

target_link_libraries(liba5 spdlog::spdlog)