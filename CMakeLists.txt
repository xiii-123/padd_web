cmake_minimum_required(VERSION 3.10)
project(crypto_service LANGUAGES C CXX)

# ===== C++ 标准 =====
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ===== 全局头文件路径 =====
include_directories(
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/lib/include          # httplib.h
    $ENV{HOME}/.local/include/pbc
)

# ===== 外部库路径 =====
link_directories(
    $ENV{HOME}/.local/lib
)

# =====================================================
# secure_usb 动态库
# =====================================================
add_library(secure_usb SHARED
    src/secure_usb/secure_usb.cpp
)

target_include_directories(secure_usb PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

set_target_properties(secure_usb PROPERTIES
    OUTPUT_NAME "secure_usb"
    VERSION 1.0
    SOVERSION 1
)

# =====================================================
# crypto_core（原 padd 项目演化而来）
# =====================================================
add_library(crypto_core SHARED
    src/crypto/padd_01.cpp
    src/crypto/utils.cpp
    src/crypto/vrf.cpp
    tools/base64.cpp
)

target_link_libraries(crypto_core
    pbc
    gmp
    crypto
    stdc++fs
)

set_target_properties(crypto_core PROPERTIES
    OUTPUT_NAME "crypto_core"
    VERSION 1.0
    SOVERSION 1
)



# 然后链接到你的目标

# =====================================================
# HTTP 服务（主程序）
# =====================================================
add_executable(crypto_httpd
    src/main.cc
)

target_link_libraries(crypto_httpd
    crypto_core
    secure_usb
    pthread
)

set_target_properties(crypto_httpd PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# =====================================================
# 工具：初始化 U 盘
# =====================================================
add_executable(init_usb
    tools/init_usb.cpp
)

target_link_libraries(init_usb
    secure_usb
)

set_target_properties(init_usb PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# =====================================================
# 可选：安装规则
# =====================================================
install(TARGETS secure_usb crypto_core
        LIBRARY DESTINATION lib)

install(TARGETS crypto_httpd init_usb
        RUNTIME DESTINATION bin)

install(DIRECTORY include/
        DESTINATION include)
