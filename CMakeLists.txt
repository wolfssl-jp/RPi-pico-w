cmake_minimum_required(VERSION 3.13)

# Pull in Pico, Pico-examples and FreeRTOS
# Pico Examples is only for referring ico_sdk_import.cmake and pico_extras_import_optional.cmake
set(PICO_BOARD pico_w)
include($ENV{PICO_EXAMPLES_PATH}/pico_sdk_import.cmake)
include($ENV{PICO_EXAMPLES_PATH}/pico_extras_import_optional.cmake)
include($ENV{FREERTOS_KERNEL_PATH}/portable/ThirdParty/GCC/RP2040/FreeRTOS_Kernel_import.cmake)

if(PICO_SDK_VERSION_STRING VERSION_LESS " 1.3.0 ")
    message(FATAL_ERROR " Raspberry Pi Pico SDK version 1.3.0(or later) required. Your version is ${PICO_SDK_VERSION_STRING} ")
endif()

project(wolf_pico_examples C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Initialize the SDK
pico_sdk_init()

### Global Include Path
    include_directories(config)
    include_directories(include)
    include_directories(${PICO_SDK_PATH}/src/rp2_common/pico_lwip/include)
    include_directories(${PICO_SDK_PATH}/src/rp2_common/hardware_rtc/include)
    include_directories(${PICO_SDK_PATH}/lib/lwip/contrib/ports/freertos/include)
    include_directories(${PICO_SDK_PATH}/lib/lwip/src/include)
    include_directories(${PICO_SDK_PATH}/src/rp2_common/pico_async_context/include)
### End of Global Include Path

include(wolfssl_import.cmake)

### Test wolfCrypt algorithms
    add_executable(testwolfcrypt
        src/test_main.c
        src/blink.c
        ${WOLFSSL_ROOT}/wolfcrypt/test/test.c
    )

    target_link_libraries(testwolfcrypt
        wolfssl
        pico_stdlib
        pico_cyw43_arch_none
        pico_rand
    )

    pico_enable_stdio_usb(testwolfcrypt 1)
    pico_enable_stdio_uart(testwolfcrypt 1)

    pico_add_extra_outputs(testwolfcrypt)
### End of Test wolfCrypt algorithms


### Benchmark wolfCrypt algorithms
    add_executable(benchmark
        src/bench_main.c
        src/blink.c
        ${WOLFSSL_ROOT}/wolfcrypt/benchmark/benchmark.c
    )

    target_link_libraries(benchmark
        wolfssl
        pico_stdlib
        pico_cyw43_arch_none
        pico_rand
    )

    target_compile_definitions(benchmark PRIVATE
        WOLFSSL_RPI_PICO
    )

    pico_enable_stdio_usb(benchmark 1)
    pico_enable_stdio_uart(benchmark 1)

    pico_add_extra_outputs(benchmark)
### End of Benchmark wolfCrypt algorithms

### TCP Client
    add_executable(tcp_Client
        src/blink.c
        src/wifi.c
        src/tcp.c
        src/tcpClient_main.c
        src/idleMemory.c
    )

    target_compile_definitions(tcp_Client PRIVATE
        WIFI_SSID=\"${WIFI_SSID}\"
        WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
        TCP_SERVER=\"${TCP_SERVER}\"
        NO_SYS=0
        LWIP_SOCKET
        LWIP_COMPAT_SOCKETS
        PING_USE_SOCKETS=1
    )

    target_link_libraries(tcp_Client
        pico_stdlib
        pico_rand
        pico_cyw43_arch_lwip_sys_freertos
        FreeRTOS-Kernel-Heap4
    )

    pico_enable_stdio_usb(tcp_Client 1)
    pico_enable_stdio_uart(tcp_Client 1)

    pico_add_extra_outputs(tcp_Client)
    ### End of TCP Client

    ### TLS Client: Bare metal
    add_executable(tls_Client
        src/blink.c
        src/wifi.c
        src/tcp.c
        src/tls.c
        src/time.c
        src/idleMemory.c
        src/tlsClient_main.c
    )

    target_compile_definitions(tls_Client PRIVATE
        WIFI_SSID=\"${WIFI_SSID}\"
        WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
        TCP_SERVER=\"${TCP_SERVER}\"
        NO_SYS=0
        LWIP_SOCKET=1
        LWIP_COMPAT_SOCKETS=1
        PING_USE_SOCKETS=1
        DATETIME=\"${DATETIME}\"
        WOLFSSL_USER_SETTINGS
    )

    target_link_libraries(tls_Client
        pico_stdlib
        pico_rand
        pico_cyw43_arch_lwip_sys_freertos
        FreeRTOS-Kernel-Heap4
        wolfssl
    )

    pico_enable_stdio_usb(tls_Client 1)
    pico_enable_stdio_uart(tls_Client 1)

    pico_add_extra_outputs(tls_Client)

### End of TLS Client

### FreeRTOS Port
add_library(FREERTOS_PORT INTERFACE)
target_include_directories(FREERTOS_PORT
    INTERFACE
    config
)
target_sources(FREERTOS_PORT INTERFACE
    ./src/IdleMemory.c
)
### FreeRTOS Port
