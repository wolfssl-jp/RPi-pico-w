cmake_minimum_required(VERSION 3.13)

# Pull in Pico and FreeRTOS
include($ENV{PICO_EXAMPLES_PATH}/pico_sdk_import.cmake)
include($ENV{PICO_EXAMPLES_PATH}/pico_extras_import_optional.cmake)
# include($ENV{PICO_SDK_PATH}/pico_sdk_version.cmake)
# include($ENV{PICO_SDK_PATH}/src/common/pico_base/generate_config_header.cmake)

#include($ENV{FREERTOS_KERNEL_PATH}/portable/ThirdParty/GCC/RP2040/FreeRTOS_Kernel_import.cmake)


if(PICO_SDK_VERSION_STRING VERSION_LESS "1.3.0")
    message(FATAL_ERROR "Raspberry Pi Pico SDK version 1.3.0 (or later) required. Your version is ${PICO_SDK_VERSION_STRING}")
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
    include_directories(${PICO_SDK_PATH}/lib/lwip/contrib/ports/freertos/include)
    include_directories(${PICO_SDK_PATH}/lib/lwip/src/include)
    include_directories(${PICO_SDK_PATH}/src/rp2_common/pico_async_context/include)
    include_directories(${PICO_SDK_PATH}/src/common/pico_base/include)

    set(WOLFSSL_ROOT $ENV{WOLFSSL_ROOT})
    include_directories(${WOLFSSL_ROOT})
    # set(WOLFMQTT_ROOT $ENV{WOLFMQTT_ROOT})
    # include_directories(${WOLFSSL_ROOT})

# ## End of Global Include Path

include(wolfssl_import.cmake)
include(wolfmqtt_import.cmake)

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
    pico_enable_stdio_uart(testwolfcrypt 0)

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

    pico_enable_stdio_usb(benchmark 1)
    pico_enable_stdio_uart(benchmark 0)

    pico_add_extra_outputs(benchmark)
### End of Benchmark wolfCrypt algorithms


### Wifi connection
    add_executable(Wifi
        src/blink.c
        src/wifi.c
        src/Wifi_main.c
    )

    target_compile_definitions(Wifi PRIVATE
        WIFI_SSID=\"${WIFI_SSID}\"
        WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
        PICO_CYW43_ARCH_POLL=1
        NO_SYS=1
    )

    target_link_libraries(Wifi
        pico_stdlib
        pico_rand
        pico_lwip
        pico_cyw43_arch
        pico_lwip_nosys
        pico_async_context_poll
    )


    pico_enable_stdio_usb(Wifi 1)
    pico_enable_stdio_uart(Wifi 0)

    pico_add_extra_outputs(Wifi)
### End of Wifi connection


### TCP Client
    add_executable(tcp_Client
        src/blink.c
        src/wifi.c
        src/tcp.c
        src/tcpClient_main.c
    )

    target_compile_definitions(tcp_Client PRIVATE
        WIFI_SSID=\"${WIFI_SSID}\"
        WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
        TEST_TCP_SERVER_IP=\"${TEST_TCP_SERVER_IP}\"
        PICO_CYW43_ARCH_POLL=1
        NO_SYS=1
    )

    target_link_libraries(tcp_Client
        pico_stdlib
        pico_rand
        pico_lwip
        pico_cyw43_arch
        pico_lwip_nosys
        pico_async_context_poll
    )


    pico_enable_stdio_usb(tcp_Client 1)
    pico_enable_stdio_uart(tcp_Client 0)

    pico_add_extra_outputs(tcp_Client)
### End of TCP Client


### TLS Client
    add_executable(tls_Client
        src/blink.c
        src/wifi.c
        src/tcp.c
        src/tlsClient_main.c
    )

    target_compile_definitions(tls_Client PRIVATE
        WIFI_SSID=\"${WIFI_SSID}\"
        WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
        TEST_TCP_SERVER_IP=\"${TEST_TCP_SERVER_IP}\"
        PICO_CYW43_ARCH_POLL=1
        NO_SYS=1
    )

    target_link_libraries(tls_Client
        pico_stdlib
        pico_rand
        pico_lwip
        pico_cyw43_arch
        pico_lwip_nosys
        pico_async_context_poll
        wolfssl
    )

    pico_enable_stdio_usb(tls_Client 1)
    pico_enable_stdio_uart(tls_Client 0)

    pico_add_extra_outputs(tls_Client)
### End of TLS Client

### MQTT Client
    add_executable(mqtt_Client
        src/mqttClient_main.c
        src/blink.c
        src/wifi.c
        src/tcp.c
        src/mqtt.c
    )
    target_compile_definitions(mqtt_Client PRIVATE
        WIFI_SSID=\"${WIFI_SSID}\"
        WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
        TEST_TCP_SERVER_IP=\"${TEST_TCP_SERVER_IP}\"
        PICO_CYW43_ARCH_POLL=1
        NO_SYS=1
        ENABLE_MQTT_TLS=1

    )
    target_link_libraries(mqtt_Client
        pico_stdlib
        pico_rand
        pico_lwip
        pico_cyw43_arch
        pico_lwip_nosys
        pico_async_context_poll
        wolfssl
        wolfmqtt
    )
    
    pico_enable_stdio_usb(mqtt_Client 1)
    pico_enable_stdio_uart(mqtt_Client 0)

    pico_add_extra_outputs(mqtt_Client)

### End of MQTT Client
