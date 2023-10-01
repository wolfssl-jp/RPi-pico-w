
set(WOLFMQTT_ROOT $ENV{WOLFMQTT_ROOT})
set(WOLFSSL_ROOT $ENV{WOLFSSL_ROOT})


# ## wolfSSL/wolfCrypt library
file(GLOB_RECURSE WOLFMQTT_SRC
    "${WOLFMQTT_ROOT}/src/mqtt_client.c"
    "${WOLFMQTT_ROOT}/src/mqtt_packet.c"
    "${WOLFMQTT_ROOT}/src/mqtt_socket.c"
    # "${WOLFMQTT_ROOT}/examples/mqttexample.c"
    # "${WOLFSSL_ROOT}/src/wolfio.c"

    )

add_library(wolfmqtt STATIC
    ${WOLFMQTT_SRC}
)

include_directories(${WOLFMQTT_ROOT})
include_directories(${WOLFSSL_ROOT})

target_compile_definitions(wolfmqtt PUBLIC
    WOLFMQTT_USER_SETTINGS
)
# Link wolfMQTT with wolfSSL
target_link_libraries(wolfmqtt
    wolfssl
)
### End of wolfMQTT library
