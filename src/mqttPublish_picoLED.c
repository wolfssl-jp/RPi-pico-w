/* mqttClient_main.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
#include <stdio.h>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/ssl.h"

#include "wolf/common.h"
#include "wolf/tcp.h"
#include "wolf/wifi.h"
#include "wolf/blink.h"
#include "lwip/tcp.h"

#define USE_CERT_BUFFERS_256
#define USE_CERT_BUFFERS_2048

#include <wolfssl/certs_test.h>



#include "wolfmqtt/mqtt_types.h"
#include "wolfmqtt/mqtt_client.h"
#include "examples/mqttport.h"
#include "examples/mqttnet.h"
#include "examples/mqttexample.h"

#include "wolf/mqtt.h"

#include "wolf/test_mosquitto_cert.h"

#include "tiny-json.h"


#define MAX_BUFFER_SIZE 1024
#define TEST_MOSQUITTO_ORG_IP "91.121.93.94"
#ifdef ENABLE_MQTT_TLS
#define MQTT_BROKER_PORT 8884
#else 
#define MQTT_BROKER_PORT 1883
#endif

#define TIMEOUT_MS 50000

#define IN_BUTTON_PIN 28
#define LED_ON_MSG "{ \"led\" : \"on\" }"
#define LED_OFF_MSG "{ \"led\" : \"off\" }"


/* Locals */
static int mStopRead = 0;

static int mqtt_message_cb(MqttClient *client, MqttMessage *msg,
    byte msg_new, byte msg_done)
{
    byte buf[PRINT_BUFFER_SIZE+1];
    word32 len;
    MQTTCtx* mqttCtx = (MQTTCtx*)client->ctx;

    enum { MAX_FIELDS = 4 }; // Max Number of Json fields is 1, is "led"
    json_t pool[ MAX_FIELDS ];


    (void)mqttCtx;

    if (msg_new) {
        /* Determine min size to dump */
        len = msg->topic_name_len;
        if (len > PRINT_BUFFER_SIZE) {
            len = PRINT_BUFFER_SIZE;
        }
        XMEMCPY(buf, msg->topic_name, len);
        buf[len] = '\0'; /* Make sure its null terminated */

        /* Print incoming message */
        PRINTF("MQTT Message: Topic %s, Qos %d, Len %u",
            buf, msg->qos, msg->total_len);

        /* for test mode: check if DEFAULT_MESSAGE was received */
        if (mqttCtx->test_mode) {
            if (XSTRLEN(DEFAULT_MESSAGE) == msg->buffer_len &&
                XSTRNCMP(DEFAULT_MESSAGE, (char*)msg->buffer,
                         msg->buffer_len) == 0)
            {
                mStopRead = 1;
            }
        }
    }

    /* Print message payload */
    len = msg->buffer_len;
    if (len > PRINT_BUFFER_SIZE) {
        len = PRINT_BUFFER_SIZE;
    }
    XMEMCPY(buf, msg->buffer, len);
    buf[len] = '\0'; /* Make sure its null terminated */
    PRINTF("Payload (%d - %d) printing %d bytes:" LINE_END "%s",
        msg->buffer_pos, msg->buffer_pos + msg->buffer_len, len, buf);


    if (msg_done) {
        PRINTF("MQTT Message: Done");
        /* parse JSON string text to JSON obj and extract value of property "led" */
        json_t const* parent = json_create( buf, pool, MAX_FIELDS );
        if ( parent == NULL ) {
            fprintf(stderr, "%s\n",
            "The JSON string is bad formated or has more fields than the array");
            return WOLF_FAIL;
        };

        
        json_t const* led_field = json_getProperty( parent, "led" );
        if ( led_field == NULL ) return WOLF_FAIL;
        if ( json_getType( led_field ) != JSON_TEXT ) return WOLF_FAIL;
        
        char const* led_value = json_getValue( led_field );
        printf( "%s%s%s", "LED: \"", led_value, "\"\n" );

         if (strcmp(led_value, "on") == 0){
            /* Enable LED */
            cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);

         } 
         else if (strcmp(led_value, "off") == 0){
            /* Disable LED */
            cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);

         }

    }
    
    /* Return negative to terminate publish processing */
    return MQTT_CODE_SUCCESS;
}




/* mqtt Publish example */
int mqttPublish_picoLED(MQTTCtx *mqttCtx)
{
    int rc = MQTT_CODE_SUCCESS, i;

    PRINTF("MQTT Client: QoS %d, Use TLS %d\n", mqttCtx->qos,
            mqttCtx->use_tls);

    /* Initialize Network */
    rc = MqttClientNet_Init(&mqttCtx->net, mqttCtx);
    PRINTF("MQTT Net Init: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }

    /* setup tx/rx buffers */
    mqttCtx->tx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
    mqttCtx->rx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);

    /* Initialize MqttClient structure */
    rc = MqttClient_Init(&mqttCtx->client, &mqttCtx->net,
        mqtt_message_cb,
        mqttCtx->tx_buf, MAX_BUFFER_SIZE,
        mqttCtx->rx_buf, MAX_BUFFER_SIZE,
        mqttCtx->cmd_timeout_ms);

    PRINTF("MQTT Init: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }
    /* The client.ctx will be stored in the cert callback ctx during
       MqttSocket_Connect for use by mqtt_tls_verify_cb */
    mqttCtx->client.ctx = mqttCtx;

#ifdef WOLFMQTT_DISCONNECT_CB
    /* setup disconnect callback */
    rc = MqttClient_SetDisconnectCallback(&mqttCtx->client,
        mqtt_disconnect_cb, NULL);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }
#endif



    /* Connect to broker */
    rc = MqttClient_NetConnect(&mqttCtx->client, mqttCtx->host,
           mqttCtx->port,
        TIMEOUT_MS, mqttCtx->use_tls, mqtt_tls_cb);

    PRINTF("MQTT Socket Connect: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }

    /* Build connect packet */
    XMEMSET(&mqttCtx->connect, 0, sizeof(MqttConnect));
    mqttCtx->connect.keep_alive_sec = mqttCtx->keep_alive_sec;
    mqttCtx->connect.clean_session = mqttCtx->clean_session;
    mqttCtx->connect.client_id = mqttCtx->client_id;

    /* Last will and testament sent by broker to subscribers
        of topic when broker connection is lost */
    XMEMSET(&mqttCtx->lwt_msg, 0, sizeof(mqttCtx->lwt_msg));
    mqttCtx->connect.lwt_msg = &mqttCtx->lwt_msg;
    mqttCtx->connect.enable_lwt = mqttCtx->enable_lwt;
    if (mqttCtx->enable_lwt) {
        /* Send client id in LWT payload */
        mqttCtx->lwt_msg.qos = mqttCtx->qos;
        mqttCtx->lwt_msg.retain = 0;
        mqttCtx->lwt_msg.topic_name = WOLFMQTT_TOPIC_NAME"lwttopic";
        mqttCtx->lwt_msg.buffer = (byte*)mqttCtx->client_id;
        mqttCtx->lwt_msg.total_len = (word16)XSTRLEN(mqttCtx->client_id);


    }
    /* Optional authentication */
    mqttCtx->connect.username = mqttCtx->username;
    mqttCtx->connect.password = mqttCtx->password;


    /* Send Connect and wait for Connect Ack */
    rc = MqttClient_Connect(&mqttCtx->client, &mqttCtx->connect);

    PRINTF("MQTT Connect: Proto (%s), %s (%d)",
        MqttClient_GetProtocolVersionString(&mqttCtx->client),
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto disconn;
    }


    /* Validate Connect Ack info */
    PRINTF("MQTT Connect Ack: Return Code %u, Session Present %d",
        mqttCtx->connect.ack.return_code,
        (mqttCtx->connect.ack.flags &
            MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) ?
            1 : 0
    );


    /* Build list of topics */
    XMEMSET(&mqttCtx->subscribe, 0, sizeof(MqttSubscribe));

    i = 0;
    mqttCtx->topics[i].topic_filter = mqttCtx->topic_name;
    mqttCtx->topics[i].qos = mqttCtx->qos;



    /* Subscribe Topic */
    mqttCtx->subscribe.packet_id = mqtt_get_packetid();
    mqttCtx->subscribe.topic_count =
            sizeof(mqttCtx->topics) / sizeof(MqttTopic);
    mqttCtx->subscribe.topics = mqttCtx->topics;

    rc = MqttClient_Subscribe(&mqttCtx->client, &mqttCtx->subscribe);


    PRINTF("MQTT Subscribe: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto disconn;
    }

    /* show subscribe results */
    for (i = 0; i < mqttCtx->subscribe.topic_count; i++) {
        MqttTopic *topic = &mqttCtx->subscribe.topics[i];
        PRINTF("  Topic %s, Qos %u, Return Code %u",
            topic->topic_filter,
            topic->qos, topic->return_code);
    }

    /* Set up for Publish Topic */
    XMEMSET(&mqttCtx->publish, 0, sizeof(MqttPublish));
    mqttCtx->publish.retain = 0;
    mqttCtx->publish.qos = mqttCtx->qos;
    mqttCtx->publish.duplicate = 0;
    mqttCtx->publish.topic_name = mqttCtx->topic_name;
    mqttCtx->publish.packet_id = mqtt_get_packetid();

    /* Waiting for button input */

    gpio_init(IN_BUTTON_PIN);
    gpio_set_dir(IN_BUTTON_PIN, GPIO_IN);
    gpio_pull_up(IN_BUTTON_PIN);


    bool led_value = false;
    while (true) {
        //  Read a value from pin 
        bool btn_value = gpio_get(IN_BUTTON_PIN);

        // Detect switch press
        if (btn_value) {
            led_value = !led_value;
            switch (led_value) {
                case false:
                    /* Publish Topic */
                    mqttCtx->publish.buffer = (byte*)LED_OFF_MSG;
                    mqttCtx->publish.total_len = (word16)XSTRLEN(LED_OFF_MSG);
                    rc = MqttClient_Publish(&mqttCtx->client, &mqttCtx->publish);
                    PRINTF("MQTT Publish: Topic %s, %s %s (%d)",
                        mqttCtx->publish.topic_name,
                         mqttCtx->publish.buffer,
                        MqttClient_ReturnCodeToString(rc), rc);
                    break;
                case true:
                    /* Publish Topic */
                    mqttCtx->publish.buffer = (byte*)LED_ON_MSG;
                    mqttCtx->publish.total_len = (word16)XSTRLEN(LED_ON_MSG);
                    rc = MqttClient_Publish(&mqttCtx->client, &mqttCtx->publish);
                    PRINTF("MQTT Publish: Topic %s, %s %s (%d)",
                        mqttCtx->publish.topic_name,
                         mqttCtx->publish.buffer,
                        MqttClient_ReturnCodeToString(rc), rc);
                    break;
            }

            // Wait until switch is released
            while (gpio_get(IN_BUTTON_PIN)) {
                tight_loop_contents();
            }
        }
        sleep_ms(10);
    }


    /* Read Loop */
    PRINTF("MQTT Waiting for message...");

    do {
        /* check for test mode */
        if (mqttCtx->test_mode) {
            PRINTF("MQTT Test mode, exit now");
            break;
        }

        /* Try and read packet */
        rc = MqttClient_WaitMessage(&mqttCtx->client,
                                            mqttCtx->cmd_timeout_ms);



        if (mStopRead) {
            rc = MQTT_CODE_SUCCESS;
            PRINTF("MQTT Exiting...");
            break;
        }

        /* check return code */
        else if (rc == MQTT_CODE_ERROR_TIMEOUT) {
            /* Keep Alive */
            PRINTF("Keep-alive timeout, sending ping");

            rc = MqttClient_Ping_ex(&mqttCtx->client, &mqttCtx->ping);
            if (rc != MQTT_CODE_SUCCESS) {
                PRINTF("MQTT Ping Keep Alive Error: %s (%d)",
                    MqttClient_ReturnCodeToString(rc), rc);
                break;
            }
        }
        else if (rc != MQTT_CODE_SUCCESS) {
            /* There was an error */
            PRINTF("MQTT Message Wait: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            break;
        }
    } while (!mStopRead);

    /* Check for error */
    if (rc != MQTT_CODE_SUCCESS) {
        goto disconn;
    }


disconn:
    /* Disconnect */
    XMEMSET(&mqttCtx->disconnect, 0, sizeof(mqttCtx->disconnect));

    rc = MqttClient_Disconnect_ex(&mqttCtx->client, &mqttCtx->disconnect);


    PRINTF("MQTT Disconnect: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto disconn;
    }

    rc = MqttClient_NetDisconnect(&mqttCtx->client);

    PRINTF("MQTT Socket Disconnect: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);

exit:

    /* Free resources */
    if (mqttCtx->tx_buf) WOLFMQTT_FREE(mqttCtx->tx_buf);
    if (mqttCtx->rx_buf) WOLFMQTT_FREE(mqttCtx->rx_buf);

    /* Cleanup network */
    MqttClientNet_DeInit(&mqttCtx->net);

    MqttClient_DeInit(&mqttCtx->client);

    return rc;
}

int set_mqtt_ctx(MQTTCtx* mqttCtx){

    XMEMSET(mqttCtx, 0, sizeof(MQTTCtx));
    mqttCtx->host = DEFAULT_MQTT_HOST;
    mqttCtx->qos = MQTT_QOS_2;
    mqttCtx->clean_session = 1;
    mqttCtx->keep_alive_sec = DEFAULT_KEEP_ALIVE_SEC;
    mqttCtx->client_id = "AnotherMQTTClient";
    mqttCtx->topic_name = WOLFMQTT_TOPIC_NAME"pico_LED";
    mqttCtx->cmd_timeout_ms = DEFAULT_CMD_TIMEOUT_MS;

#ifdef ENABLE_MQTT_TLS
    mqttCtx->use_tls = 1;
#else 
    mqttCtx->use_tls = 0;
#endif
    mqttCtx->app_name = "mqttclient";
    mqttCtx->message = DEFAULT_MESSAGE;


    
    return 0;
}


void main(void)
{
    blink(15, 1);

    cyw43_arch_enable_sta_mode();
    printf("Connecting to Wi-Fi...\n");
    printf("WIFI_SSID=%s, WIFI_PASSWORD=%s\n", WIFI_SSID, WIFI_PASSWORD);
    if (wolf_wifiConnect(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 30000)) {
        printf("failed to connect.\n");
        return;
    } else {
        printf("Wifi connected.\n");
    }
    cyw43_arch_lwip_begin();


    int rc;
    MQTTCtx mqttCtx;

    /* init defaults */
    mqtt_init_ctx(&mqttCtx);

    rc = set_mqtt_ctx(&mqttCtx);

    rc = mqttPublish_picoLED(&mqttCtx);

    mqtt_free_ctx(&mqttCtx);

    cyw43_arch_lwip_end();
    cyw43_arch_deinit();

    printf("Wifi disconnected\n");

}


