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


#define MAX_BUFFER_SIZE 1024
#define TEST_MOSQUITTO_ORG_IP "91.121.93.94"
#ifdef ENABLE_MQTT_TLS
#define MQTT_BROKER_PORT 8884
#else 
#define MQTT_BROKER_PORT 1883
#endif




/* Locals */
static int mStopRead = 0;

static int mqtt_message_cb(MqttClient *client, MqttMessage *msg,
    byte msg_new, byte msg_done)
{
    byte buf[PRINT_BUFFER_SIZE+1];
    word32 len;
    MQTTCtx* mqttCtx = (MQTTCtx*)client->ctx;

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
    }

    /* Return negative to terminate publish processing */
    return MQTT_CODE_SUCCESS;
}




/* This function is a copy from wolfMQTT/exapmles/mqttclient/mqttclient.c */
int mqttClient_test(MQTTCtx *mqttCtx)
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
#ifdef WOLFMQTT_PROPERTY_CB
    rc = MqttClient_SetPropertyCallback(&mqttCtx->client,
            mqtt_property_cb, NULL);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }
#endif

    /* Connect to broker */
    rc = MqttClient_NetConnect(&mqttCtx->client, mqttCtx->host,
           mqttCtx->port,
        DEFAULT_CON_TIMEOUT_MS, mqttCtx->use_tls, mqtt_tls_cb);

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

#ifdef WOLFMQTT_V5
        {
            /* Add a 5 second delay to sending the LWT */
            MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->lwt_msg.props);
            prop->type = MQTT_PROP_WILL_DELAY_INTERVAL;
            prop->data_int = 5;
        }
#endif
    }
    /* Optional authentication */
    mqttCtx->connect.username = mqttCtx->username;
    mqttCtx->connect.password = mqttCtx->password;
#ifdef WOLFMQTT_V5
    mqttCtx->client.packet_sz_max = mqttCtx->max_packet_size;
    mqttCtx->client.enable_eauth = mqttCtx->enable_eauth;

    if (mqttCtx->client.enable_eauth == 1) {
        /* Enhanced authentication */
        /* Add property: Authentication Method */
        MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->connect.props);
        prop->type = MQTT_PROP_AUTH_METHOD;
        prop->data_str.str = (char*)DEFAULT_AUTH_METHOD;
        prop->data_str.len = (word16)XSTRLEN(prop->data_str.str);
    }
    {
        /* Request Response Information */
        MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->connect.props);
        prop->type = MQTT_PROP_REQ_RESP_INFO;
        prop->data_byte = 1;
    }
    {
        /* Request Problem Information */
        MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->connect.props);
        prop->type = MQTT_PROP_REQ_PROB_INFO;
        prop->data_byte = 1;
    }
    {
        /* Maximum Packet Size */
        MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->connect.props);
        prop->type = MQTT_PROP_MAX_PACKET_SZ;
        prop->data_int = (word32)mqttCtx->max_packet_size;
    }
    {
        /* Topic Alias Maximum */
        MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->connect.props);
        prop->type = MQTT_PROP_TOPIC_ALIAS_MAX;
        prop->data_short = mqttCtx->topic_alias_max;
    }
    if (mqttCtx->clean_session == 0) {
        /* Session expiry interval */
        MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->connect.props);
        prop->type = MQTT_PROP_SESSION_EXPIRY_INTERVAL;
        prop->data_int = DEFAULT_SESS_EXP_INT; /* Session does not expire */
    }
#endif

    /* Send Connect and wait for Connect Ack */
    rc = MqttClient_Connect(&mqttCtx->client, &mqttCtx->connect);

    PRINTF("MQTT Connect: Proto (%s), %s (%d)",
        MqttClient_GetProtocolVersionString(&mqttCtx->client),
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto disconn;
    }

#ifdef WOLFMQTT_V5
    if (mqttCtx->connect.props != NULL) {
        /* Release the allocated properties */
        MqttClient_PropsFree(mqttCtx->connect.props);
    }
    if (mqttCtx->lwt_msg.props != NULL) {
        /* Release the allocated properties */
        MqttClient_PropsFree(mqttCtx->lwt_msg.props);
    }
#endif

    /* Validate Connect Ack info */
    PRINTF("MQTT Connect Ack: Return Code %u, Session Present %d",
        mqttCtx->connect.ack.return_code,
        (mqttCtx->connect.ack.flags &
            MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) ?
            1 : 0
    );

#ifdef WOLFMQTT_PROPERTY_CB
        /* Print the acquired client ID */
        PRINTF("MQTT Connect Ack: Assigned Client ID: %s",
                mqttCtx->client_id);
#endif

    /* Build list of topics */
    XMEMSET(&mqttCtx->subscribe, 0, sizeof(MqttSubscribe));

    i = 0;
    mqttCtx->topics[i].topic_filter = mqttCtx->topic_name;
    mqttCtx->topics[i].qos = mqttCtx->qos;

#ifdef WOLFMQTT_V5
    if (mqttCtx->subId_not_avail != 1) {
        /* Subscription Identifier */
        MqttProp* prop;
        prop = MqttClient_PropsAdd(&mqttCtx->subscribe.props);
        prop->type = MQTT_PROP_SUBSCRIPTION_ID;
        prop->data_int = DEFAULT_SUB_ID;
    }
#endif

    /* Subscribe Topic */
    mqttCtx->subscribe.packet_id = mqtt_get_packetid();
    mqttCtx->subscribe.topic_count =
            sizeof(mqttCtx->topics) / sizeof(MqttTopic);
    mqttCtx->subscribe.topics = mqttCtx->topics;

    rc = MqttClient_Subscribe(&mqttCtx->client, &mqttCtx->subscribe);

#ifdef WOLFMQTT_V5
    if (mqttCtx->subscribe.props != NULL) {
        /* Release the allocated properties */
        MqttClient_PropsFree(mqttCtx->subscribe.props);
    }
#endif

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

    /* Publish Topic */
    XMEMSET(&mqttCtx->publish, 0, sizeof(MqttPublish));
    mqttCtx->publish.retain = 0;
    mqttCtx->publish.qos = mqttCtx->qos;
    mqttCtx->publish.duplicate = 0;
    mqttCtx->publish.topic_name = mqttCtx->topic_name;
    mqttCtx->publish.packet_id = mqtt_get_packetid();

    if (mqttCtx->pub_file) {
        /* If a file is specified, then read into the allocated buffer */
        rc = mqtt_file_load(mqttCtx->pub_file, &mqttCtx->publish.buffer,
                (int*)&mqttCtx->publish.total_len);
        if (rc != MQTT_CODE_SUCCESS) {
            /* There was an error loading the file */
            PRINTF("MQTT Publish file error: %d", rc);
        }
    }
    else {
        mqttCtx->publish.buffer = (byte*)mqttCtx->message;
        mqttCtx->publish.total_len = (word16)XSTRLEN(mqttCtx->message);
    }

    if (rc == MQTT_CODE_SUCCESS) {
    #ifdef WOLFMQTT_V5
        {
            /* Payload Format Indicator */
            MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->publish.props);
            prop->type = MQTT_PROP_PAYLOAD_FORMAT_IND;
            prop->data_byte = 1;
        }
        {
            /* Content Type */
            MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->publish.props);
            prop->type = MQTT_PROP_CONTENT_TYPE;
            prop->data_str.str = (char*)"wolf_type";
            prop->data_str.len = (word16)XSTRLEN(prop->data_str.str);
        }
        if ((mqttCtx->topic_alias_max > 0) &&
            (mqttCtx->topic_alias > 0) &&
            (mqttCtx->topic_alias < mqttCtx->topic_alias_max)) {
            /* Topic Alias */
            MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->publish.props);
            prop->type = MQTT_PROP_TOPIC_ALIAS;
            prop->data_short = mqttCtx->topic_alias;
        }
    #endif

        /* This loop allows payloads larger than the buffer to be sent by
           repeatedly calling publish.
        */
        do {
            rc = MqttClient_Publish(&mqttCtx->client, &mqttCtx->publish);
        } while(rc == MQTT_CODE_PUB_CONTINUE);

        if ((mqttCtx->pub_file) && (mqttCtx->publish.buffer)) {
            WOLFMQTT_FREE(mqttCtx->publish.buffer);
        }

        PRINTF("MQTT Publish: Topic %s, %s (%d)",
            mqttCtx->publish.topic_name,
            MqttClient_ReturnCodeToString(rc), rc);
    #ifdef WOLFMQTT_V5
        if (mqttCtx->qos > 0) {
            PRINTF("\tResponse Reason Code %d", mqttCtx->publish.resp.reason_code);
        }
    #endif
        if (rc != MQTT_CODE_SUCCESS) {
            goto disconn;
        }
    #ifdef WOLFMQTT_V5
        if (mqttCtx->publish.props != NULL) {
            /* Release the allocated properties */
            MqttClient_PropsFree(mqttCtx->publish.props);
        }
    #endif
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

    #ifdef WOLFMQTT_NONBLOCK
        /* Track elapsed time with no activity and trigger timeout */
        rc = mqtt_check_timeout(rc, &mqttCtx->start_sec,
            mqttCtx->cmd_timeout_ms/1000);
    #endif

        if (mStopRead) {
            rc = MQTT_CODE_SUCCESS;
            PRINTF("MQTT Exiting...");
            break;
        }

        /* check return code */
    #ifdef WOLFMQTT_ENABLE_STDIN_CAP
        else if (rc == MQTT_CODE_STDIN_WAKE) {
            XMEMSET(mqttCtx->rx_buf, 0, MAX_BUFFER_SIZE);
            if (XFGETS((char*)mqttCtx->rx_buf, MAX_BUFFER_SIZE - 1,
                    stdin) != NULL)
            {
                rc = (int)XSTRLEN((char*)mqttCtx->rx_buf);

                /* Publish Topic */
                mqttCtx->stat = WMQ_PUB;
                XMEMSET(&mqttCtx->publish, 0, sizeof(MqttPublish));
                mqttCtx->publish.retain = 0;
                mqttCtx->publish.qos = mqttCtx->qos;
                mqttCtx->publish.duplicate = 0;
                mqttCtx->publish.topic_name = mqttCtx->topic_name;
                mqttCtx->publish.packet_id = mqtt_get_packetid();
                mqttCtx->publish.buffer = mqttCtx->rx_buf;
                mqttCtx->publish.total_len = (word16)rc;
                rc = MqttClient_Publish(&mqttCtx->client,
                       &mqttCtx->publish);
                PRINTF("MQTT Publish: Topic %s, %s (%d)",
                    mqttCtx->publish.topic_name,
                    MqttClient_ReturnCodeToString(rc), rc);
            }
        }
    #endif
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

    /* Unsubscribe Topics */
    XMEMSET(&mqttCtx->unsubscribe, 0, sizeof(MqttUnsubscribe));
    mqttCtx->unsubscribe.packet_id = mqtt_get_packetid();
    mqttCtx->unsubscribe.topic_count =
        sizeof(mqttCtx->topics) / sizeof(MqttTopic);
    mqttCtx->unsubscribe.topics = mqttCtx->topics;

    /* Unsubscribe Topics */
    rc = MqttClient_Unsubscribe(&mqttCtx->client,
           &mqttCtx->unsubscribe);

    PRINTF("MQTT Unsubscribe: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto disconn;
    }
    mqttCtx->return_code = rc;

disconn:
    /* Disconnect */
    XMEMSET(&mqttCtx->disconnect, 0, sizeof(mqttCtx->disconnect));
#ifdef WOLFMQTT_V5
    {
        /* Session expiry interval */
        MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->disconnect.props);
        prop->type = MQTT_PROP_SESSION_EXPIRY_INTERVAL;
        prop->data_int = 0;
    }
    #if 0 /* enable to test sending a disconnect reason code */
    if (mqttCtx->enable_lwt) {
        /* Disconnect with Will Message */
        mqttCtx->disconnect.reason_code = MQTT_REASON_DISCONNECT_W_WILL_MSG;
    }
    #endif
#endif
    rc = MqttClient_Disconnect_ex(&mqttCtx->client, &mqttCtx->disconnect);
#ifdef WOLFMQTT_V5
    if (mqttCtx->disconnect.props != NULL) {
        /* Release the allocated properties */
        MqttClient_PropsFree(mqttCtx->disconnect.props);
    }
#endif

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
    mqttCtx->qos = DEFAULT_MQTT_QOS;
    mqttCtx->clean_session = 1;
    mqttCtx->keep_alive_sec = DEFAULT_KEEP_ALIVE_SEC;
    mqttCtx->client_id = DEFAULT_CLIENT_ID;
    mqttCtx->topic_name = DEFAULT_TOPIC_NAME;
    mqttCtx->cmd_timeout_ms = DEFAULT_CMD_TIMEOUT_MS;
#ifdef WOLFMQTT_V5
    mqttCtx->max_packet_size = DEFAULT_MAX_PKT_SZ;
    mqttCtx->topic_alias = 1;
    mqttCtx->topic_alias_max = 1;
#endif
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
    blink(20, 1);

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

    rc = mqttClient_test(&mqttCtx);

    mqtt_free_ctx(&mqttCtx);

    cyw43_arch_lwip_end();
    cyw43_arch_deinit();

    printf("Wifi disconnected\n");

}
