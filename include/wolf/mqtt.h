/* mqtt.h
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




// #include "wolf/userio_templete.h"
#include "wolfmqtt/mqtt_client.h"
#include "examples/mqttport.h"
#include "examples/mqttnet.h"
#include "examples/mqttexample.h"

static int mqtt_get_rand(byte* data, word32 len);
static char* mqtt_append_random(const char* inStr, word32 inLen);
void mqtt_init_ctx(MQTTCtx* mqttCtx);
void mqtt_free_ctx(MQTTCtx* mqttCtx);
int err_sys(const char* msg);
word16 mqtt_get_packetid(void);

#ifdef ENABLE_MQTT_TLS
static int mqtt_tls_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store);
int mqtt_tls_cb(MqttClient* client);
#endif

static int NetConnect(void *context, const char* host, word16 port,
    int timeout_ms);
static int NetRead(void *context, byte* buf, int buf_len,
    int timeout_ms);
static int NetWrite(void *context, const byte* buf, int buf_len,
    int timeout_ms);
static int NetDisconnect(void *context);

int MqttClientNet_Init(MqttNet* net, MQTTCtx* mqttCtx);
int MqttClientNet_DeInit(MqttNet* net);
