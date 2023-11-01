
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


#include "wolfmqtt/mqtt_client.h"
#include "examples/mqttport.h"
#include "examples/mqttnet.h"
#include "examples/mqttexample.h"

#include "wolf/test_mosquitto_cert.h"

#define MAX_BUFFER_SIZE 1024
#define TEST_MOSQUITTO_ORG_IP "91.121.93.94"
#ifdef ENABLE_MQTT_TLS
#define MQTT_BROKER_PORT 8883
#else 
#define MQTT_BROKER_PORT 1883
#endif /* ENABLE_MQTT_TLS */

/* locals */
static volatile word16 mPacketIdLast;
static const char* kDefTopicName = DEFAULT_TOPIC_NAME;
static const char* kDefClientId =  DEFAULT_CLIENT_ID;

/* argument parsing */
static int myoptind = 0;
static char* myoptarg = NULL;

#ifdef ENABLE_MQTT_TLS
static const char* mTlsCaFile;
static const char* mTlsCertFile;
static const char* mTlsKeyFile;
#ifdef HAVE_SNI
static int useSNI;
static const char* mTlsSniHostName;
#endif
#ifdef HAVE_PQC
static const char* mTlsPQAlg;
#endif
#endif /* ENABLE_MQTT_TLS */



/* used for testing only, requires wolfSSL RNG */
#ifdef ENABLE_MQTT_TLS
#include <wolfssl/wolfcrypt/random.h>
#endif

static int mqtt_get_rand(byte* data, word32 len)
{
    int ret = -1;
#ifdef ENABLE_MQTT_TLS
    WC_RNG rng;
    ret = wc_InitRng(&rng);
    if (ret == 0) {
        ret = wc_RNG_GenerateBlock(&rng, data, len);
        wc_FreeRng(&rng);
    }
#elif defined(HAVE_RAND)
    word32 i;
    for (i = 0; i<len; i++) {
        data[i] = (byte)rand();
    }
#endif
    return ret;
}

#ifndef TEST_RAND_SZ
#define TEST_RAND_SZ 4
#endif
static char* mqtt_append_random(const char* inStr, word32 inLen)
{
    int rc;
    const char kHexChar[] = { '0', '1', '2', '3', '4', '5', '6', '7',
                              '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    byte rndBytes[TEST_RAND_SZ], rndHexStr[TEST_RAND_SZ*2];
    char *tmp = NULL;

    rc = mqtt_get_rand(rndBytes, (word32)sizeof(rndBytes));
    if (rc == 0) {
        /* Convert random to hex string */
        int i;
        for (i=0; i<(int)sizeof(rndBytes); i++) {
            byte in = rndBytes[i];
            rndHexStr[(i*2)] =   kHexChar[in >> 4];
            rndHexStr[(i*2)+1] = kHexChar[in & 0xf];
        }
    }
    if (rc == 0) {
        /* Allocate topic name and client id */
        tmp = (char*)WOLFMQTT_MALLOC(inLen + 1 + sizeof(rndHexStr) + 1);
        if (tmp == NULL) {
            rc = MQTT_CODE_ERROR_MEMORY;
        }
    }
    if (rc == 0) {
        /* Format: inStr + `_` randhex + null term */
        XMEMCPY(tmp, inStr, inLen);
        tmp[inLen] = '_';
        XMEMCPY(tmp + inLen + 1, rndHexStr, sizeof(rndHexStr));
        tmp[inLen + 1 + sizeof(rndHexStr)] = '\0';
    }
    return tmp;
}



void mqtt_init_ctx(MQTTCtx* mqttCtx)
{
    XMEMSET(mqttCtx, 0, sizeof(MQTTCtx));
    mqttCtx->host = DEFAULT_MQTT_HOST;
    mqttCtx->qos = DEFAULT_MQTT_QOS;
    mqttCtx->clean_session = 1;
    mqttCtx->keep_alive_sec = DEFAULT_KEEP_ALIVE_SEC;
    mqttCtx->client_id = kDefClientId;
    mqttCtx->topic_name = kDefTopicName;
    mqttCtx->cmd_timeout_ms = DEFAULT_CMD_TIMEOUT_MS;
#ifdef WOLFMQTT_V5
    mqttCtx->max_packet_size = DEFAULT_MAX_PKT_SZ;
    mqttCtx->topic_alias = 1;
    mqttCtx->topic_alias_max = 1;
#endif
#ifdef WOLFMQTT_DEFAULT_TLS
    mqttCtx->use_tls = WOLFMQTT_DEFAULT_TLS;
#endif
    mqttCtx->app_name = "mqttclient";
    mqttCtx->message = DEFAULT_MESSAGE;
}


void mqtt_free_ctx(MQTTCtx* mqttCtx)
{
    if (mqttCtx == NULL) {
        return;
    }

    if (mqttCtx->dynamicTopic && mqttCtx->topic_name) {
        WOLFMQTT_FREE((char*)mqttCtx->topic_name);
        mqttCtx->topic_name = NULL;
    }
    if (mqttCtx->dynamicClientId && mqttCtx->client_id) {
        WOLFMQTT_FREE((char*)mqttCtx->client_id);
        mqttCtx->client_id = NULL;
    }
}

#if defined(__GNUC__) && !defined(NO_EXIT) && !defined(WOLFMQTT_ZEPHYR)
    __attribute__ ((noreturn))
#endif
int err_sys(const char* msg)
{
    if (msg) {
        PRINTF("wolfMQTT error: %s", msg);
    }
    exit(EXIT_FAILURE);
#ifdef WOLFMQTT_ZEPHYR
    /* Zephyr compiler produces below warning. Let's silence it.
     * warning: 'noreturn' function does return
     * 477 | }
     *     | ^
     */
    return 0;
#endif
}


word16 mqtt_get_packetid(void)
{
    /* Check rollover */
    if (mPacketIdLast >= MAX_PACKET_ID) {
        mPacketIdLast = 0;
    }

    return ++mPacketIdLast;
}

#ifdef WOLFMQTT_NONBLOCK
#if defined(MICROCHIP_MPLAB_HARMONY)
    #include <system/tmr/sys_tmr.h>
#else
    #include <time.h>
#endif

static word32 mqtt_get_timer_seconds(void)
{
    word32 timer_sec = 0;

#if defined(MICROCHIP_MPLAB_HARMONY)
    timer_sec = (word32)(SYS_TMR_TickCountGet() /
            SYS_TMR_TickCounterFrequencyGet());
#else
    /* Posix style time */
    timer_sec = (word32)time(0);
#endif

    return timer_sec;
}

int mqtt_check_timeout(int rc, word32* start_sec, word32 timeout_sec)
{
    word32 elapsed_sec;

    /* if start seconds not set or is not continue */
    if (*start_sec == 0 || rc != MQTT_CODE_CONTINUE) {
        *start_sec = mqtt_get_timer_seconds();
        return rc;
    }

    elapsed_sec = mqtt_get_timer_seconds();
    if (*start_sec < elapsed_sec) {
        elapsed_sec -= *start_sec;
        if (elapsed_sec >= timeout_sec) {
            *start_sec = mqtt_get_timer_seconds();
            PRINTF("Timeout timer %d seconds", timeout_sec);
            return MQTT_CODE_ERROR_TIMEOUT;
        }
    }

    return rc;
}
#endif /* WOLFMQTT_NONBLOCK */


#ifdef ENABLE_MQTT_TLS

#ifdef WOLFSSL_ENCRYPTED_KEYS
int mqtt_password_cb(char* passwd, int sz, int rw, void* userdata)
{
    (void)rw;
    (void)userdata;
    if (userdata != NULL) {
        XSTRNCPY(passwd, (char*)userdata, sz);
        return (int)XSTRLEN((char*)userdata);
    }
    else {
        XSTRNCPY(passwd, "yassl123", sz);
        return (int)XSTRLEN(passwd);
    }
}
#endif

static int mqtt_tls_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    char buffer[WOLFSSL_MAX_ERROR_SZ];
    MQTTCtx *mqttCtx = NULL;
    char appName[PRINT_BUFFER_SIZE] = {0};

    if (store->userCtx != NULL) {
        /* The client.ctx was stored during MqttSocket_Connect. */
        mqttCtx = (MQTTCtx *)store->userCtx;
        XSTRNCPY(appName, " for ", PRINT_BUFFER_SIZE-1);
        XSTRNCAT(appName, mqttCtx->app_name,
                PRINT_BUFFER_SIZE-XSTRLEN(appName)-1);
    }

    PRINTF("MQTT TLS Verify Callback%s: PreVerify %d, Error %d (%s)",
            appName, preverify,
            store->error, store->error != 0 ?
                    wolfSSL_ERR_error_string(store->error, buffer) : "none");
    PRINTF("  Subject's domain name is %s", store->domain);

    if (store->error != 0) {
        /* Allowing to continue */
        /* Should check certificate and return 0 if not okay */
        PRINTF("  Allowing cert anyways");
    }

    return 1;
}

/* Use this callback to setup TLS certificates and verify callbacks */
int mqtt_tls_cb(MqttClient* client)
{
    int rc = WOLFSSL_FAILURE;
    int ret;

    /* Use highest available and allow downgrade. If wolfSSL is built with
     * old TLS support, it is possible for a server to force a downgrade to
     * an insecure version. */
    if ((client->tls.ctx = wolfSSL_CTX_new((wolfTLSv1_2_client_method()))) == NULL) {
        printf("ERROR:wolfSSL_CTX_new()\n");
        return WOLF_FAIL;
    }

    if (client->tls.ctx) {
        wolfSSL_CTX_set_verify(client->tls.ctx, WOLFSSL_VERIFY_PEER,
                mqtt_tls_verify_cb);

        /* default to success */
        rc = WOLFSSL_SUCCESS;
    }
#if !defined(NO_CERT)
    /* Load client certificates into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_load_verify_buffer(client->tls.ctx, test_mosquitto_org_der_2048,
            sizeof_test_mosquitto_org_der_2048, SSL_FILETYPE_ASN1)) != WOLFSSL_SUCCESS) {
        printf("ERROR: failed to load CA cert. %d\n", ret);
        return  WOLF_FAIL;
    }
#endif /* !NO_CERT */


    PRINTF("MQTT TLS Setup (%d)", rc);

    return rc;
}

#else 
int mqtt_tls_cb(MqttClient* client)
{}
#endif /* ENABLE_MQTT_TLS */

int mqtt_file_load(const char* filePath, byte** fileBuf, int *fileLen)
{
#if !defined(NO_FILESYSTEM)
    int rc = 0;
    XFILE file = NULL;
    long int pos = -1L;

    /* Check arguments */
    if (filePath == NULL || XSTRLEN(filePath) == 0 || fileLen == NULL ||
        fileBuf == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Open file */
    file = XFOPEN(filePath, "rb");
    if (file == NULL) {
        PRINTF("File '%s' does not exist!", filePath);
        rc = EXIT_FAILURE;
        goto exit;
    }

    /* Determine length of file */
    if (XFSEEK(file, 0, XSEEK_END) != 0) {
        PRINTF("fseek() failed");
        rc = EXIT_FAILURE;
        goto exit;
     }

    pos = (int)XFTELL(file);
    if (pos == -1L) {
       PRINTF("ftell() failed");
       rc = EXIT_FAILURE;
       goto exit;
    }

    *fileLen = (int)pos;
    if (XFSEEK(file, 0, XSEEK_SET) != 0) {
        PRINTF("fseek() failed");
        rc = EXIT_FAILURE;
        goto exit;
     }
#ifdef DEBUG_WOLFMQTT
    PRINTF("File %s is %d bytes", filePath, *fileLen);
#endif

    /* Allocate buffer for image */
    *fileBuf = (byte*)WOLFMQTT_MALLOC(*fileLen);
    if (*fileBuf == NULL) {
        PRINTF("File buffer malloc failed!");
        rc = MQTT_CODE_ERROR_MEMORY;
        goto exit;
    }

    /* Load file into buffer */
    rc = (int)XFREAD(*fileBuf, 1, *fileLen, file);
    if (rc != *fileLen) {
        PRINTF("Error reading file! %d", rc);
        rc = EXIT_FAILURE;
        goto exit;
    }
    rc = 0; /* Success */

exit:
    if (file) {
        XFCLOSE(file);
    }
    if (rc != 0) {
        if (*fileBuf) {
            WOLFMQTT_FREE(*fileBuf);
            *fileBuf = NULL;
        }
    }
    return rc;

#else
    (void)filePath;
    (void)fileBuf;
    (void)fileLen;
    PRINTF("File system support is not configured.");
    return EXIT_FAILURE;
#endif
}






static int NetConnect(void *context, const char* host, word16 port,
    int timeout_ms)
{

    SocketContext *sock = (SocketContext*)context;


    memset(&sock->addr, 0, sizeof(sock->addr));
    sock->addr.sin_family = AF_INET;           /* using IPv4      */
    sock->addr.sin_port = htons(MQTT_BROKER_PORT); /* on DEFAULT_PORT */
    printf("NetConnect: Host %s, Port %u, Timeout %d ms, Use TLS %d\n",
            host, port, timeout_ms, sock->mqttCtx->use_tls);

    if (inet_pton(AF_INET, TEST_MOSQUITTO_ORG_IP, &(sock->addr).sin_addr) != 1) {
        fprintf(stderr, "ERROR: invalid address\n");
        return WOLF_FAIL;
    }
    
    sock->fd = socket();
    if (!sock->fd)
    {
        printf("ERROR:wolf_TCPsocket()\n");
        return WOLF_FAIL;
    }

    if (connect(sock->fd,(struct sockaddr*) &sock->addr, sizeof(&sock->addr)) != WOLF_SUCCESS) {
        printf("ERROR:wolf_TCPconnect()\n");
        return WOLF_FAIL;
    }

    sock->stat = SOCK_CONN;

    return WOLF_SUCCESS;

}


static int NetRead(void *context, byte* buf, int buf_len,
    int timeout_ms)
{   
    unsigned long ret;
    SocketContext *sock = (SocketContext*)context;

    ret = recv(sock->fd, buf, buf_len);
    return ret;
}

static int NetWrite(void *context, const byte* buf, int buf_len,
    int timeout_ms)
{
    unsigned long ret;
    SocketContext *sock = (SocketContext*)context;
    ret = send(sock->fd, buf, buf_len);
    return ret;
}
static int NetDisconnect(void *context)
{
    unsigned long ret;
    SocketContext *sock = (SocketContext*)context;
    if(sock->fd) {
        free(sock->fd);              /* Close the connection to the server   */
        sock->stat = SOCK_BEGIN;

    }
    return 0;
}



int MqttClientNet_Init(MqttNet* net, MQTTCtx* mqttCtx)
{
    if (net) {
        SocketContext* sockCtx;
        XMEMSET(net, 0, sizeof(MqttNet));
        net->connect = NetConnect;
        net->read = NetRead;
        net->write = NetWrite;
        net->disconnect = NetDisconnect;
        
        sockCtx = (SocketContext*)WOLFMQTT_MALLOC(sizeof(SocketContext));
        if (sockCtx == NULL) {
            return MQTT_CODE_ERROR_MEMORY;
        }
        net->context = sockCtx;
        XMEMSET(sockCtx, 0, sizeof(SocketContext));
        sockCtx->fd = SOCKET_INVALID;
        sockCtx->stat = SOCK_BEGIN;
        sockCtx->mqttCtx = mqttCtx;

        
    }
    return MQTT_CODE_SUCCESS;
}

int MqttClientNet_DeInit(MqttNet* net)
{
    if (net) {
        if (net->context) {
            WOLFMQTT_FREE(net->context);
        }
        XMEMSET(net, 0, sizeof(MqttNet));
    }
    return 0;
}
