## Getting Started

This example includes wolfSSL test, benchmark, Wifi, TCP/TLS client and wolfMQTT client.


### 1. Download files

```
# git clone https://github.com/wolfssl-jp/RPi-pico-w
$ git clone https://github.com/raspberrypi/pico-sdk
$ git clone https://github.com/raspberrypi/pico-examples
$ git clone https://github.com/wolfssl/wolfssl
$ git clone https://github.com/wolfSSL/wolfMQTT
```

### 2. Define path

```
$ export PICO_WOLF_PATH=/your/RPi-pico-w/path
$ export PICO_SDK_PATH=/your/pico-sdk/path
$ export PICO_EXAMPLES_PATH=/your/pico-examples/path
$ export WOLFSSL_ROOT=/your/wolfssl-root/path
```

### 3. cmake and make

```
$ cd $PICO_SDK_PATH
$ git submodule update --init
$ cd $PICO_WOLF_PATH
$ ln -s $PICO_EXAMPLES_PATH/pico_extras_import_optional.cmake pico_extras_import_optional.cmake
$ ln -s $PICO_EXAMPLES_PATH/pico_sdk_import.cmake pico_sdk_import.cmake
$ mkdir build
$ cd build
$ cmake -DPICO_BOARD=pico_w -DWIFI_SSID="wifi-ssid" -DWIFI_PASSWORD="wifi-password" \
-DTEST_TCP_SERVER_IP="ip-addr" ..
$ make 
```

### 4. Target files

- testwolfcrypt.uf2
- benchmark.uf2
- wifi.uf2
- tcp_Client.uf2
- tls_Client.uf2
- mqtt_Client.uf2
- mqttSubscribe_picoLED.uf2

Console output is to USB serial

[tiny-json](https://github.com/rafagafe/tiny-json): This project uses an external JSON parser called tiny-json. tiny-json is distributed under the MIT License.

### References

- Raspberry Pi Pico and Pico W<br>
https://www.raspberrypi.com/documentation/microcontrollers/raspberry-pi-pico.html

- Connecting to the Internet with Raspberry Pi Pico W<br>
https://datasheets.raspberrypi.com/picow/connecting-to-the-internet-with-pico-w.pdf
