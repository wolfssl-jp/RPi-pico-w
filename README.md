## Getting Started

This example includes wolfSSL test, benchmark, Wifi, TCP/TLS client.


### 1. Download files

```
# git clone https://github.com/wolfssl-jp/RPi-pico-w
$ git clone https://github.com/raspberrypi/pico-sdk
$ git clone https://github.com/raspberrypi/pico-examples
$ git clone https://github.com/wolfssl/wolfssl
```

### 2. Define path

```
$ export PICO_SDK_PATH=/your/pico-sdk/path
$ export PICO_EXAMPLES_PATH=/your/pico-examples/path
$ export WOLFSSL_ROOT=/your/wolfssl-root/path
```

### 3. cmake and make

```
$ cd wolfssl-examples/RPi-Pico
$ mkdir build
$ cd build
$ cmake -DPICO_BOARD=pico_w -DWIFI_SSID="wifi-ssid" -DWIFI_PASSWORD="wifi-password"
-DTEST_TCP_SERVER_IP="ip-addr" ..
$ make
```

### 4. Target files

- testwolfcrypt.uf2
- benchmark.uf2
- wifi.uf2
- tcp_Client.uf2
- tls_Client.uf2

Console output is to USB serial

### References

- Raspberry Pi Pico and Pico W<br>
https://www.raspberrypi.com/documentation/microcontrollers/raspberry-pi-pico.html

- Connecting to the Internet with Raspberry Pi Pico W<br>
https://datasheets.raspberrypi.com/picow/connecting-to-the-internet-with-pico-w.pdf
