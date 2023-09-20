# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/Users/rocksonqwerty/dev/pico/pico-sdk/tools/pioasm"
  "/Users/rocksonqwerty/dev-intern/RPi-pico-w/build/pioasm"
  "/Users/rocksonqwerty/dev-intern/RPi-pico-w/build/pico-sdk/src/rp2_common/pico_cyw43_driver/pioasm"
  "/Users/rocksonqwerty/dev-intern/RPi-pico-w/build/pico-sdk/src/rp2_common/pico_cyw43_driver/pioasm/tmp"
  "/Users/rocksonqwerty/dev-intern/RPi-pico-w/build/pico-sdk/src/rp2_common/pico_cyw43_driver/pioasm/src/PioasmBuild-stamp"
  "/Users/rocksonqwerty/dev-intern/RPi-pico-w/build/pico-sdk/src/rp2_common/pico_cyw43_driver/pioasm/src"
  "/Users/rocksonqwerty/dev-intern/RPi-pico-w/build/pico-sdk/src/rp2_common/pico_cyw43_driver/pioasm/src/PioasmBuild-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/Users/rocksonqwerty/dev-intern/RPi-pico-w/build/pico-sdk/src/rp2_common/pico_cyw43_driver/pioasm/src/PioasmBuild-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/Users/rocksonqwerty/dev-intern/RPi-pico-w/build/pico-sdk/src/rp2_common/pico_cyw43_driver/pioasm/src/PioasmBuild-stamp${cfgdir}") # cfgdir has leading slash
endif()
