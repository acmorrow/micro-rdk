#include "esp_blufi_api.h"

typedef void (*simple_blufi_sta_ssid_handler)(void* state, const uint8_t* sta_ssid, size_t len);
typedef void (*simple_blufi_sta_pass_handler)(void* state, const uint8_t* sta_pass, size_t len);
typedef void (*simple_blufi_custom_data_handler)(void* state, const uint8_t* data, size_t len);

esp_err_t simple_blufi_server_init(
    void* state,
    simple_blufi_sta_ssid_handler ssid,
    simple_blufi_sta_pass_handler pass,
    simple_blufi_custom_data_handler custom);

void simple_blufi_server_terminate();
