#include "esp_blufi_api.h"

int blufi_aes_encrypt(uint8_t iv8, uint8_t *crypt_data, int crypt_len);
int blufi_aes_decrypt(uint8_t iv8, uint8_t *crypt_data, int crypt_len);
uint16_t blufi_crc_checksum(uint8_t iv8, uint8_t *data, int len);

int blufi_security_init(void);
void blufi_security_deinit(void);

typedef void (*simple_blufi_sta_ssid_handler)(void* state, const char* sta_ssid);
typedef void (*simple_blufi_sta_pass_handler)(void* state, const char* sta_pass);
typedef void (*simple_blufi_aux_data_handler)(void* state, const uint8_t* bytes, size_t len);

esp_err_t simple_blufi_server_init(
    void* state,
    simple_blufi_sta_ssid_handler ssid,
    simple_blufi_sta_pass_handler pass,
    simple_blufi_aux_data_handler aux);

void simple_blufi_server_terminate();
