#include "blufi.h"

#include <string.h>

#include "mbedtls/aes.h"
#include "mbedtls/dhm.h"
#include "mbedtls/md5.h"

#include "esp_blufi.h"
#include "esp_blufi_api.h"
#include "esp_bt.h"
#include "esp_check.h"
#include "esp_crc.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_nimble_hci.h"

/* #include "esp_system.h" */
/* #include "esp_wifi.h" */
/* #include "nvs_flash.h" */

#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

#define BLUFI_EXAMPLE_TAG "micro-rdk-blufi"
#define BLUFI_INFO(fmt, ...)   ESP_LOGI(BLUFI_EXAMPLE_TAG, fmt, ##__VA_ARGS__)
#define BLUFI_ERROR(fmt, ...)  ESP_LOGE(BLUFI_EXAMPLE_TAG, fmt, ##__VA_ARGS__)

/*
   The SEC_TYPE_xxx is for self-defined packet data type in the procedure of "BLUFI negotiate key"
   If user use other negotiation procedure to exchange(or generate) key, should redefine the type by yourself.
 */
#define SEC_TYPE_DH_PARAM_LEN   0x00
#define SEC_TYPE_DH_PARAM_DATA  0x01
#define SEC_TYPE_DH_P           0x02
#define SEC_TYPE_DH_G           0x03
#define SEC_TYPE_DH_PUBLIC      0x04


struct blufi_security {
#define DH_SELF_PUB_KEY_LEN     128
#define DH_SELF_PUB_KEY_BIT_LEN (DH_SELF_PUB_KEY_LEN * 8)
    uint8_t  self_public_key[DH_SELF_PUB_KEY_LEN];
#define SHARE_KEY_LEN           128
#define SHARE_KEY_BIT_LEN       (SHARE_KEY_LEN * 8)
    uint8_t  share_key[SHARE_KEY_LEN];
    size_t   share_len;
#define PSK_LEN                 16
    uint8_t  psk[PSK_LEN];
    uint8_t  *dh_param;
    int      dh_param_len;
    uint8_t  iv[16];
    mbedtls_dhm_context dhm;
    mbedtls_aes_context aes;
};
static struct blufi_security *blufi_sec = NULL;

static int myrand( void *rng_state, unsigned char *output, size_t len )
{
    esp_fill_random(output, len);
    return( 0 );
}

// TODO: Should this use `esp_blufi_send_error_info` instead?
extern void btc_blufi_report_error(esp_blufi_error_state_t state);

static void blufi_dh_negotiate_data_handler(uint8_t *data, int len, uint8_t **output_data, int *output_len, bool *need_free)
{
    int ret;
    uint8_t type = data[0];

    if (blufi_sec == NULL) {
        BLUFI_ERROR("BLUFI Security is not initialized");
        btc_blufi_report_error(ESP_BLUFI_INIT_SECURITY_ERROR);
        return;
    }

    switch (type) {
    case SEC_TYPE_DH_PARAM_LEN:
        blufi_sec->dh_param_len = ((data[1]<<8)|data[2]);
        if (blufi_sec->dh_param) {
            free(blufi_sec->dh_param);
            blufi_sec->dh_param = NULL;
        }
        blufi_sec->dh_param = (uint8_t *)malloc(blufi_sec->dh_param_len);
        if (blufi_sec->dh_param == NULL) {
            btc_blufi_report_error(ESP_BLUFI_DH_MALLOC_ERROR);
            BLUFI_ERROR("%s, malloc failed\n", __func__);
            return;
        }
        break;
    case SEC_TYPE_DH_PARAM_DATA:{
        if (blufi_sec->dh_param == NULL) {
            BLUFI_ERROR("%s, blufi_sec->dh_param == NULL\n", __func__);
            btc_blufi_report_error(ESP_BLUFI_DH_PARAM_ERROR);
            return;
        }
        uint8_t *param = blufi_sec->dh_param;
        memcpy(blufi_sec->dh_param, &data[1], blufi_sec->dh_param_len);
        ret = mbedtls_dhm_read_params(&blufi_sec->dhm, &param, &param[blufi_sec->dh_param_len]);
        if (ret) {
            BLUFI_ERROR("%s read param failed %d\n", __func__, ret);
            btc_blufi_report_error(ESP_BLUFI_READ_PARAM_ERROR);
            return;
        }
        free(blufi_sec->dh_param);
        blufi_sec->dh_param = NULL;
        ret = mbedtls_dhm_make_public(&blufi_sec->dhm, (int) mbedtls_mpi_size( &blufi_sec->dhm.P ), blufi_sec->self_public_key, blufi_sec->dhm.len, myrand, NULL);
        if (ret) {
            BLUFI_ERROR("%s make public failed %d\n", __func__, ret);
            btc_blufi_report_error(ESP_BLUFI_MAKE_PUBLIC_ERROR);
            return;
        }

        mbedtls_dhm_calc_secret( &blufi_sec->dhm,
                blufi_sec->share_key,
                SHARE_KEY_BIT_LEN,
                &blufi_sec->share_len,
                NULL, NULL);

        mbedtls_md5(blufi_sec->share_key, blufi_sec->share_len, blufi_sec->psk);

        mbedtls_aes_setkey_enc(&blufi_sec->aes, blufi_sec->psk, 128);

        /* alloc output data */
        *output_data = &blufi_sec->self_public_key[0];
        *output_len = blufi_sec->dhm.len;
        *need_free = false;

    }
        break;
    case SEC_TYPE_DH_P:
        break;
    case SEC_TYPE_DH_G:
        break;
    case SEC_TYPE_DH_PUBLIC:
        break;
    }
}

static int blufi_aes_encrypt(uint8_t iv8, uint8_t *crypt_data, int crypt_len)
{
    int ret;
    size_t iv_offset = 0;
    uint8_t iv0[16];

    memcpy(iv0, blufi_sec->iv, sizeof(blufi_sec->iv));
    iv0[0] = iv8;   /* set iv8 as the iv0[0] */

    ret = mbedtls_aes_crypt_cfb128(&blufi_sec->aes, MBEDTLS_AES_ENCRYPT, crypt_len, &iv_offset, iv0, crypt_data, crypt_data);
    if (ret) {
        return -1;
    }

    return crypt_len;
}

static int blufi_aes_decrypt(uint8_t iv8, uint8_t *crypt_data, int crypt_len)
{
    int ret;
    size_t iv_offset = 0;
    uint8_t iv0[16];

    memcpy(iv0, blufi_sec->iv, sizeof(blufi_sec->iv));
    iv0[0] = iv8;   /* set iv8 as the iv0[0] */

    ret = mbedtls_aes_crypt_cfb128(&blufi_sec->aes, MBEDTLS_AES_DECRYPT, crypt_len, &iv_offset, iv0, crypt_data, crypt_data);
    if (ret) {
        return -1;
    }

    return crypt_len;
}

static uint16_t blufi_crc_checksum(uint8_t iv8, uint8_t *data, int len)
{
    /* This iv8 ignore, not used */
    return esp_crc16_be(0, data, len);
}

static esp_err_t blufi_security_init(void)
{
    blufi_sec = (struct blufi_security *)malloc(sizeof(struct blufi_security));
    if (blufi_sec == NULL) {
        return ESP_FAIL;
    }

    memset(blufi_sec, 0x0, sizeof(struct blufi_security));

    mbedtls_dhm_init(&blufi_sec->dhm);
    mbedtls_aes_init(&blufi_sec->aes);

    memset(blufi_sec->iv, 0x0, 16);
    return 0;
}

static void blufi_security_deinit(void)
{
    if (blufi_sec == NULL) {
        return;
    }
    if (blufi_sec->dh_param){
        free(blufi_sec->dh_param);
        blufi_sec->dh_param = NULL;
    }
    mbedtls_dhm_free(&blufi_sec->dhm);
    mbedtls_aes_free(&blufi_sec->aes);

    memset(blufi_sec, 0x0, sizeof(struct blufi_security));

    free(blufi_sec);
    blufi_sec =  NULL;
}

static void* global_state = NULL;
static simple_blufi_sta_ssid_handler global_sta_ssid_handler = NULL;
static simple_blufi_sta_pass_handler global_sta_pass_handler = NULL;
static simple_blufi_custom_data_handler global_custom_data_handler = NULL;

static void blufi_event_callback(esp_blufi_cb_event_t event, esp_blufi_cb_param_t *param) {
  switch (event) {
  case ESP_BLUFI_EVENT_INIT_FINISH:
    BLUFI_INFO("BLUFI init finish\n");
    esp_blufi_adv_start();
    break;
  case ESP_BLUFI_EVENT_DEINIT_FINISH:
    BLUFI_INFO("BLUFI deinit finish\n");
    break;
  case ESP_BLUFI_EVENT_BLE_CONNECT:
    BLUFI_INFO("BLUFI ble connect\n");
    esp_blufi_adv_stop();
    blufi_security_init();
    break;
  case ESP_BLUFI_EVENT_BLE_DISCONNECT:
    BLUFI_INFO("BLUFI ble disconnect\n");
    blufi_security_deinit();
    esp_blufi_adv_start();
    break;
  case ESP_BLUFI_EVENT_RECV_STA_SSID:
    BLUFI_INFO("Recv STA SSID %d bytes\n", param->sta_ssid.ssid_len);
    esp_log_buffer_hex("Password hex bytes", param->sta_ssid.ssid, param->sta_ssid.ssid_len);
    if (global_sta_ssid_handler)
      global_sta_ssid_handler(global_state, param->sta_ssid.ssid, param->sta_ssid.ssid_len);
    break;
  case ESP_BLUFI_EVENT_RECV_STA_PASSWD:
    BLUFI_INFO("Recv STA PASSWORD %d bytes\n", param->sta_passwd.passwd_len);
    esp_log_buffer_hex("Password hex bytes", param->sta_passwd.passwd, param->sta_passwd.passwd_len);
    if (global_sta_pass_handler)
      global_sta_pass_handler(global_state, param->sta_passwd.passwd, param->sta_passwd.passwd_len);
    break;
  case ESP_BLUFI_EVENT_RECV_CUSTOM_DATA:
    BLUFI_INFO("Recv Custom Data %d bytes\n", param->custom_data.data_len);
    esp_log_buffer_hex("Custom Data hex bytes", param->custom_data.data, param->custom_data.data_len);
    if (global_custom_data_handler)
      global_custom_data_handler(global_state, param->custom_data.data, param->custom_data.data_len);
    break;
  default:
    break;
  }
}

static void blufi_on_sync(void) {
  esp_blufi_profile_init();
}

static void blufi_on_reset(int reason) {
}

static void blufi_server_task(void *param) {
    BLUFI_INFO("BLE Host Task Started");
    /* This function will return only when nimble_port_stop() is executed */
    nimble_port_run();
    nimble_port_freertos_deinit();
}

#define CHECK(x) { int ret = x; if (ret != ESP_OK) return ret; }

esp_err_t simple_blufi_server_init(
    void* state,
    simple_blufi_sta_ssid_handler ssid,
    simple_blufi_sta_pass_handler pass,
    simple_blufi_custom_data_handler custom) {

  CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));

  esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
  CHECK(esp_bt_controller_init(&bt_cfg));
  CHECK(esp_bt_controller_enable(ESP_BT_MODE_BLE));

  esp_blufi_callbacks_t blufi_callbacks = {
    .event_cb = blufi_event_callback,
    .negotiate_data_handler = blufi_dh_negotiate_data_handler,
    .encrypt_func = blufi_aes_encrypt,
    .decrypt_func = blufi_aes_decrypt,
    .checksum_func = blufi_crc_checksum,
  };

  CHECK(esp_blufi_register_callbacks(&blufi_callbacks));

  CHECK(esp_nimble_hci_init());
  nimble_port_init();

  /* Initialize the NimBLE host configuration. */
  ble_hs_cfg.reset_cb = blufi_on_reset;
  ble_hs_cfg.sync_cb = blufi_on_sync;
  ble_hs_cfg.gatts_register_cb = esp_blufi_gatt_svr_register_cb;
  ble_hs_cfg.store_status_cb = ble_store_util_status_rr;
  ble_hs_cfg.sm_io_cap = 4;
  ble_hs_cfg.sm_mitm = 1;
  ble_hs_cfg.sm_sc = 1;

  int rc = esp_blufi_gatt_svr_init();
  assert(rc == 0);

  /* Set the default device name. */
  rc = ble_svc_gap_device_name_set(BLUFI_DEVICE_NAME);
  assert(rc == 0);

  esp_blufi_btc_init();

  global_state = state;
  global_sta_ssid_handler = ssid;
  global_sta_pass_handler = pass;
  global_custom_data_handler = custom;

  nimble_port_freertos_init(blufi_server_task);

  return ESP_OK;
}

void simple_blufi_server_terminate() {
  int ret = nimble_port_stop();
  if (ret == 0) {

    global_sta_ssid_handler = NULL;
    global_sta_pass_handler = NULL;
    global_custom_data_handler = NULL;
    global_state = NULL;

    nimble_port_deinit();

    ret = esp_nimble_hci_and_controller_deinit();
    if (ret != ESP_OK) {
      BLUFI_ERROR("esp_nimble_hci_and_controller_deinit() failed with error: %d", ret);
    }
  }
}
