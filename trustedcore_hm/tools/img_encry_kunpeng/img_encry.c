/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: for kunpeng image encrypt.
 * Create: 2020-06-08
 */
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <openssl/pem.h>

#define IMAGE_SIZE             (1024 * 1024 * 10)
#define KEY_LEN                32
#define IV_LEN                 16
#define TAG_LEN                16
#define DOUBLE_KEY_LEN         64
#define DOUBLE_IV_LEN          32
#define RW_FILE_FAIL           (-1)
#define ENC_INIT_FAIL          (-1)
#define CTX_CTRL_FAIL          (-2)
#define ENC_UPD_FAIL           (-3)
#define ENC_FIN_FAIL           (-4)
#define ENC_NEW_FAIL           (-5)
#define ENC_INIT_KEY_IV_FAIL   (-6)
#define ENC_UPD_AAD_FAIL       (-7)
#define CTX_CTRL_TAG_FAIL      (-8)
#define ARG_COUNT              11

static int read_file(const char *file, unsigned char *out, int *out_len)
{
    int size;
    int rc;
    if (file == NULL || out == NULL || out_len == NULL) {
        printf("read file null ptr\n");
        return RW_FILE_FAIL;
    }
    FILE *in = fopen(file, "rb");
    if (in == NULL) {
        printf("open file %s failed!\n", file);
        return RW_FILE_FAIL;
    }
    fseek(in, 0, SEEK_END);
    size = ftell(in);
    if (size == 0 || size > IMAGE_SIZE) {
        printf("file size is invalid!\n");
        fclose(in);
        return RW_FILE_FAIL;
    }

    fseek(in, 0, SEEK_SET);
    rc = fread(out, 1, size, in);
    if (rc != size) {
        printf("read file failed!\n");
        fclose(in);
        return RW_FILE_FAIL;
    }
    *out_len = size;
    fclose(in);
    return 0;
}

static int write_file(const char *file, unsigned char *buf, int len)
{
    if (file == NULL) {
        printf("file is null\n");
        return RW_FILE_FAIL;
    }

    FILE *out = fopen(file, "wb");
    if (out == NULL)
        return RW_FILE_FAIL;

    int write = fwrite(buf, len, 1, out);
    if (write == 0) {
        printf("write file failed!\n");
        fclose(out);
        return RW_FILE_FAIL;
    }
    fclose(out);
    return 0;
}

#define CHAR_CONVERT_BASE 10
static char convert(char c)
{
    if (c >= '0' && c <= '9')
        c = c - '0';
    else
        c = c - 'a' + CHAR_CONVERT_BASE;
    return c;
}

#define HEN_NUM 16
static void hexstr_to_uchar(const char *input, int len, char *output)
{
    int idx = 0;
    int i;
    for (i = 0; i < len; i += 2) { /* need to use 2 char for every cycle */
        char c = convert(input[i]);
        char d = convert(input[i + 1]);
        output[idx] = c * HEN_NUM + d;
        idx++;
    }
}

static int aes_gcm_256_encrypt(const void *plain, int plain_len, const void *aad, int aad_len, const void *key,
                               const void *iv, int iv_len, void *to, void *tag, int taglen)
{
    int count;
    int out_len = plain_len;
    int res = 0;

    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    if (cipher == NULL)
        return ENC_NEW_FAIL;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return ENC_NEW_FAIL;

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) <= 0) {
        res = ENC_INIT_FAIL;
        goto enc_out;
    }
    // set key & iv
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) <= 0) {
        res = CTX_CTRL_FAIL;
        goto enc_out;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, (const unsigned char *)key, (const unsigned char *)iv) <= 0) {
        res = ENC_INIT_KEY_IV_FAIL;
        goto enc_out;
    }

    if (aad != NULL && aad_len > 0) {
        if (EVP_EncryptUpdate (ctx, NULL, &count, (const unsigned char *)aad, aad_len) <= 0) {
            res = ENC_UPD_AAD_FAIL;
            goto enc_out;
        }
    }
    if (EVP_EncryptUpdate(ctx, (unsigned char *)to, &count, (const unsigned char *)plain, out_len) <= 0) {
        res = ENC_UPD_FAIL;
        goto enc_out;
    }

    if (EVP_EncryptFinal_ex(ctx, (unsigned char *)to + out_len, &count) <= 0) {
        res = ENC_FIN_FAIL;
        goto enc_out;
    }

    if (tag != NULL) {
        if (EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_GET_TAG, taglen, tag) <= 0) {
            res = CTX_CTRL_TAG_FAIL;
            goto enc_out;
        }
    }
enc_out:
    EVP_CIPHER_CTX_free(ctx);
    if (res < 0)
        return res;
    return out_len;
}

static bool check_param(int argc, char *argv[])
{
    bool check = ((argc == ARG_COUNT) && (strlen(argv[6]) == DOUBLE_KEY_LEN) && /* argv[6] is aesKey */
                 (strlen(argv[8]) == DOUBLE_IV_LEN)); /* argv[8] is aesRndIV */
    if (!check)
        printf("the param is invalid\n");
    return check;
}

static bool check_path(const char *path)
{
    char real_path[PATH_MAX] = { 0 };
    char *p = realpath(path, real_path);
    if (p == NULL)
        return false;
    return true;
}
int main(int argc, char *argv[])
{
    int ret;
    int img_len = 0;
    if (!check_param(argc, argv))
        return -1;

    unsigned char *img_buf = (unsigned char *)malloc(IMAGE_SIZE);
    if (img_buf == NULL)
        return -1;

    unsigned char *out_buf = (unsigned char *)malloc(IMAGE_SIZE);
    if (out_buf == NULL) {
        free(img_buf);
        return -1;
    }

    char key[KEY_LEN] = { 0 };
    char iv[IV_LEN] = { 0 };
    unsigned char tag[TAG_LEN] = { 0 };

    if (!check_path(argv[2])) /* argv[2] is image_name */
        goto ENC_ERR;
    hexstr_to_uchar(argv[6], DOUBLE_KEY_LEN, key); /* argv[6] is aesKey */
    hexstr_to_uchar(argv[8], DOUBLE_IV_LEN, iv); /* argv[8] is aesRndIV */

    ret = read_file(argv[2], img_buf, &img_len); /* argv[2] is image name */
    if (ret != 0)
        goto ENC_ERR;

    ret = aes_gcm_256_encrypt(img_buf, img_len, NULL, 0, key, iv, IV_LEN, out_buf, tag, sizeof(tag));
    if (ret < 0)
        goto ENC_ERR;

    ret = write_file(argv[4], out_buf, img_len); /* argv[4] is enc_image */
    if (ret < 0)
        goto ENC_ERR;
    ret = write_file(argv[10], tag, sizeof(tag)); /* argv[10] is target file */
    if (ret < 0)
        goto ENC_ERR;

ENC_ERR:
    free(img_buf);
    free(out_buf);
    return 0;
}
