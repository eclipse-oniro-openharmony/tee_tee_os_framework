/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Root of Trust public function
 * Author: t00360454
 * Create: 2020-02-11
 */
#ifndef _ROOT_OF_TRUST_PUBLIC_H_
#define _ROOT_OF_TRUST_PUBLIC_H_
#include <tee_internal_api.h>

#define WEAK __attribute__((weak))
typedef void (*func_ptr)(void);
/* the num rot ipc cmd should begin 0x7100 */
enum ROT_IPC_MSG_CMD {
    ROT_MSG_EXT_SEND_CMD = 0x7100,
};

struct memref_in {
    uint32_t size;
    uint8_t *buffer;
};

struct memref_out {
    uint32_t *size;
    uint8_t *buffer;
};

struct algo_modes {
    uint32_t mode;
    uint32_t padding;
};

/*
 * @brief    : Store Device IDs.
 * @param[in]: ids, the device's IDs info to be stored.
 * @return   : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTStoreID(const struct memref_in *ids);

/*
 * @brief    : Verify the Device IDs.
 * @param[in]: ids, the device's IDs info to be stored.
 * @return   : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTVerifyID(const struct memref_in *ids);

/*
 * @brief     : Generate App Key.
 * @param[in] : parameters, key information, data is arranged in big-endian mode.
 *              see structure key_params for details.
 * @param[out]: blob_handle, the buffer of apdu response data.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTGenerateAppKey(const struct memref_in *params, struct memref_out *blob_handle);

/*
 * @brief     : Generate Key.
 * @param[in] : parameters, key information, data is arranged in big-endian mode.
 *              see structure key_params for details.
 * @param[out]: blob_handle, the buffer of apdu response data.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTGenerateKey(const struct memref_in *params, struct memref_out *blob_handle);

/*
 * @brief     : Import Key and Certs.
 * @param[in] : parameters, key information, data is arranged in big-endian mode.
 *              see structure key_params for details.
 * @param[in] : cert, standard X.509 Certs.
 * @param[out]: blob_handle, the buffer of apdu response data.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTImportKey(const struct memref_in *params, const struct memref_in *cert,
                                struct memref_out *blob_handle);

/*
 * @brief     : Export Public Key.
 * @param[in] : blob_handle, the handle of key information.
 * @param[out]: pub_key, public key.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTExportKey(const struct memref_in *blob_handle, struct memref_out *pub_key);

/*
 * @brief     : Export Certs.
 * @param[in] : blob_handle, the handle of key information.
 * @param[out]: cert, standard X.509 Certs.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTExportCert(const struct memref_in *blob_handle, struct memref_out *cert);

/*
 * @brief     : Generate signature.
 * @param[in] : blob_handle, the handle of key information.
 * @param[in] : mode, the calc mode for signed.
 * @param[in] : digest, the digest data to be signed.
 * @param[out]: out_data, the signature buffer.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTSign(const struct memref_in *blob_handle, uint32_t mode, const struct memref_in *digest,
                           struct memref_out *out_data);

/*
 * @brief     : Verifies the signature.
 * @param[in] : blob_handle, the handle of key information.
 * @param[in] : mode, the clac mode for verified.
 * @param[in] : digest, the digest data to be verified.
 * @param[out]: signature, the signature data.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTVerify(const struct memref_in *blob_handle, uint32_t mode, const struct memref_in *digest,
                             const struct memref_in *signature);

/*
 * @brief     : Generate MAC.
 * @param[in] : blob_handle, the handle of key information.
 * @param[in] : mode_params, the clac mode and padding mode for MACed.
 * @param[in] : data, the message data to be MACed.
 * @param[in] : iv, the init vector data.
 * @param[out]: mac, the output buffer.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTComputeMAC(const struct memref_in *blob_handle, const struct algo_modes *mode_params,
                                 const struct memref_in *data, const struct memref_in *iv, struct memref_out *mac);

/*
 * @brief     : Genearte MAC and compare the MAC.
 * @param[in] : blob_handle, the handle of key information.
 * @param[in] : mode_params, the clac mode and padding mode for MACed.
 * @param[in] : data, the message data to be MACed.
 * @param[in] : iv, the init vector data.
 * @param[in] : mac, the input MAC to be compared.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTCompareMAC(const struct memref_in *blob_handle, const struct algo_modes *mode_params,
                                 const struct memref_in *data, const struct memref_in *iv, const struct memref_in *mac);

/*
 * @brief     : symmetric or asymmetric cipher Encryption.
 * @param[in] : blob_handle, the handle of key information.
 * @param[in] : mode_params, the clac mode and padding mode for Cipher, padding mode used only for symmetric algo.
 * @param[in] : in_data, the message data to be Encrypted.
 * @param[in] : iv, the init vector data, ignored for asymmetric algo.
 * @param[out]: out_data, the output buffer.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTEncrypt(const struct memref_in *blob_handle, const struct algo_modes *mode_params,
                              const struct memref_in *in_data, const struct memref_in *iv, struct memref_out *out_data);

/*
 * @brief     : symmetric or asymmetric cipher Decryption.
 * @param[in] : blob_handle, the handle of key information.
 * @param[in] : mode_params, the clac mode and padding mode for Cipher, padding mode used only for symmetric algo.
 * @param[in] : in_data, the message data to be Encrypted.
 * @param[in] : iv, the init vector data, ignored for asymmetric algo.
 * @param[out]: out_data, the output buffer.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTDecrypt(const struct memref_in *blob_handle, const struct algo_modes *mode_params,
                              const struct memref_in *in_data, const struct memref_in *iv, struct memref_out *out_data);

/*
 * @brief     : Get the Certs Exist or not.
 * @param[in] : blob_handle, the handle of key information.
 * @return    : exist if TEE_SUCCESS, non-exist if others.
 */
TEE_Result TEE_EXT_ROTCertExist(const struct memref_in *blob_handle);

/*
 * @brief     : Key Attestion or ID Attestion.
 * @param[in] : blob_handle, the handle of key information.
 * @param[in] : auth_list, extensions data.
 * @param[in] : ids, device ids, ignored for Key Attest.
 * @param[out]: cert_chain, the output buffer.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTAttestKey(const struct memref_in *blob_handle, const struct memref_in *auth_list,
                                const struct memref_in *ids, struct memref_out *cert_chain);

/*
 * @brief     : Get Key Blob Handle.
 * @param[in] : key_type, key type, such as RSA/ECC/AES.
 * @param[out]: blob_handle, the buffer of apdu response data.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTGetBlobHandle(uint32_t key_type, struct memref_out *blob_handle);

#endif
