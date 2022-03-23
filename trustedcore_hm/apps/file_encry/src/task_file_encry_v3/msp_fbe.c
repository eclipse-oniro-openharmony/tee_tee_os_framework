/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: TEE TA FBE -> MSP SA FBE communication API.
 * Create: 2020-01-20
 */

#include "msp_fbe.h"
#include "tee_common.h"
#include "string.h"
#include "tee_internal_se_api.h"
#include "tee_log.h"
#include "securec.h"
#ifdef MSP_FBE_DYNAMIC_LOAD
#include "msp_tee_se_ext_api.h"
#endif /* MSP_FBE_DYNAMIC_LOAD */

#define TEE_MAX_READER_NUM         16
#define TEE_MAX_READER_NAME_LEN    16

#define TEE_MSP_READER_NAME        "msp"
#define MSP_MAX_READER_LEN         16
#define BLOCK_SIZE                 16
#define MSP_LENGTH_TA_UUID         16
#define MSP_SAID_LENGTH            16

#define MSP_STATUS(mod, sub_err)   ((mod) | (sub_err))

#define MSP_APDU_S_PREFIX          0xF00F0000
#define MSP_PREFIX                 0x62500000
#define MSP_OP_SA_LOAD_INSTALL     (MSP_PREFIX | 0x00000100)
#define MSP_OP_INQUIRY             (MSP_PREFIX | 0x00000200)
#define MSP_OP_STORE               (MSP_PREFIX | 0x00000300)
#define MSP_OP_FETCH               (MSP_PREFIX | 0x00000400)
#define MSP_OP_FETCH_ENHANCE       (MSP_PREFIX | 0x00000500)
#define MSP_OP_DELETE              (MSP_PREFIX | 0x00000600)
#define MSP_OP_RESET               (MSP_PREFIX | 0x00000700)
#define MSP_OP_PREFETCH            (MSP_PREFIX | 0x00000800)
#define MSP_OP_TRY                 (MSP_PREFIX | 0x00000900)

#define MSP_NULL_POINTER           0x00000001
#define MSP_INVALID_LENGTH         0x00000002
#define MSP_APDU_CMD_NOT_ENOUGH    0x00000004
#define MSP_APDU_RSP_INCOMPLETE    0x00000006
#define MSP_APDU_RSP_WRONG_TAG     0x00000007
#define MSP_APDU_RSP_WRONG_LENGTH  0x00000008
#define MSP_INVALID_FILE_TYPE      0x00000009
#define MSP_MMCPY_FAIL             0x0000000A

#define MSP_APDU_HEADER_LENGTH     0x5
#define MSP_APDU_OFFSET_LC         0x4
#define MSP_APDU_LENGTH_SW         2
#define MSP_APDU_CLA               0x0
#define MSP_APDU_SW_SUCCESS        0x9000

#define MSP_APDU_INS_TRY           0x54
#define MSP_APDU_INS_INQUIRY       0x49
#define MSP_APDU_INS_STORE         0x53
#define MSP_APDU_INS_PREFETCH      0x50
#define MSP_APDU_INS_FETCH         0x46
#define MSP_APDU_INS_FETCH_ENHANCE 0x45
#define MSP_APDU_INS_DELETE        0x44
#define MSP_APDU_INS_RESET         0x52

#define MSP_LENGTH_MAGIC           16
#define MSP_LENGTH_KEY_SHORT       32
#define MSP_LENGTH_KEY_MIDDLE      48
#define MSP_LENGTH_KEY_LONG        64

#define MSP_KEY_LEN_CKEY           64
#define MSP_KEY_LEN_PUB_SHORT      65
#define MSP_KEY_LEN_PUB_LONG       97
#define MSP_KEY_LEN_PRI_SHORT      32
#define MSP_KEY_LEN_PRI_LONG       48

#define MSP_KEY_LEN_DE             MSP_KEY_LEN_CKEY
#define MSP_KEY_LEN_CE             MSP_KEY_LEN_CKEY
#define MSP_KEY_LEN_ECE            MSP_KEY_LEN_CKEY
#define MSP_KEY_LEN_SECE_SHORT     (MSP_KEY_LEN_CKEY + \
                                   MSP_KEY_LEN_PUB_SHORT + \
                                   MSP_KEY_LEN_PRI_SHORT)
#define MSP_KEY_LEN_SECE_LONG      (MSP_KEY_LEN_CKEY + \
                                   MSP_KEY_LEN_PUB_LONG + \
                                   MSP_KEY_LEN_PRI_LONG)

#define MSP_RSP_RET_LENGTH         4

#define THREE_BYTE_BITS            24
#define TWO_BYTE_BITS              16
#define ONE_BYTE_BITS              8
#define ONE_BYTE_MASK              0x000000FF

#define MSP_TLV_TL_LENGTH          2

#define MSP_TLV_TAG_USER_ID        0x55
#define MSP_TLV_TAG_TYPE           0x54
#define MSP_TLV_TAG_MAGIC          0x4D
#define MSP_TLV_TAG_KEY            0x4B
#define MSP_TLV_TAG_FLAG           0x46
#define MSP_TLV_TAG_UNIT_STATUS    0x53
#define MSP_TLV_TAG_VERSION        0x56

#define MSP_UNIT_STATUS_LENGTH     8

#define MSP_TLV_LENGTH_USER_ID     4
#define MSP_TLV_LENGTH_TYPE        1
#define MSP_TLV_LENGTH_VERSION     4

#define MSP_INDEX_INVALID          (~0U)

#define MSP_SUPER_USER_ID          0
#define MSP_FETCH_AND_STORE        0xA5

#define MSP_MAX_DATA_LEN           (MSP_APDU_HEADER_LENGTH + 1 + \
                                   4 * MSP_TLV_TL_LENGTH + \
                                   MSP_LENGTH_TA_UUID + \
                                   MSP_TLV_LENGTH_USER_ID + \
                                   MSP_TLV_LENGTH_TYPE + \
                                   MSP_LENGTH_MAGIC + \
                                   MSP_KEY_LEN_SECE_LONG + 1)

#define TEE_TA_VERSION             0x302E3031
#define MSP_SA_MNG_VERSION         0x00010001

/* hisi.sa.fbe(5 space):Must keep the same with the AID in MSP. */
static char g_msp_fbe_aid[MSP_SAID_LENGTH] = {
	'h', 'i', 's', 'i', '.', 's', 'a', '.',
	'f', 'b', 'e', ' ', ' ', ' ', ' ', ' '
};
#ifdef MSP_FBE_DYNAMIC_LOAD
/* hisi.sa.fbe(4 space) + '0' */
static char g_msp_fbe_instance_aid[MSP_SAID_LENGTH] = {
	'h', 'i', 's', 'i', '.', 's', 'a', '.',
	'f', 'b', 'e', ' ', ' ', ' ', ' ', '0'
};
#endif /* MSP_FBE_DYNAMIC_LOAD */
static uint8_t g_fbe_ta_uuid[] = {
	0x54, 0xff, 0x86, 0x8f, 0x0d, 0x8d, 0x44, 0x95,
	0x9d, 0x95, 0x8e, 0x24, 0xb2, 0xa0, 0x82, 0x74
};
static uint32_t g_msp_reader_idx = MSP_INDEX_INVALID;
static uint32_t g_msp_sa_version;
static uint32_t g_tee_ta_version = TEE_TA_VERSION;

struct tee_msp_connection_t {
	TEE_SEServiceHandle service;
	TEE_SEReaderHandle reader;
	TEE_SESessionHandle session;
	TEE_SEChannelHandle channel;
};

#ifdef MSP_DEBUG
static void msp_fbe_dump_buffer(uint8_t *buf, int len)
{
	int i;

	tloge("@@@Dump Begin (HEX):Length=%u, @@@\n", len);
	for (i = 0; i < len; i++)
		tloge("%02x", buf[i]);

	tloge("###Dump End###\n");
}
#endif /* MSP_DEBUG */

static void msp_fbe_release_service(struct tee_msp_connection_t *con)
{
	if (con->service) {
		TEE_SEServiceClose(con->service);
		con->service = NULL;
	}
}

static void msp_fbe_release_reader(struct tee_msp_connection_t *con)
{
	if (con->reader) {
		TEE_SEReaderCloseSessions(con->reader);
		con->reader = NULL;
	}
	msp_fbe_release_service(con);
}

static void msp_fbe_release_session(struct tee_msp_connection_t *con)
{
	if (con->session) {
		TEE_SESessionCloseChannels(con->session);
		con->session = NULL;
	}

	msp_fbe_release_reader(con);
}

static void msp_fbe_disconnect_msp(struct tee_msp_connection_t *con)
{
	if (con->channel) {
		TEE_SEChannelClose(con->channel);
		con->channel = NULL;
	}

	msp_fbe_release_session(con);
}

static uint32_t msp_fbe_get_msp_reader(struct tee_msp_connection_t *con)
{
	uint32_t ret;
	uint32_t i;
	TEE_SEReaderHandle readers[TEE_MAX_READER_NUM] = {0};
	char reader_name[TEE_MAX_READER_NAME_LEN] = {0};
	size_t reader_count = TEE_MAX_READER_NUM;
	uint32_t name_len = TEE_MAX_READER_NAME_LEN - 1;

	ret = TEE_SEServiceGetReaders(con->service, readers, &reader_count);
	if (ret != TEE_SUCCESS) {
		tloge("%s, Get readers failed, ret=0x%x", __func__, ret);
		return ret;
	}

	if (reader_count > TEE_MAX_READER_NUM) {
		tloge("%s, count is abnormal, cnt=%u", __func__, reader_count);
		ret = TEE_ERROR_GENERIC;
		return ret;
	}
	if (g_msp_reader_idx != MSP_INDEX_INVALID &&
		g_msp_reader_idx < reader_count) {
		con->reader = readers[g_msp_reader_idx];
		return MSP_SUCCESS;
	}

	for (i = 0; i < reader_count; i++) {
		ret = TEE_SEReaderGetName(readers[i], reader_name, &name_len);
		/* Error does not exit, continue to find. */
		if (ret != TEE_SUCCESS)
			continue;

		if (!strcmp(reader_name, TEE_MSP_READER_NAME)) {
			con->reader = readers[i];
			g_msp_reader_idx = i;
			return MSP_SUCCESS;
		}
	}
	tloge("msp reader not found\n");
	return TEE_ERROR_GENERIC;
}

#ifdef MSP_FBE_DYNAMIC_LOAD
static TEE_Result msp_fbe_sa_load_install(void)
{
	TEE_Result ret;
	int result;
	struct sa_status status = { 0 };
	struct sa_status_detail detail_status = { 0 };
	struct msp_install_sa_info install_sa_info = { 0 };

	ret = TEE_EXT_MSPGetStatus((uint8_t *)g_msp_fbe_aid, MSP_SAID_LENGTH, &detail_status);
	if ((ret != TEE_SUCCESS) && (ret != (TEE_Result)TEE_ERROR_NEED_LOAD_SA)) {
		tloge("TEE_EXT_MSPGetStatus fail, ret=0x%x\n", ret);
		return ret;
	}
	if (detail_status.sa_lfc == SA_LCS_NO_LOAD) {
		ret = TEE_EXT_MSPLoadSA(NULL, 0, (uint8_t *)g_msp_fbe_aid, MSP_SAID_LENGTH);
		if (ret != TEE_SUCCESS) {
			tloge("TEE_EXT_MSPLoadSA fail, ret=0x%x\n", ret);
			return ret;
		}
	}
	if (detail_status.sa_lfc == SA_LCS_INSTALLED)
		return ret;

	result = memcpy_s(install_sa_info.sa_aid, MSP_SAID_LENGTH, g_msp_fbe_aid, MSP_SAID_LENGTH);
	if (result != EOK) {
		tloge("%s: memcpy fail, 0x%x!\n", __func__, result);
		return MSP_STATUS(MSP_OP_SA_LOAD_INSTALL, MSP_MMCPY_FAIL);
	}
	result = memcpy_s(install_sa_info.sa_instance_id, MSP_SAID_LENGTH, g_msp_fbe_instance_aid,
		MSP_SAID_LENGTH);
	if (result != EOK) {
		tloge("%s: memcpy fail, 0x%x!\n", __func__, result);
		return MSP_STATUS(MSP_OP_SA_LOAD_INSTALL, MSP_MMCPY_FAIL);
	}
	install_sa_info.version = MSP_SA_MNG_VERSION;
	ret = TEE_EXT_MSPInstallSA(&install_sa_info, &status);
	if (ret != TEE_SUCCESS) {
		tloge("TEE_EXT_MSPInstallSA fail, ret=0x%x\n", ret);
		return ret;
	}

	return ret;
}
#endif /* MSP_FBE_DYNAMIC_LOAD */

/*
 * Description: Build connection channel to response with MSP.
 * param[in]  : con, The connection struct between TEE and MSP.
 * param[out] : void.
 * return     : Operation status: success(0) or other failure status
 */
static uint32_t msp_fbe_connect_msp(struct tee_msp_connection_t *con)
{
	uint32_t ret;
#ifndef MSP_FBE_DYNAMIC_LOAD
	TEE_SEAID seaid = {(uint8_t *)g_msp_fbe_aid, sizeof(g_msp_fbe_aid)};
#else /* MSP_FBE_DYNAMIC_LOAD */
	TEE_SEAID seaid = {(uint8_t *)g_msp_fbe_instance_aid, sizeof(g_msp_fbe_instance_aid)};

	ret = msp_fbe_sa_load_install();
	if (ret != TEE_SUCCESS) {
		tloge("msp_fbe_sa_load_install fail, ret=0x%x\n", ret);
		return ret;
	}
#endif /* MSP_FBE_DYNAMIC_LOAD */

	ret = TEE_SEServiceOpen(&(con->service));
	if (ret != TEE_SUCCESS) {
		tloge("Open service fail, ret=0x%x\n", ret);
		return ret;
	}

	ret = msp_fbe_get_msp_reader(con);
	if (ret != MSP_SUCCESS) {
		msp_fbe_release_reader(con);
		tloge("%s get reader fail, ret=0x%x\n", __func__, ret);
		return ret;
	}

	ret = TEE_SEReaderOpenSession(con->reader, &(con->session));
	if (ret != TEE_SUCCESS) {
		msp_fbe_release_reader(con);
		tloge("Open session fail, ret=0x%x\n", ret);
		return ret;
	}

	ret = TEE_SESessionOpenLogicalChannel(
		con->session, &seaid, &(con->channel));
	if (ret != TEE_SUCCESS) {
		msp_fbe_release_session(con);
		tloge("Open channel fail, ret=0x%x\n", ret);
		return ret;
	}

	return MSP_SUCCESS;
}

/*
 * Description: Combine two or four bytes to form a value.
 * param[in]  : buf, The byte buffer.
 * param[in]  : is_two, true if to combine two byte, false if to combine four.
 * param[out] : void.
 * return     : The combined value.
 */
static uint32_t msp_fbe_combine_byte(const uint8_t *buf, bool is_two)
{
	uint32_t combine;
	uint32_t offset = 0;

	combine = buf[offset];

	offset++;
	combine = (combine << ONE_BYTE_BITS) | buf[offset];

	if (is_two)
		return combine;

	offset++;
	combine = (combine << ONE_BYTE_BITS) | buf[offset];

	offset++;
	combine = (combine << ONE_BYTE_BITS) | buf[offset];
	return combine;
}

/*
 * Description: Check APDU SW and MSP execution status in the responsing apdu.
 * param[in]  : buf, The apdu buffer.
 * param[in]  : len, The length of the apdu buffer.
 * param[out] : void.
 * return     : Operation status: success(0) or other failure status
 */
static uint32_t msp_fbe_check_rsp_status(const uint8_t *buf, uint32_t len)
{
	uint16_t sw;
	uint8_t exp_len;

	/* The last two bytes in APDU construct APDU SW(status word). */
	exp_len = MSP_APDU_LENGTH_SW;
	if (len < exp_len) {
		tloge("%s invalid length=%u\n", __func__, len);
		return MSP_APDU_RSP_INCOMPLETE;
	}
	sw = msp_fbe_combine_byte(buf + len - exp_len, true);
	/* APDU SW is expected to be 0x9000, otherwise APDU error occurs */
	if (sw != MSP_APDU_SW_SUCCESS) {
		tloge("%s APDU SW=0x%x\n", __func__, sw);
		return (MSP_APDU_S_PREFIX | sw);
	}

	/* The first four bytes in APDU construt MSP execution status. */
	exp_len += MSP_RSP_RET_LENGTH;
	if (len < exp_len) {
		tloge("%s invalid length=%u\n", __func__, len);
		return MSP_APDU_RSP_INCOMPLETE;
	}
	return msp_fbe_combine_byte(buf, false);
}

/*
 * Description: Check the file type and key length of private key.
 * param[in]  : op, The key operation.
 * param[in]  : info, Key information.
 * param[out] : void
 * return     : Operation status: success(0) or other failure status
 */
static uint32_t msp_fbe_check_pri_key(
	uint32_t op, struct key_info_t *info)
{
	uint32_t key_len = info->key_len;

	if (op == MSP_OP_FETCH && (key_len == MSP_KEY_LEN_PRI_SHORT ||
		key_len == MSP_KEY_LEN_PRI_LONG))
		return MSP_SUCCESS;

	return MSP_STATUS(op, MSP_INVALID_FILE_TYPE);
}

/*
 * Description: Check the file type and key length of SECE key.
 * param[in]  : op, The key operation.
 * param[in]  : info, Key information.
 * param[out] : void
 * return     : Operation status: success(0) or other failure status
 */
static uint32_t msp_fbe_check_sece_key(uint32_t op, struct key_info_t *info)
{
	uint32_t key_len = info->key_len;

	if (op == MSP_OP_FETCH &&
		(key_len == MSP_KEY_LEN_CKEY + MSP_KEY_LEN_PUB_LONG ||
		key_len == MSP_KEY_LEN_CKEY + MSP_KEY_LEN_PUB_SHORT))
		return MSP_SUCCESS;
	if ((op == MSP_OP_FETCH_ENHANCE || op == MSP_OP_DELETE) &&
		(key_len == MSP_KEY_LEN_SECE_LONG ||
		key_len == MSP_KEY_LEN_SECE_SHORT))
		return MSP_SUCCESS;

	return MSP_STATUS(op, MSP_INVALID_FILE_TYPE);
}

/*
 * Description: Check the validity of the file type and key length.
 * param[in]  : op, The key operation.
 * param[in]  : info, Key information.
 * param[out] : void
 * return     : Operation status: success(0) or other failure status
 */
static uint32_t msp_fbe_check_file_type_and_key(
	uint32_t op, struct key_info_t *info)
{
	uint32_t key_len = info->key_len;

	if (op != MSP_OP_DELETE && !info->key_buf) {
		tloge("%s key buffer NULL\n", __func__);
		return MSP_STATUS(op, MSP_NULL_POINTER);
	}

	if (info->file_type < FILE_SECE && key_len == MSP_KEY_LEN_CKEY)
		return MSP_SUCCESS;

	if (info->file_type == FILE_PRIV)
		return msp_fbe_check_pri_key(op, info);

	if (info->file_type == FILE_SECE)
		return msp_fbe_check_sece_key(op, info);

	return MSP_STATUS(op, MSP_INVALID_FILE_TYPE);
}

/*
 * Description: Check the validity of the magic.
 * param[in]  : magic_buf, The content of magic.
 * param[in]  : magic_len, The length of magic.
 * param[out] : void
 * return     : Operation status: success(0) or other failure status
 */
static uint32_t msp_fbe_check_magic(uint8_t *magic, uint32_t magic_len)
{
	if (!magic) {
		tloge("%s magic NULL\n", __func__);
		return MSP_NULL_POINTER;
	}

	if (magic_len != MSP_LENGTH_MAGIC) {
		tloge("%s invalid length=%u\n", __func__, magic_len);
		return MSP_INVALID_LENGTH;
	}

	return MSP_SUCCESS;
}

/*
 * Description: Check the parameter correctness of the store operation.
 * param[in]  : op, The type of the key operation.
 * param[in]  : info, Point to strut containing general key information.
 * param[out] : void
 * return     : Operation status: success(0) or other failure status
 */
static uint32_t msp_fbe_check_info(uint32_t op, struct key_info_t *info)
{
	uint32_t ret;
#ifdef MSP_DEBUG_P
	if (op == MSP_OP_INQUIRY || op == MSP_OP_RESET)
		return MSP_SUCCESS;
#endif /* MSP_DEBUG_P */
	if (op == MSP_OP_PREFETCH)
		return MSP_SUCCESS;

	if (!info)
		return MSP_STATUS(op, MSP_NULL_POINTER);

	ret = msp_fbe_check_file_type_and_key(op, info);
	if (ret != MSP_SUCCESS)
		return ret;

	ret = msp_fbe_check_magic(info->magic_buf, info->magic_len);
	if (ret != MSP_SUCCESS)
		return MSP_STATUS(op, ret);

	return MSP_SUCCESS;
}

/*
 * Description: Get the APDU instruction for the key operation.
 * param[in]  : op, The type of the key operation.
 * param[out] : void.
 * return     : the APDU instruction.
 */
static uint8_t msp_fbe_get_op_ins(uint32_t op)
{
	switch (op) {
	case MSP_OP_TRY:
		return MSP_APDU_INS_TRY;
	case MSP_OP_STORE:
		return MSP_APDU_INS_STORE;
	case MSP_OP_PREFETCH:
		return MSP_APDU_INS_PREFETCH;
	case MSP_OP_FETCH:
		return MSP_APDU_INS_FETCH;
	case MSP_OP_FETCH_ENHANCE:
		return MSP_APDU_INS_FETCH_ENHANCE;
	case MSP_OP_DELETE:
		return MSP_APDU_INS_DELETE;
#ifdef MSP_DEBUG_P
	case MSP_OP_INQUIRY:
		return MSP_APDU_INS_INQUIRY;
	case MSP_OP_RESET:
		return MSP_APDU_INS_RESET;
#endif /* MSP_DEBUG_P */
	default:
		break;
	}
	return 0;
}

#ifdef MSP_DEBUG_P
/*
 * Description: Verify the correctness and extract the unit status from APDU.
 * param[in]  : rsp, The responsing apdu.
 * param[in]  : rsp_len, The length of responsing apdu.
 * return     : Operation status: success(0) or other failure status
 */
static uint32_t msp_fbe_inquiry_parse_rsp(uint8_t *rsp, uint32_t rsp_len)
{
	uint32_t offset;
	uint32_t ret;
	uint32_t exp_len;
	uint32_t data_len;
	uint32_t data_end;
	uint32_t user_id;
	uint32_t index;

	/*
	 * APDU format: xxxx[...]sw.
	 * The last two bytes are concatenated to be APDU status word.
	 * 9000 means success, else error.
	 * The first four bytes are concatenated to be MSP SA execution status.
	 * 0 means success, else error. If both status have no error.
	 * The key is packed with TLV data format in the middle rsp buffer.
	 */
	ret = msp_fbe_check_rsp_status(rsp, rsp_len);
	if (ret != MSP_SUCCESS) {
		tloge("%s ret=0x%x\n", __func__, ret);
		return ret;
	}

	exp_len = MSP_APDU_LENGTH_SW + MSP_RSP_RET_LENGTH + MSP_TLV_TL_LENGTH;
	if (rsp_len < exp_len) {
		tloge("%s invalid length=%u\n", __func__, rsp_len);
		return MSP_STATUS(MSP_OP_FETCH, MSP_APDU_RSP_INCOMPLETE);
	}
	/* The APDU data is expected to contain the unit status */
	offset = MSP_RSP_RET_LENGTH;
	if (rsp[offset] != MSP_TLV_TAG_UNIT_STATUS) {
		tloge("%s wrong T=%u\n", __func__, rsp[offset]);
		return MSP_STATUS(MSP_OP_FETCH, MSP_APDU_RSP_WRONG_TAG);
	}
	offset++;
	data_len = rsp[offset];
	if (data_len == 0 || data_len % MSP_UNIT_STATUS_LENGTH != 0) {
		tloge("%s invalid data_len=%u\n", __func__, data_len);
		return MSP_STATUS(MSP_OP_FETCH, MSP_APDU_RSP_WRONG_LENGTH);
	}
	if (rsp_len < data_len || rsp_len - exp_len < data_len) {
		tloge("%s invalid rsp_len=%u, data_len=%u\n",
			__func__, rsp_len, data_len);
		return MSP_STATUS(MSP_OP_FETCH, MSP_APDU_RSP_INCOMPLETE);
	}
	offset++;
	data_end = offset + data_len;
	index = 0;
	while (data_end - offset >= MSP_UNIT_STATUS_LENGTH) {
		user_id = msp_fbe_combine_byte(rsp + offset, false);
		tloge("%s unit[%u] user_id=%u\n", __func__, index, user_id);
		offset += sizeof(user_id);
		tloge("%s unit[%u] map=0x%x\n", __func__, index, rsp[offset]);
		offset++;
		tloge("%s unit[%u] pub_len=%u\n", __func__, index, rsp[offset]);
		offset++;
		tloge("%s unit[%u] pri_len=%u\n", __func__, index, rsp[offset]);
		offset++;
		tloge("%s unit[%u] reserve=%u\n", __func__, index, rsp[offset]);
		offset++;
		index += 1;
	}
	return MSP_SUCCESS;
}
#endif /* MSP_DEBUG_P */

/*
 * Description: Pack the key information into the apdu command data.
 * param[in]  : op, The type of the key operation.
 * param[in]  : info, Point to strut containing general key information.
 * param[in]  : flag, Indicate the fetch operation.
 * param[out] : apdu_cmd, The apdu command data buffer.
 * return     : Operation status: success(0) or other failure status
 */
static uint32_t msp_fbe_apdu_pack_info(
	uint32_t op, struct key_info_t *info, uint8_t *apdu_cmd, uint32_t *length)
{
	uint32_t offset;
	int status;

	offset = 0;
	apdu_cmd[offset++] = MSP_APDU_CLA; /* APDU CLA */
	apdu_cmd[offset++] = msp_fbe_get_op_ins(op); /* APDU INS */
	apdu_cmd[offset++] = 0; /* APDU P1 */
	apdu_cmd[offset++] = 0; /* APDU P2 */

	offset++; /* Let this offset value to be set as APDU Lc later. */
	status = memcpy_s(apdu_cmd + offset, MSP_MAX_DATA_LEN - offset,
			  g_fbe_ta_uuid, sizeof(g_fbe_ta_uuid));
	if (status != EOK) {
		tloge("%s: memcpy fail, 0x%x!\n", __func__, status);
		return MSP_STATUS(op, MSP_MMCPY_FAIL);
	}
	offset += MSP_LENGTH_TA_UUID;
	if (!info)
		goto end;

	/* APDU data begin */
	apdu_cmd[offset++] = MSP_TLV_TAG_USER_ID;
	apdu_cmd[offset++] = MSP_TLV_LENGTH_USER_ID;
	apdu_cmd[offset++] = (info->user_id >> THREE_BYTE_BITS) & ONE_BYTE_MASK;
	apdu_cmd[offset++] = (info->user_id >> TWO_BYTE_BITS) & ONE_BYTE_MASK;
	apdu_cmd[offset++] = (info->user_id >> ONE_BYTE_BITS) & ONE_BYTE_MASK;
	apdu_cmd[offset++] = info->user_id & ONE_BYTE_MASK;

	if (op == MSP_OP_PREFETCH)
		goto end;

	apdu_cmd[offset++] = MSP_TLV_TAG_TYPE;
	apdu_cmd[offset++] = MSP_TLV_LENGTH_TYPE;
	apdu_cmd[offset++] = info->file_type;

	apdu_cmd[offset++] = MSP_TLV_TAG_MAGIC;
	apdu_cmd[offset++] = info->magic_len;
	status = memcpy_s(apdu_cmd + offset, MSP_MAX_DATA_LEN - offset,
			  info->magic_buf, info->magic_len);
	if (status != EOK) {
		tloge("%s: memcpy fail, 0x%x!\n", __func__, status);
		return MSP_STATUS(op, MSP_MMCPY_FAIL);
	}
	offset += info->magic_len;

	apdu_cmd[offset++] = MSP_TLV_TAG_KEY;
	apdu_cmd[offset++] = info->key_len;
	if (op != MSP_OP_DELETE && op != MSP_OP_FETCH) {
		status = memcpy_s(
			apdu_cmd + offset, MSP_MAX_DATA_LEN - offset,
			info->key_buf, info->key_len);
		if (status != EOK) {
			tloge("%s: memcpy fail, 0x%x!\n", __func__, status);
			return MSP_STATUS(op, MSP_MMCPY_FAIL);
		}
		offset += info->key_len;
	}

end:
	/* APDU Lc */
	apdu_cmd[MSP_APDU_OFFSET_LC] = offset - MSP_APDU_HEADER_LENGTH;
	apdu_cmd[offset++] = 0; /* APDU Le */
	/* APDU data end */
	*length = offset;
	return MSP_SUCCESS;
}

static uint32_t msp_fbe_try_parse_rsp(uint8_t *rsp, uint32_t rsp_len)
{
	uint32_t offset;
	uint32_t ret;
	uint32_t exp_len;

	/*
	 * APDU format: xxxx[...]sw.
	 * The last two bytes are concatenated to be APDU status word.
	 * 9000 means success, else error.
	 * The first four bytes are concatenated to be MSP SA execution status.
	 * 0 means success, else error. If both status have no error.
	 * The key is packed with TLV data format in the middle rsp buffer.
	 */
	ret = msp_fbe_check_rsp_status(rsp, rsp_len);
	if (ret != MSP_SUCCESS) {
		tloge("%s ret=0x%x\n", __func__, ret);
		return ret;
	}

	exp_len = MSP_APDU_LENGTH_SW + MSP_RSP_RET_LENGTH;

	/* The APDU data is expected to contain the MSP SA version */
	exp_len += MSP_TLV_TL_LENGTH + MSP_TLV_LENGTH_VERSION;
	if (rsp_len < exp_len) {
		tloge("%s invalid length=%u\n", __func__, rsp_len);
		return MSP_STATUS(MSP_OP_FETCH, MSP_APDU_RSP_INCOMPLETE);
	}
	offset = MSP_RSP_RET_LENGTH;
	if (rsp[offset] != MSP_TLV_TAG_VERSION) {
		tloge("%s wrong T=%u\n", __func__, rsp[offset]);
		return MSP_STATUS(MSP_OP_FETCH, MSP_APDU_RSP_WRONG_TAG);
	}

	offset++;
	if (rsp[offset] != MSP_TLV_LENGTH_VERSION) {
		tloge("%s wrong L=%u\n", __func__, rsp[offset]);
		return MSP_STATUS(MSP_OP_FETCH, MSP_APDU_RSP_WRONG_LENGTH);
	}
	offset++;
	g_msp_sa_version = msp_fbe_combine_byte(rsp + offset, false);
	return MSP_SUCCESS;
}

/*
 * Description: Verify the correctness and extract the key data from APDU.
 * param[in]  : rsp, The responsing apdu.
 * param[in]  : rsp_len, The length of responsing apdu.
 * param[out] : key_buf, The buffer to return the key.
 * param[in]  : key_len, The length of the key buffer.
 * return     : Operation status: success(0) or other failure status
 */
static uint32_t msp_fbe_fetch_parse_rsp(
	uint8_t *rsp, uint32_t rsp_len, uint8_t *key_buf, uint32_t key_len)
{
	uint32_t offset;
	uint32_t ret;
	uint32_t exp_len;
	int status;

	/*
	 * APDU format: xxxx[...]sw.
	 * The last two bytes are concatenated to be APDU status word.
	 * 9000 means success, else error.
	 * The first four bytes are concatenated to be MSP SA execution status.
	 * 0 means success, else error. If both status have no error.
	 * The key is packed with TLV data format in the middle rsp buffer.
	 */
	ret = msp_fbe_check_rsp_status(rsp, rsp_len);
	if (ret != MSP_SUCCESS) {
		tloge("%s ret=0x%x\n", __func__, ret);
		return ret;
	}

	exp_len = MSP_APDU_LENGTH_SW + MSP_RSP_RET_LENGTH;

	/* The APDU data is expected to contain the key value */
	exp_len += MSP_TLV_TL_LENGTH + key_len;
	if (rsp_len < exp_len) {
		tloge("%s invalid length=%u\n", __func__, rsp_len);
		return MSP_STATUS(MSP_OP_FETCH, MSP_APDU_RSP_INCOMPLETE);
	}
	offset = MSP_RSP_RET_LENGTH;
	if (rsp[offset] != MSP_TLV_TAG_KEY) {
		tloge("%s wrong T=%u\n", __func__, rsp[offset]);
		return MSP_STATUS(MSP_OP_FETCH, MSP_APDU_RSP_WRONG_TAG);
	}

	offset++;
	if (rsp[offset] != key_len) {
		tloge("%s wrong L=%u\n", __func__, rsp[offset]);
		return MSP_STATUS(MSP_OP_FETCH, MSP_APDU_RSP_WRONG_LENGTH);
	}

	offset++;
	status = memcpy_s(key_buf, key_len, rsp + offset, key_len);
	if (status != EOK) {
		tloge("%s: memcpy fail, 0x%x!\n", __func__, status);
		return MSP_STATUS(MSP_OP_FETCH, MSP_MMCPY_FAIL);
	}

	return MSP_SUCCESS;
}

/*
 * Description: Check the correctness of the responsing apdu.
 * param[in]  : buf, The apdu buffer.
 * param[in]  : buf_len, The length of the apdu buffer.
 * param[out] : void.
 * return     : Operation status: success(0) or other failure status
 */
static uint32_t msp_fbe_check_response(
	uint32_t op, struct key_info_t *info, uint8_t *rsp, uint32_t rsp_len)
{
	uint32_t ret;

#ifdef MSP_DEBUG_P
	if (op == MSP_OP_INQUIRY)
		return msp_fbe_inquiry_parse_rsp(rsp, rsp_len);
#endif /* MSP_DEBUG_P */
	if (op == MSP_OP_FETCH || op == MSP_OP_FETCH_ENHANCE)
		ret = msp_fbe_fetch_parse_rsp(
			rsp, rsp_len, info->key_buf, info->key_len);
	else
		ret = msp_fbe_check_rsp_status(rsp, rsp_len);

	if (ret != MSP_SUCCESS)
		tloge("%s, 0x%x\n", __func__, ret);

	return ret;
}

/*
 * Description: Store the magic-key pair to MSP.
 * param[in]  : info, Point to strut containing general key information.
 * param[out] : void
 * return     : Operation status: success(0) or other failure status
 */
static uint32_t msp_fbe_key_operation(uint32_t op, struct key_info_t *info)
{
	uint32_t ret;
	uint8_t apdu_cmd[MSP_MAX_DATA_LEN] = {0};
	uint32_t offset = 0;
	uint8_t apdu_rsp[MSP_MAX_DATA_LEN] = {0};
	uint32_t rsp_len = sizeof(apdu_rsp);
	struct tee_msp_connection_t con = {0};

	ret = msp_fbe_check_info(op, info);
	if (ret != MSP_SUCCESS) {
		tloge("%s, 0x%x\n", __func__, ret);
		return ret;
	}

	ret = msp_fbe_apdu_pack_info(op, info, apdu_cmd, &offset);
	if (ret != MSP_SUCCESS) {
		tloge("%s, 0x%x\n", __func__, ret);
		return ret;
	}
	ret = msp_fbe_connect_msp(&con);
	if (ret != MSP_SUCCESS) {
		tloge("%s, 0x%x\n", __func__, ret);
		goto end;
	}

	ret = TEE_SEChannelTransmit(
		con.channel, apdu_cmd, offset, apdu_rsp, &rsp_len);
	if (ret != TEE_SUCCESS) {
		tloge("%s, Transmit fail, ret=0x%x\n", __func__, ret);
		goto end;
	}

	ret = msp_fbe_check_response(op, info, apdu_rsp, rsp_len);
end:
	(void)memset_s(apdu_cmd, sizeof(apdu_cmd), 0, sizeof(apdu_cmd));
	(void)memset_s(apdu_rsp, sizeof(apdu_rsp), 0, sizeof(apdu_rsp));
	msp_fbe_disconnect_msp(&con);
	return ret;
}

#ifdef MSP_DEBUG_P
/*
 * Description: Return the using status of the slot.
 * param[out] : buffer, The buffer to return the slot status.
 * param[in]  : length, The length of buffer.
 * return     : Operation status: success(0) or other failure status
 */
uint32_t msp_fbe_inquiry_key(void)
{
	uint32_t op = MSP_OP_INQUIRY;
	uint32_t ret;

	ret = msp_fbe_key_operation(op, NULL);
	if (ret != MSP_SUCCESS)
		tloge("%s, 0x%x\n", __func__, ret);

	return ret;
}
#endif /* MSP_DEBUG_P */

uint32_t msp_fbe_try(uint32_t *version)
{
	int status;
	uint32_t ret;
	uint8_t apdu_cmd[MSP_MAX_DATA_LEN] = {0};
	uint32_t offset;
	uint8_t apdu_rsp[MSP_MAX_DATA_LEN] = {0};
	uint32_t rsp_len = sizeof(apdu_rsp);
	struct tee_msp_connection_t con = {0};

	if (g_msp_sa_version) {
		ret = MSP_SUCCESS;
		goto end;
	}

	offset = 0;
	apdu_cmd[offset++] = MSP_APDU_CLA; /* APDU CLA */
	apdu_cmd[offset++] = msp_fbe_get_op_ins(MSP_OP_TRY); /* APDU INS */
	apdu_cmd[offset++] = 0; /* APDU P1 */
	apdu_cmd[offset++] = 0; /* APDU P2 */

	offset++; /* Let this offset value to be set as APDU Lc later. */
	status = memcpy_s(apdu_cmd + offset, MSP_MAX_DATA_LEN - offset,
			  g_fbe_ta_uuid, sizeof(g_fbe_ta_uuid));
	if (status != EOK) {
		tloge("%s: memcpy fail, 0x%x!\n", __func__, status);
		return MSP_STATUS(MSP_OP_TRY, MSP_MMCPY_FAIL);
	}
	offset += MSP_LENGTH_TA_UUID;
	/* APDU data begin */
	apdu_cmd[offset++] = MSP_TLV_TAG_VERSION;
	apdu_cmd[offset++] = MSP_TLV_LENGTH_VERSION;
	apdu_cmd[offset++] = (g_tee_ta_version >> THREE_BYTE_BITS) & ONE_BYTE_MASK;
	apdu_cmd[offset++] = (g_tee_ta_version >> TWO_BYTE_BITS) & ONE_BYTE_MASK;
	apdu_cmd[offset++] = (g_tee_ta_version >> ONE_BYTE_BITS) & ONE_BYTE_MASK;
	apdu_cmd[offset++] = g_tee_ta_version & ONE_BYTE_MASK;
	/* APDU Lc */
	apdu_cmd[MSP_APDU_OFFSET_LC] = offset - MSP_APDU_HEADER_LENGTH;
	apdu_cmd[offset++] = 0; /* APDU Le */

	ret = msp_fbe_connect_msp(&con);
	if (ret != MSP_SUCCESS) {
		tloge("%s, 0x%x\n", __func__, ret);
		goto end;
	}
	ret = TEE_SEChannelTransmit(
		con.channel, apdu_cmd, offset, apdu_rsp, &rsp_len);
	if (ret != TEE_SUCCESS) {
		tloge("%s, Transmit fail, ret=0x%x\n", __func__, ret);
		goto end;
	}

	ret = msp_fbe_try_parse_rsp(apdu_rsp, rsp_len);
end:
	(void)memset_s(apdu_cmd, sizeof(apdu_cmd), 0, sizeof(apdu_cmd));
	(void)memset_s(apdu_rsp, sizeof(apdu_rsp), 0, sizeof(apdu_rsp));
	msp_fbe_disconnect_msp(&con);
	if (version)
		*version = g_msp_sa_version;
	return ret;
}

/*
 * Description: Let the MSP SA prefetch the user-related key.
 * param[in]  : user_id, The user identifier.
 * param[out] : void
 * return     : Operation status: success(0) or other failure status
 */
uint32_t msp_fbe_prefetch_key(uint32_t user_id)
{
	uint32_t op = MSP_OP_PREFETCH;
	uint32_t ret;
	struct key_info_t info = {0};

	info.user_id = user_id;
	ret = msp_fbe_key_operation(op, &info);
	if (ret != MSP_SUCCESS)
		tloge("%s, 0x%x\n", __func__, ret);
	return ret;
}

/*
 * Description: Fetch the key from MSP by magic. If the key is not found,
 *              return error.
 * param[in]  : info, Point to struct containing general key information.
 * param[out] : info, The key_buf is used to return the key.
 * return     : Operation status: success(0) or other failure status
 */
uint32_t msp_fbe_fetch_key(struct key_info_t *info)
{
	uint32_t op = MSP_OP_FETCH;
	uint32_t ret;

	ret = msp_fbe_key_operation(op, info);
	if (ret != MSP_SUCCESS)
		tloge("%s, 0x%x\n", __func__, ret);
	return ret;
}

/*
 * Description: Fetch the key from MSP by magic. If the key is not found,
 *              store the key.
 * param[in]  : info, Point to struct containing general key information.
 *              The key_buf in info must contain the valid key content.
 * param[out] : info, The key_buf is used to return the key if key is found.
 * return     : Operation status: success(0) or other failure status
 */
uint32_t msp_fbe_fetch_key_enhance(struct key_info_t *info)
{
	uint32_t op = MSP_OP_FETCH_ENHANCE;
	uint32_t ret;

	ret = msp_fbe_key_operation(op, info);
	if (ret != MSP_SUCCESS)
		tloge("%s, 0x%x\n", __func__, ret);
	return ret;
}

/*
 * Description: Delete the magic-key pair from MSP by magic.
 * param[in]  : info, Point to strut containing general key information.
 * param[out] : void.
 * return     : Operation status: success(0) or other failure status
 */
uint32_t msp_fbe_delete_key(struct key_info_t *info)
{
	uint32_t op = MSP_OP_DELETE;
	uint32_t ret;

	ret = msp_fbe_key_operation(op, info);
	if (ret != MSP_SUCCESS)
		tloge("%s, 0x%x\n", __func__, ret);
	return ret;
}

#ifdef MSP_DEBUG_P
/*
 * Description: Reset all the magic-key pairs from MSP.
 * param[in]  : void.
 * param[out] : void.
 * return     : Operation status: success(0) or other failure status
 */
uint32_t msp_fbe_reset_key(void)
{
	uint32_t op = MSP_OP_RESET;
	uint32_t ret;

	ret = msp_fbe_key_operation(op, NULL);
	if (ret != MSP_SUCCESS)
		tloge("%s, 0x%x\n", __func__, ret);
	return ret;
}
#endif /* MSP_DEBUG_P */
