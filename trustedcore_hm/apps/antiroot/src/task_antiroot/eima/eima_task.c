/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: Eima TA which process message from rootscan CA
 * Create: 2018-06-11
 */

#include "eima_task.h"
#include <string.h>
#include "antiroot_task.h"
#include "root_status_ops.h"
#include "securec.h"
#include "tee_ext_api.h"
#include "tee_log.h"
#include "tee_private_api.h"

static unsigned char g_eima_nounce[COUNTER_LENGTH];
static uint32_t g_cmd_state = EIMA_STATE_CHALLENGE;
static eima_whitelist g_eima_whitelist;
static eima_whitelist g_eima_runtimelist;
static uint32_t g_cmd_error;

/* store the tampered file path when measuring of one process failed */
static char g_hash_error_file_path[FNAME_LENGTH];

#define EIMA_BASE_LINE 0
#define EIMA_RUN_TIME  1
#define EIMA_FREE_POLICY_TARGET_TYPE  0xff

#ifdef DEBUG_DUMP_HEX
#define HEX_NUM 16
static void dump_hex(const uint8_t *hex, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < (len - len % HEX_NUM); i += HEX_NUM)
		tlogd("\n\n %x %x %x %x %x %x %x %x  %x %x %x %x  %x %x %x %x\n",
			hex[i + EIMA_DUMP_IDX_0], hex[i + EIMA_DUMP_IDX_1],
			hex[i + EIMA_DUMP_IDX_2], hex[i + EIMA_DUMP_IDX_3],
			hex[i + EIMA_DUMP_IDX_4], hex[i + EIMA_DUMP_IDX_5],
			hex[i + EIMA_DUMP_IDX_6], hex[i + EIMA_DUMP_IDX_7],
			hex[i + EIMA_DUMP_IDX_8], hex[i + EIMA_DUMP_IDX_9],
			hex[i + EIMA_DUMP_IDX_10], hex[i + EIMA_DUMP_IDX_11],
			hex[i + EIMA_DUMP_IDX_12], hex[i + EIMA_DUMP_IDX_13],
			hex[i + EIMA_DUMP_IDX_14], hex[i + EIMA_DUMP_IDX_15]);

	for (i = (len - len % HEX_NUM); i < len; i++)
		tlogd("     hex[%d] = %x\n", i, hex[i]);
}
#else
static void dump_hex(const uint8_t *hex, uint32_t len)
{
	(void)hex;
	(void)len;
	return;
}
#endif

static inline int sanity_check_len(uint16_t current, uint16_t offset,
				unsigned int total)
{
	return ((current > UINT16_MAX - offset) || (total < current + offset));
}

static uint16_t get_len(struct sbuf_iter *iter)
{
	const uint16_t *len;

	len = iter->buf + iter->index;
	iter->index += sizeof(*len);

	return *len;
}

static uint8_t get_hash_len(struct sbuf_iter *iter)
{
	const uint8_t *len;

	len = iter->buf + iter->index;
	iter->index += sizeof(*len);

	return *len;
}

static void *get_value_entry(struct sbuf_iter *iter, uint16_t len)
{
	void *entry = NULL;
	errno_t s_ret;

	entry = TEE_Malloc(len, 0);
	if (entry == NULL) {
		tloge("EIMA get value entry: malloc failed, size is 0x%x\n",
			len);
		return NULL;
	}

	s_ret = memcpy_s(entry, len, iter->buf + iter->index, len - 1);
	if (s_ret != EOK) {
		tloge("memcpy_s fail\n");
		TEE_Free(entry);
		return NULL;
	}
	iter->index += len;

	return entry;
}

static inline int has_ending_null_byte(const struct sbuf_iter *iter,
				uint16_t len)
{
	const char *str = iter->buf + iter->index + len - 1;

	return *str == '\0';
}

static int check_filename_entry(const struct sbuf_iter *iter, uint16_t len)
{
	if (sanity_check_len(iter->index, len, iter->size) != 0) {
		tloge("EIMA check filename entry: len is error!\n");
		return EIMA_DESERIALIZATION_SIZE_FAILURE;
	}

	if ((len < EIMA_MIN_FILENAME_SIZE) ||
		(len > EIMA_MAX_FILENAME_SIZE)) {
		tloge("EIMA check filename entry: filename len is error, len is %u!\n", len);
		return EIMA_DESERIALIZATION_FILENAME_SIZE;
	}

	if (!has_ending_null_byte(iter, len)) {
		tloge("EIMA check filename entry: filename is not null end\n");
		return EIMA_DESERIALIZATION_FILENAME_NO_NULL_END;
	}

	if ((strlen(iter->buf + iter->index)  + 1) != len) {
		tloge("EIMA check filename entry: filename len is not equal\n");
		return EIMA_DESERIALIZATION_FILENAME_NULL;
	}
	return EIMA_OK;
}

static TEE_Result get_filename_entry(struct sbuf_iter *iter,
				eima_integrity_target *target)
{
	char *filename = NULL;
	uint16_t len;
	int res;

	len = get_len(iter);
	res = check_filename_entry(iter, len);
	if (res != EIMA_OK) {
		tloge("EIMA get filename entry: bad parameter, ret is %d!\n", res);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	filename = get_value_entry(iter, len);
	if (filename == NULL) {
		tloge("EIMA get filename entry: get entry value error!\n");
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	target->fname = filename;
	target->fname_len = len;

	return TEE_SUCCESS;
}

static int check_hash_entry(const struct sbuf_iter *iter, uint16_t len)
{
	if (sanity_check_len(iter->index, len, iter->size) != 0) {
		tloge("EIMA check hash entry:bad parameter 1,hash_len is %u\n",
			len);
		return EIMA_DESERIALIZATION_SIZE_FAILURE;
	}

	if ((len < EIMA_MIN_HASH_SIZE) || (len > EIMA_MAX_HASH_SIZE)) {
		tloge("EIMA check hash entry:bad parameter 2,hash_len is %u\n",
			len);
		return EIMA_DESERIALIZATION_HASH_SIZE;
	}

	return EIMA_OK;
}

static TEE_Result get_hash_entry(struct sbuf_iter *iter,
				eima_integrity_target *target)
{
	uint16_t len;
	errno_t s_ret;
	int res;

	len = get_hash_len(iter);
	/* if len is 0 ,not do the hash check just return ok */
	if (len == 0) {
		iter->index += sizeof(target->hash);
		return TEE_SUCCESS;
	}
	res = check_hash_entry(iter, len);
	if (res != EIMA_OK) {
		tloge("EIMA get hash entry check hash lenth error!\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	s_ret = memcpy_s(target->hash, HASH_LENGTH, iter->buf + iter->index,
			len);
	if (s_ret != EOK) {
		tloge("memcpy_s fail\n");
		return AR_ERR_SYS_ERROR;
	}

	target->hash_len = len;
	iter->index += len;

	return TEE_SUCCESS;
}

static eima_policy *find_policy(const char *uname,
					eima_whitelist *eima_baseline)
{
	uint32_t policy_count;
	uint32_t tmp_count;
	eima_policy *policy = NULL;

	if ((uname == NULL) || (eima_baseline == NULL)) {
		tloge("EIMA find policy bad parameter!\n");
		return NULL;
	}

	policy_count = eima_baseline->policy_count;
	for (tmp_count = 0; tmp_count < policy_count; tmp_count++) {
		policy = eima_baseline->usecase_policy + tmp_count;
		if (!TEE_MemCompare(uname, policy->usecase_name, UNAME_LENGTH))
			return policy;
	}
	tlogd("EIMA find policy error, not found the %s\n", uname);
	return NULL;
}

static eima_integrity_target *find_target(const eima_integrity_target *target,
					eima_policy *policy)
{
	uint32_t tmp_count;
	eima_integrity_target *tmp_target = NULL;

	if ((target == NULL) || (target->fname == NULL) || (policy == NULL)) {
		tloge("EIMA find target bad parameter!\n");
		return NULL;
	}
	for (tmp_count = 0; tmp_count < policy->target_count; tmp_count++) {
		tmp_target = policy->target + tmp_count;
		if (tmp_target->fname == NULL) {
			tloge("EIMA find target target->fname is NULL\n");
			continue;
		}
		if ((tmp_target->type == target->type) &&
			(tmp_target->fname_len == target->fname_len) &&
			(!TEE_MemCompare(tmp_target->fname, target->fname,
			tmp_target->fname_len))) {
			return tmp_target;
		}
	}
	tlogd("EIMA find target error, not found the %s\n", target->fname);
	return NULL;
}

static void eima_free_policy(eima_policy *policy)
{
	errno_t s_ret;
	eima_integrity_target *target = NULL;
	uint32_t i;

	if (policy == NULL)
		return;

	for (i = 0; i < policy->target_count; i++) {
		target = policy->target + i;
		target->type = EIMA_FREE_POLICY_TARGET_TYPE;
		target->hash_len = 0;
		s_ret = memset_s(target->hash, HASH_LENGTH, 0x0, HASH_LENGTH);
		if (s_ret != EOK)
			tloge("memset_s fail\n"); /* if memset fail continue to tee free */

		policy->target[i].fname_len = 0;
		if (target->fname != NULL) {
			TEE_Free(policy->target->fname);
			policy->target->fname = NULL;
		}
	}

	policy->target_count = 0;
	s_ret = memset_s(policy->usecase_name, UNAME_LENGTH, 0, UNAME_LENGTH);
	if (s_ret != EOK)
		tloge("memset_s fail\n");
}

static TEE_Result eima_get_policy(const char *buf, eima_whitelist *list,
						eima_policy **policy)
{
	uint32_t policy_count;
	eima_policy *policy_tmp = NULL;
	uint8_t *uname = NULL;
	errno_t s_ret;

	/* get policy count */
	policy_count = list->policy_count;
	if (policy_count >= USECASE_NUM) {
		tloge("the whitelist is full\n");
		return AR_ERR_OUT_OF_MEM;
	}

	/* find policy in whitelist */
	policy_tmp = find_policy(buf, list);
	if (policy_tmp != NULL) {
		tloge("policy is already exist!\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* add policy into whitelist */
	policy_tmp = list->usecase_policy + policy_count;

	/* usecase_name init */
	uname = policy_tmp->usecase_name;
	s_ret = memcpy_s(uname, UNAME_LENGTH, buf, UNAME_LENGTH - 1);
	if (s_ret != EOK) {
		tloge("memcpy_s fail\n");
		return AR_ERR_SYS_ERROR;
	}
	uname[UNAME_LENGTH - 1] = '\0';

	*policy = policy_tmp;
	return TEE_SUCCESS;
}

static TEE_Result eima_set_list(const char *buf, uint32_t size,
					eima_whitelist *list)
{
	TEE_Result ret;
	eima_policy *policy = NULL;
	eima_integrity_target *target = NULL;
	uint32_t tmp_count;
	uint32_t i;
	struct sbuf_iter iter = { buf, size, 0 };

	/* tmp_count is equal to the buf offset target_count */
	tmp_count = *((uint32_t *)(buf + offsetof(eima_policy, target_count)));
	if ((tmp_count > TARGET_NUM) || (tmp_count == 0)) {
		tloge("EIMA SetWhitelist target num is invalid, tmp_count is %u!\n",
			tmp_count);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = eima_get_policy(buf, list, &policy);
	if (ret != TEE_SUCCESS)
		return ret;

	/* policy_count init */
	policy->target_count = tmp_count;
	iter.index = UNAME_LENGTH;
	iter.index += sizeof(policy->target_count);

	/* target init */
	for (i = 0; i < policy->target_count; i++) {
		target = policy->target + i;
		target->type = *((uint8_t *)(iter.buf + iter.index));
		iter.index++;

		ret = get_hash_entry(&iter, target);
		if (ret != TEE_SUCCESS) {
			tloge("Eima_setList get hash value error!\n");
			ret = TEE_ERROR_GENERIC;
			goto error;
		}

		ret = get_filename_entry(&iter, target);
		if (ret != TEE_SUCCESS) {
			tloge("Eima_setList get file name error!\n");
			ret =  TEE_ERROR_GENERIC;
			goto error;
		}
	}

	list->policy_count++;
	return ret;
error:
	eima_free_policy(policy);
	return ret;
}

static void set_eima_bit(void)
{
	uint32_t status;
	/* Set EIMABIT */
	status = 0x1 << EIMABIT;
	tlogd("EIMA  status is 0x%x\n", status);
	if (__SRE_WriteRootStatus(status))
		tloge("Eima: write rstatus error!\n");
}

static TEE_Result check_tcount(uint32_t tcount, uint32_t target_count)
{
	if ((tcount == 0) || (tcount > target_count)) {
		tloge("EIMA Sethash target num is big!\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	return TEE_SUCCESS;
}

static TEE_Result get_hash_filename_entry(struct sbuf_iter *iter,
				eima_integrity_target *tmp_target)
{
	TEE_Result ret;

	ret = get_hash_entry(iter, tmp_target);
	if (ret != TEE_SUCCESS) {
		tloge("EIMA SetBaseline get hash error!\n");
		ret = TEE_ERROR_GENERIC;
		return ret;
	}

	ret = get_filename_entry(iter, tmp_target);
	if (ret != TEE_SUCCESS) {
		tloge("EIMA SetBaseline get filename error!\n");
		ret =  TEE_ERROR_GENERIC;
		return ret;
	}
	return ret;
}

static TEE_Result compare_target_hash(eima_integrity_target *dst_target,
				eima_integrity_target *tmp_target)
{
	TEE_Result ret;
	errno_t s_ret;

	ret = TEE_MemCompare(dst_target->hash, tmp_target->hash, HASH_LENGTH);
	if (ret == 0)
		return TEE_SUCCESS;

	if (tmp_target->fname == NULL)
		return TEE_ERROR_GENERIC;

	s_ret = memcpy_s(g_hash_error_file_path, FNAME_LENGTH,
				dst_target->fname,
				dst_target->fname_len);
	if (s_ret != EOK) {
		tloge("EIMA copy tampered file path to "
			"global variable error!\n");
		ret = TEE_ERROR_GENERIC;
		return ret;
	}
	g_hash_error_file_path[FNAME_LENGTH - 1] = '\0';

	tlogd("EIMA measure the hash  error, filename is %s\n",
		dst_target->fname);
	dump_hex(dst_target->hash, HASH_LENGTH);
	tlogd("EIMA measure the hash  error, tmp filename is %s\n",
		tmp_target->fname);
	dump_hex(tmp_target->hash, HASH_LENGTH);
	set_eima_bit();
	return AR_ERR_RSP_CHECK_FAIL;
}

static TEE_Result set_dst_target_hash(uint32_t flag,
				eima_integrity_target *dst_target,
				eima_integrity_target *tmp_target)
{
	errno_t s_ret;
	TEE_Result ret;

	if (flag == EIMA_BASE_LINE) {
		if (dst_target->hash_len == 0) {
			s_ret = memcpy_s(dst_target->hash, HASH_LENGTH,
					tmp_target->hash,
					tmp_target->hash_len);
			if (s_ret != EOK) {
				tloge("EIMA SetBaseline set hash error!\n");
				ret = TEE_ERROR_GENERIC;
				return ret;
			}
			dst_target->hash_len = tmp_target->hash_len;
		} else {
			ret = compare_target_hash(dst_target, tmp_target);
			if (ret != TEE_SUCCESS)
				return ret;
		}
	} else if (flag == EIMA_RUN_TIME) {
		s_ret = memcpy_s(dst_target->hash, HASH_LENGTH,
				tmp_target->hash, tmp_target->hash_len);
		if (s_ret != EOK) {
			tloge("EIMA SetRunTime set hash error!\n");
			ret = TEE_ERROR_GENERIC;
			return ret;
		}
		dst_target->hash_len = tmp_target->hash_len;
	} else {
		tloge("Eima_Sethash bad flag!\n");
		ret = AR_ERR_INVOKE_ERROR;
		return ret;
	}
	if (tmp_target->fname != NULL) {
		TEE_Free(tmp_target->fname);
		tmp_target->fname = NULL;
	}
	return TEE_SUCCESS;
}

/* flag Baseline or Runtime */
static TEE_Result eima_set_hash(const char *buf, uint32_t size,
				uint32_t flag, eima_whitelist *list)
{
	TEE_Result ret;
	errno_t s_ret;
	eima_policy *policy = NULL;
	eima_integrity_target tmp_target;
	eima_integrity_target *dst_target = NULL;
	uint32_t tmp_count;
	uint32_t i;
	struct sbuf_iter iter = { buf, size, 0 };

	policy = find_policy(buf, list);
	if (policy == NULL) {
		tloge("EIMA Sethash not found policy!\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	iter.index += UNAME_LENGTH;
	tmp_count = *((uint32_t *)(buf + offsetof(eima_policy, target_count)));
	ret = check_tcount(tmp_count, policy->target_count);
	if (ret != TEE_SUCCESS) {
		tloge("EIMA Sethash target num is bad!\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	iter.index += sizeof(policy->target_count);

	for (i = 0; i < tmp_count; i++) {
		s_ret = memset_s(&tmp_target, sizeof(tmp_target), 0x0,
			sizeof(eima_integrity_target));
		if (s_ret != EOK) {
			tloge("memset_s fail\n");
			return TEE_ERROR_GENERIC;
		}

		tmp_target.type = *((uint8_t *)(iter.buf + iter.index));
		iter.index++;

		ret = get_hash_filename_entry(&iter, &tmp_target);
		if (ret != TEE_SUCCESS)
			goto error;

		dst_target = find_target(&tmp_target, policy);
		if (dst_target == NULL) {
			tloge("EIMA SetBaseline not found dest target!\n");
			ret = AR_ERR_INVOKE_ERROR;
			goto error;
		}

		ret = set_dst_target_hash(flag, dst_target, &tmp_target);
		if (ret != TEE_SUCCESS)
			goto error;
	}
	return TEE_SUCCESS;

error:
	if (tmp_target.fname != NULL)
		TEE_Free(tmp_target.fname);
	return ret;
}

static void eima_free_whitelist(eima_whitelist *list)
{
	uint32_t count;

	if (list == NULL) {
		tloge("list is NULL!\n");
		return;
	}
	if (list->policy_count != 0) {
		for (count = 0; count < list->policy_count; count++)
			eima_free_policy(list->usecase_policy + count);
	}
}

static TEE_Result eima_set_whitelist(const char *buf, uint32_t size)
{
	TEE_Result ret;

	if ((buf == NULL) || (size == 0)) {
		tloge("EIMA SetWhitelist buf or size is bad!\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = eima_set_list(buf, size, &g_eima_whitelist);
	if (ret != TEE_SUCCESS) {
		tloge("eima set whitelist failed!\n");
		goto error;
	}

	ret = eima_set_list(buf, size, &g_eima_runtimelist);
	if (ret != TEE_SUCCESS) {
		tloge("eima_set_runtime failed!\n");
		goto error;
	}

	return ret;

error:
	eima_free_whitelist(&g_eima_whitelist);
	eima_free_whitelist(&g_eima_runtimelist);
	return ret;
}

static TEE_Result eima_set_baseline(const char *buf, uint32_t size)
{
	TEE_Result ret;

	if ((buf == NULL) || (size == 0)) {
		tloge("EIMA SetBaseline buf or size is bad!\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = eima_set_hash(buf, size, EIMA_BASE_LINE, &g_eima_whitelist);
	if (ret != TEE_SUCCESS)
		tloge("eima set baseline failed!\n");

	return ret;
}

static TEE_Result eima_set_runtime(const char *buf, uint32_t size)
{
	TEE_Result ret;

	if ((buf == NULL) || (size == 0)) {
		tloge("EIMA SetRuntime  buf or size is bad!\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = eima_set_hash(buf, size, EIMA_RUN_TIME, &g_eima_runtimelist);
	if (ret != TEE_SUCCESS)
		tloge("eima set runtime failed!\n");

	ret = eima_set_hash(buf, size, EIMA_BASE_LINE, &g_eima_whitelist);

	return ret;
}

static TEE_Result hand_response_msg(uint8_t type, const char *buf,
						uint32_t size)
{
	TEE_Result ret;

	if ((buf == NULL) || (size > ANTIROOT_DST_LEN)) {
		tloge("EIMA hand response msg: Bad parameter!\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	switch (type) {
	case EIMA_MSG_WHITELIST:
		ret = eima_set_whitelist(buf, size);
		break;
	case EIMA_MSG_BASELINE:
		ret = eima_set_baseline(buf, size);
		break;
	case EIMA_MSG_RUNTIME_INFO:
		ret = eima_set_runtime(buf, size);
		break;
	default:
		tloge("EIMA hand response msg: Invalid message type, type is %u\n", type);
		ret = AR_ERR_INVOKE_ERROR;
		break;
	}

	return ret;
}

static TEE_Result decrypt_rsp_content(tee_rm_command *cmd,
				tee_rm_command *tmp_cmd,
				uint32_t *dst_len)
{
	TEE_Result ret;
	errno_t s_ret;

	ret = TEE_EXT_AES_CRYPTO(EIMA_DB, (uint8_t *)cmd,
				EIMA_DECRYPTO, TEE_ALG_AES_CBC_NOPAD,
				g_eima_nounce, sizeof(g_eima_nounce),
				(uint8_t *)cmd + EIMA_IV_LEN,
				(uint8_t *)tmp_cmd, EIMA_SRC_LEN, dst_len);

	tlogd("EIMA Rsp: *dst_len = %u, src_len = %d, eima_dst_len = %d\n",
		*dst_len, EIMA_SRC_LEN, EIMA_DST_LEN);

	if (ret != TEE_SUCCESS) {
		tloge("EIMA Rsp: decrypt failed %x\n", ret);
		s_ret = memset_s(g_eima_nounce, sizeof(g_eima_nounce), 0x0,
			sizeof(g_eima_nounce));
		if (s_ret != EOK) {
			tloge("memset_s fail\n");
			return TEE_ERROR_GENERIC;
		}

		return AR_ERR_SYS_ERROR;
	}

	return ret;
}

static TEE_Result cmd_eima_rsp(tee_rm_command *cmd)
{
	TEE_Result ret;
	errno_t s_ret;
	uint32_t dst_len = 0;
	tee_rm_command *tmp_cmd = NULL;
	tee_eima_response *tmp_rsp = NULL;
	uint8_t msg_type;

	if (cmd == NULL) {
		tloge("EIMA Rsp: bad params, cmd is NULL\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	tmp_cmd = (tee_rm_command *)TEE_Malloc(EIMA_DST_LEN, 0);
	if (tmp_cmd == NULL) {
		tloge("EIMA Rsp: malloc failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* decrypt the rsp content */
	ret = decrypt_rsp_content(cmd, tmp_cmd, &dst_len);
	if (ret != TEE_SUCCESS) {
		TEE_Free(tmp_cmd);
		tmp_cmd = NULL;
		return ret;
	}

	/* get the response type */
	tmp_rsp = (tee_eima_response *)&(tmp_cmd->content);
	msg_type = tmp_rsp->msg_type;

	s_ret = memset_s(g_eima_nounce, sizeof(g_eima_nounce),
		0x0, sizeof(g_eima_nounce));
	if (s_ret != EOK) {
		tloge("memset_s fail\n");
		TEE_Free(tmp_cmd);
		tmp_cmd = NULL;
		return TEE_ERROR_GENERIC;
	}

	/* call the hand_response_msg function */
	ret = hand_response_msg(msg_type, tmp_cmd->buf, dst_len);
	if (ret)
		tloge("EIMA measurement update fail 0x%x\n", ret);

	TEE_Free(tmp_cmd);
	tmp_cmd = NULL;

	return ret;
}

static TEE_Result eima_generate_new_iv_and_encrypt(tee_rm_command *cmd,
				tee_rm_command *dec_cmd,
				uint8_t *nounce, uint32_t nounce_len)
{
	errno_t s_ret;
	uint32_t dst_len;
	uint8_t cha_iv[EIMA_IV_LEN] = { 0 };
	TEE_Result ret;

	TEE_GenerateRandom(cha_iv, EIMA_IV_LEN);
	s_ret = memcpy_s(cmd, EIMA_IV_LEN, cha_iv, EIMA_IV_LEN);
	if (s_ret != EOK) {
		tloge("memcpy_s fail\n");
		return TEE_ERROR_GENERIC;
	}

	ret = TEE_EXT_AES_CRYPTO(EIMA_DB, cha_iv,
				EIMA_ENCRYPTO, TEE_ALG_AES_CBC_NOPAD,
				nounce, nounce_len,
				(uint8_t *)dec_cmd,
				(uint8_t *)cmd + EIMA_IV_LEN,
				EIMA_SRC_LEN, &dst_len);
	if (ret != TEE_SUCCESS) {
		tloge("invoke encrypto failed %x\n", ret);
		ret = AR_ERR_SYS_ERROR;
	}

	return ret;
}

static TEE_Result cmd_eima_challenge(tee_rm_command *cmd)
{
	TEE_Result ret;
	tee_rm_command *dec_cmd = NULL;
	errno_t s_ret;
	uint8_t nounce[COUNTER_LENGTH] = { 0 };

	if (cmd == NULL) {
		tloge("cmd eima challenge: bad params, cmd is NULL\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	dec_cmd = (tee_rm_command *)((uint8_t *)cmd + EIMA_IV_LEN);
	s_ret = memcpy_s(nounce, COUNTER_LENGTH,
			dec_cmd->content.eima_challenge.nounce, COUNTER_LENGTH);
	if (s_ret != EOK) {
		tloge("memcpy_s fail\n");
		return TEE_ERROR_GENERIC;
	}

	/* init nounce */
	s_ret = memset_s(g_eima_nounce, COUNTER_LENGTH, 0, COUNTER_LENGTH);
	if (s_ret != EOK) {
		tloge("memset_s fail\n");
		return TEE_ERROR_GENERIC;
	}
	/* Generate random nonce */
	TEE_GenerateRandom(g_eima_nounce, COUNTER_LENGTH);

	dec_cmd = (tee_rm_command *)TEE_Malloc(EIMA_DST_LEN, 0);
	if (dec_cmd == NULL) {
		tloge("cmd eima challenge: malloc failed!\n");
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	s_ret = memcpy_s(dec_cmd->content.eima_challenge.nounce,
				COUNTER_LENGTH, g_eima_nounce,
				sizeof(g_eima_nounce));
	if (s_ret != EOK) {
		tloge("memcpy_s fail\n");
		TEE_Free(dec_cmd);
		dec_cmd = NULL;
		return TEE_ERROR_GENERIC;
	}

	/* generate new IV and encrypt */
	ret = eima_generate_new_iv_and_encrypt(cmd, dec_cmd,
				nounce, sizeof(nounce));
	if (ret != TEE_SUCCESS)
		/* continue to TEE Free dec_cmd */
		tloge("eima generate new iv and encrypt failed %x\n", ret);

	TEE_Free(dec_cmd);
	dec_cmd = NULL;
	return ret;
}

TEE_Result eima_init(void)
{
	tlogd("hello eima root!\n");
	errno_t s_ret;

	s_ret = memset_s(&g_eima_whitelist, sizeof(g_eima_whitelist),
			0x00, sizeof(eima_whitelist));
	if (s_ret != EOK) {
		tloge("memset_s fail\n");
		return TEE_ERROR_SECURITY;
	}

	s_ret = memset_s(&g_eima_runtimelist, sizeof(g_eima_runtimelist),
			0x00, sizeof(eima_whitelist));
	if (s_ret != EOK) {
		tloge("memset_s fail\n");
		return TEE_ERROR_SECURITY;
	}
	return TEE_SUCCESS;
}

static TEE_Result eima_handle_cmd_response(TEE_Param params[TEE_MAX_PARAM_NUM],
			tee_rm_command *eima_cmd)
{
	TEE_Result ret;
	errno_t s_ret;

	ret = cmd_eima_rsp(eima_cmd);
	if (ret == AR_ERR_RSP_CHECK_FAIL) {
		params[1].value.a = REV_ROOTED;
		s_ret = memcpy_s(params[0].memref.buffer,
				params[0].memref.size,
				g_hash_error_file_path,
				FNAME_LENGTH);
		if (s_ret != EOK) {
			tloge("EIMA: copy tampered file path error!\n");
			return TEE_ERROR_GENERIC;
		}
		tlogd("tampered file path: %s",
				(char *)(params[0].memref.buffer));
	} else {
		s_ret = memset_s(params[0].memref.buffer,
				params[0].memref.size,
				0, FNAME_LENGTH);
		if (s_ret != EOK) {
			tloge("EIMA: set tampered file path"
				" full zero 0 error!\n");
			return TEE_ERROR_GENERIC;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result eima_handle_cmd_challenge(tee_rm_command *eima_cmd)
{
	TEE_Result ret = TEE_SUCCESS;

	if (g_cmd_state == EIMA_STATE_CHALLENGE) {
		ret = cmd_eima_challenge(eima_cmd);
		if (ret == TEE_SUCCESS) {
			g_cmd_state = EIMA_STATE_RESPONSE;
			g_cmd_error = 0;
		}
	} else {
		tloge("EIMA: error cmd state for challenge!\n");
		g_cmd_error++;
	}

	return ret;
}

TEE_Result eima_handle_cmd(TEE_Param params[TEE_MAX_PARAM_NUM],
			uint32_t cmd_id)
{
	TEE_Result ret;
	tee_rm_command *eima_cmd = NULL;
	uint32_t root_status;

	if (params[0].memref.buffer == NULL) {
		tloge("ERROR: bad params!\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	eima_cmd = params[0].memref.buffer;
	if (params[0].memref.size != SIZE_CMD_BUFF) {
		tloge("EIMA: command id: 0x%x, size: %u\n",
			cmd_id, params[0].memref.size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	switch (cmd_id) {
	case CMD_EIMA_CHALLENGE:
		ret = eima_handle_cmd_challenge(eima_cmd);
		break;
	case CMD_EIMA_RESPONSE:
		ret = eima_handle_cmd_response(params, eima_cmd);
		if (ret != TEE_SUCCESS) {
			tloge("EIMA: error cmd state for response!\n");
			return ret;
		}
		g_cmd_state = EIMA_STATE_CHALLENGE;
		break;
	default:
		tloge("EIMA: Invalid CMD ID!\n");
		ret = AR_ERR_INVOKE_ERROR;
		break;
	}

	if (g_cmd_error >= MAX_ERROR_TIME) {
		root_status = 0x1 << CHECKFAILBIT;
		tloge("rstatus is 0x%x\n", root_status);
		if (__SRE_WriteRootStatus(root_status)) {
			tloge("antiroot: write rstatus error!\n");
			return AR_ERR_SYS_ERROR;
		}
		params[1].value.a = REV_ROOTED;
	}

	return  ret;
}

void eima_deinit(void)
{
	eima_free_whitelist(&g_eima_whitelist);
	eima_free_whitelist(&g_eima_runtimelist);
}
