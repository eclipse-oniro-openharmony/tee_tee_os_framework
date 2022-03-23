/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: Antiroot TA which process message from rootscan CA
 * Create: 2018-05-21
 */

#ifdef DEF_ENG
#define PRINT_HASHES
#define DEBUG_DUMP_HEX
#define LOG_ON
#endif

#include "antiroot_task.h"
#include <string.h>
#include "crys_hash.h"
#include "hmdrv.h"
#include "root_status_ops.h"
#include "securec.h"
#include "sre_syscalls_id_ext.h"
#include "tee_crypto_api.h"
#include "tee_ext_api.h"
#include "tee_log.h"
#include "tee_mem_mgmt_api.h"
#include "tee_private_api.h"
#include "tee_time_api.h"

#define MAX_SE_HOOKS 360

static whitelist g_whitelist;
static uint16_t g_challenge;
static unsigned char g_nounce[COUNTER_LENGTH];
static int32_t g_invoke_cmd_state = STATE_INIT;
static uint32_t g_invoke_err_counter;
/* for g_statistics of Challengeid */
static uint32_t g_statistics[MAX_CHALLENGE_LENGTH];

#ifdef TEE_KERNEL_MEASUREMENT
static paddr_t g_kstart;
static paddr_t g_kend;
static paddr_t g_se_hooks_phy[MAX_SE_HOOKS];
static paddr_t g_se_hooks_num;
static paddr_t g_sys_call_phy_start;
static paddr_t g_sys_call_phy_end;
static bool g_pause_measurement;
static bool g_get_kernel_address;
#endif

#ifdef TEE_RODATA_MEASUREMENT
static paddr_t g_ro_data_start;
static paddr_t g_ro_data_end;
#endif

#define SHA256_HOOKS_LEN  8
#define KERNEL_MEM_SLICE  0x80000000u

/* scan period */
#define TIME_SCAN_CYCLE   610 /* 10mins cycle + 10sec buffer */
#define TIME_GET_RESPON   5   /* 5 seconds */

/* time define */
#define ONE_DAY_HOURS     24 /* one day has 24 hours */
#define ONE_HOUR_MINUTES  60 /* one hour has 60 minutes */
#define USER_SLEEP_TIME   (23 * ONE_HOUR_MINUTES) /* USER sleep time 23:00 */
#define USER_WAKE_UP_TIME (7 * ONE_HOUR_MINUTES)  /* USER wake up time 07:00 */

#if defined(DEBUG_DUMP_HEX) || defined(PRINT_HASHES)
#define DUMP_BUF_LEN       58 /* dump temp array buf length */
#define ARG_LIST_LEN       16
#endif

#define HIGH_CPU_LOAD      10
#define LOW_BATTERY        50
/* (busy_ratio * BUSY_RATIO_RADIX) make 0 < busy_ratio < 100 */
#define BUSY_RATIO_RADIX   25
#define BUSY_RATIO_PERCENT 100

#define RANDOM_RAN_LEN     2 /* random variable 'ran' length */

static const operation_config g_operation_configs[] = {
	{ KERNELCODE,     1, 10, 1, KERNELCODEBIT},
	{ SYSTEMCALL,     1, 10, 1, SYSTEMCALLBIT},
	{ ROOTPROC,       0, 1, 1, ROOTPROCBIT},
	{ SESTATUS,       1, 1, 1, SESTATUSBIT},
	{ SEHOOK,         0, 10, 1, SEHOOKBIT},
	{ SETID,          1, 1, 1, SETID},
	{ RODATA,         1, 10, 1, RODATABIT},
	{ SEPOLICY,       0, 1, 1, SEPOLICYBIT},
	{ PROCINTER,      0, 10, 1, PROCINTERBIT},
	{ FRAMINTER,      0, 1, 1, FRAMINTERBIT},
	{ INAPPINTER,     0, 1, 1, INAPPINTERBIT},
	{ CPUUTIL,        0, 1, 1, TOTALBIT},
	{ POWER,          0, 1, 1, TOTALBIT},
	{ ISCHARGE,       0, 1, 1, TOTALBIT},
	{ CURRENTTIME,    0, 1, 1, TOTALBIT},
	{ NOOP,           1, 1, 1, NOOPBIT},
};

struct check_status {
	uint32_t     status;
	unsigned int error_count;
	TEE_Result   first_error;
};

typedef union {
	hash_t used_hash;
	uint32_t data[CRYS_HASH_RESULT_SIZE_IN_WORDS];
} generic_hash_t;

static int32_t nshasher_sha256_start(void)
{
	uint64_t args[] = {
		(uint64_t)CRYS_HASH_SHA256_mode
	};
	return hm_drv_call(SW_SYSCALL_NSHASHER_START, args, ARRAY_SIZE(args));
}

static uint32_t nshasher_sha256_finish(int32_t ctx, const generic_hash_t *out)
{
	if (out == NULL) {
		tloge("nshasher sha256 finish input hash error\n");
		return TEE_ERROR_GENERIC;
	}
	uint64_t args[] = {
		(uint64_t)ctx,
		(uint64_t)(uintptr_t)out
	};

	return hm_drv_call(SW_SYSCALL_NSHASHER_FINISH, args, ARRAY_SIZE(args));
}

static uint32_t nshasher_sha256_update_ns(int32_t ctx,
					  paddr_t phy, uint32_t size)
{
	uint64_t args[] = {
		(uint64_t)ctx,
		(uint64_t)phy,
		(uint64_t)size,
	};
	return hm_drv_call(SW_SYSCALL_NSHASHER_UPDATE_FROM_NS, args,
			ARRAY_SIZE(args));
}

static TEE_Result sha256_address_range(paddr_t start, paddr_t end, hash_t *out)
{
	generic_hash_t hash;
	int32_t ctx;

	if (out == NULL) {
		tloge("sha256 address range input hash error\n");
		return TEE_ERROR_GENERIC;
	}

	ctx = nshasher_sha256_start();
	if (ctx < 0) {
		tloge("unable to initiate hashing\n");
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	while (start < end) {
		paddr_t len = end - start;

		if (len > KERNEL_MEM_SLICE)
			len = KERNEL_MEM_SLICE; /* fits in uint32_t */
		if (nshasher_sha256_update_ns(ctx, start, (uint32_t)len)) {
			tloge("hash update failed\n");
			nshasher_sha256_finish(ctx, NULL);
			return TEE_ERROR_GENERIC;
		}
		start += len;
	}
	if (nshasher_sha256_finish(ctx, &hash)) {
		tloge("unable to finish hashing\n");
		return TEE_ERROR_GENERIC;
	}

	*out = hash.used_hash;
	return TEE_SUCCESS;
}

static TEE_Result sha256_hooks(paddr_t *pa_list, paddr_t count, hash_t *out)
{
	generic_hash_t hash;
	int32_t ctx;

	if (out == NULL || pa_list == NULL) {
		tloge("sha256 hooks input error\n");
		return TEE_ERROR_GENERIC;
	}

	ctx = nshasher_sha256_start();
	if (ctx < 0) {
		tloge("unable to initiate hashing\n");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	while (count--) {
		if (nshasher_sha256_update_ns(ctx, *pa_list++,
					SHA256_HOOKS_LEN) != 0) {
			tloge("hash update failed\n");
			nshasher_sha256_finish(ctx, NULL);
			return TEE_ERROR_GENERIC;
		}
	}
	if (nshasher_sha256_finish(ctx, &hash) != 0) {
		tloge("unable to finish hashing\n");
		return TEE_ERROR_GENERIC;
	}

	*out = hash.used_hash;
	return TEE_SUCCESS;
}

#if defined(DEBUG_DUMP_HEX) || defined(PRINT_HASHES)
static int _print(char **p, const char *e, const char *fmt, ...)
{
	va_list v;
	int delta;

	va_start(v, fmt);
	delta = vsnprintf_s(*p, e - *p, e - *p - 1, fmt, v);
	va_end(v);
	if (delta >= 0)
		*p += delta;
	else
		tloge("vsnprintf_s fail, line = %d\n", __LINE__);
	return delta;
}

static void _dump(const void *data, size_t size, const char *comment)
{
	const uint8_t *bytes = data;
	char buf[DUMP_BUF_LEN] = { 0 };
	const char *e = buf + ARRAY_SIZE(buf);
	char *p = NULL;
	int ret;

	for (uint32_t line = 0; size; line += ARG_LIST_LEN) {
		p = buf;
		ret = _print(&p, e, "%08x:", line);
		if (ret < 0)
			return;
		for (int i = ARG_LIST_LEN; i-- && size; --size) {
			ret = _print(&p, e, " %02x", *bytes++);
			if (ret < 0)
				return;
		}
		if ((line != 0) || (comment == NULL))
			tlogd("%s\n", buf);
		else
			tlogd("%-57s %s\n", buf, comment);
	}
}
#endif

#ifdef DEBUG_DUMP_HEX
#define DUMP_HEX _dump
#else
#define DUMP_HEX(...)
#endif

static void dump_hash(const hash_t *hash, const char *comment)
{
#ifdef PRINT_HASHES
	_dump(hash, sizeof(*hash), comment);
#else
	(void)hash;
	(void)comment;
#endif
}

static bool is_procs_list_valid(char *procs_list)
{
	char *buf = procs_list;
	char *sub_procs_list = NULL;
	uint32_t sub_white_list_len;
	bool flags = false;
	char *next_token = NULL;

	if ((buf == NULL) || (strlen(buf) == 0)) {
		tloge("procs len is invalid\n");
		return false;
	}

	if (g_whitelist.root_procs == NULL) {
		tloge("g_whitelist.root_procs is invalid\n");
		return false;
	}

	sub_procs_list = strtok_s(buf, ":", &next_token);
	while (sub_procs_list != NULL) {
		flags = false;
		uint32_t n = 0;
		int32_t ret;
		char *sub_white_list = (char *)g_whitelist.root_procs;

		while (n < g_whitelist.procs_len) {
			sub_white_list_len = strlen(sub_white_list);
			if (sub_white_list_len != strlen(sub_procs_list)) {
				sub_white_list += (sub_white_list_len + 1);
				n += (sub_white_list_len + 1);
				continue;
			}
			ret = TEE_MemCompare(sub_procs_list,
					sub_white_list, sub_white_list_len);
			sub_white_list += (sub_white_list_len + 1);
			if (ret == 0) {
				flags = true;
				break;
			}

			n += (sub_white_list_len + 1);
		}
		if (!flags) {
			tlogd("procs list is invalid, sub_procs_list = %s\n",
				sub_procs_list);
			return false;
		}
		sub_procs_list = strtok_s(NULL, ":", &next_token);
	}

	tlogd("procs list is valid\n");
	return true;
}

static void print_whitelist_value(void)
{
#ifndef TEE_KERNEL_MEASUREMENT
#ifdef DEF_ENG
	dump_hash(&g_whitelist.kernel_hash, "g_whitelist.kernel_hash");
	dump_hash(&g_whitelist.sys_call_hash, "g_whitelist.sys_call_hash");
	dump_hash(&g_whitelist.se_hooks_hash, "g_whitelist.se_hooks_hash");
#ifdef TEE_RODATA_MEASUREMENT
	dump_hash(&g_whitelist.ro_data_hash, "g_whitelist.ro_data_hash");
#endif
#endif
#endif
	tlogd("cmd_set_wlist: g_whitelist.se_linux_switch = %u\n",
		g_whitelist.se_linux_switch);
	tlogd("cmd_set_wlist: g_whitelist.procs_len = %u\n",
		g_whitelist.procs_len);
	tlogd("cmd_set_wlist: g_whitelist.setid = %u\n", g_whitelist.setid);
}

static TEE_Result set_whitelist_proc_value(const tee_rm_command *cmd)
{
	int ret;
	char *buf = NULL;
	char *next_token = NULL;
	char *substr = NULL;

	if ((g_whitelist.procs_len <= 0) ||
		(g_whitelist.procs_len >= (MAX_PROCSLEN - 1))) {
		tloge("cmd_set_wlist failed, procs_len is %u\n",
			g_whitelist.procs_len);
		return AR_ERR_INVOKE_ERROR;
	}
	g_whitelist.root_procs =
		(unsigned char *)TEE_Malloc(g_whitelist.procs_len + 1, 0);

	if (g_whitelist.root_procs == NULL) {
		tloge("cmd_set_wlist: root_procs TEE_Malloc fail\n");
		return AR_ERR_OUT_OF_MEM;
	}

	ret = memcpy_s(g_whitelist.root_procs, g_whitelist.procs_len,
			cmd->buf, g_whitelist.procs_len);
	if (ret != EOK) {
		tloge("cmd_set_wlist: memcpy_s fail\n");
		return AR_ERR_SYS_ERROR;
	}

	tlogd("cmd_set_wlist: cmd.root_procs = %s\n", cmd->buf);
	tlogd("cmd_set_wlist: g_whitelist.root_procs = %s\n",
		g_whitelist.root_procs);
	buf = (char *)g_whitelist.root_procs;

	/* cut root_procs into several strings, and seperate by '\0' */
	substr = strtok_s(buf, ":", &next_token);
	while (substr != NULL)
		substr = strtok_s(NULL, ":", &next_token);

	return TEE_SUCCESS;
}

static TEE_Result set_whitelist_value(const tee_rm_white_list *list_config,
				const tee_rm_command *cmd)
{
	int ret;
	TEE_Result tee_ret;

	tlogd("sizeof(g_whitelist) = %u\n", sizeof(g_whitelist));
	ret = memset_s(&g_whitelist, sizeof(g_whitelist),
		0x00, sizeof(g_whitelist));
	if (ret != EOK) {
		tloge("memset_s fail\n");
		return AR_ERR_SYS_ERROR;
	}

	g_whitelist.d_status = list_config->d_status;
	tlogd("cmd_set_wlist: d_status = %u, list_config->d_status = %u\n",
		g_whitelist.d_status, list_config->d_status);

	g_whitelist.kernel_hash = list_config->kcode;
	g_whitelist.sys_call_hash = list_config->syscalls;
	g_whitelist.se_hooks_hash = list_config->sehooks;
#ifdef TEE_RODATA_MEASUREMENT
	g_whitelist.ro_data_hash = list_config->rodata;
#endif
	g_whitelist.se_linux_switch = list_config->selinux;
	g_whitelist.procs_len = list_config->procs_len;
	g_whitelist.setid = list_config->setid;

	print_whitelist_value();

	tee_ret = set_whitelist_proc_value(cmd);
	if (tee_ret != TEE_SUCCESS)
		return ret;

	return TEE_SUCCESS;
}

static TEE_Result set_challenge_req_key(const tee_rm_cipher_key *key_config)
{
	int ret_tmp;
	TEE_Result ret;

	ret_tmp = memcpy_s(g_whitelist.cha_req_key, KEY_LENGTH,
			key_config->cha_req_key, KEY_LENGTH);
	if (ret_tmp != EOK) {
		tloge("memcpy_s fail\n");
		return AR_ERR_SYS_ERROR;
	}

	ret_tmp = memcpy_s(g_whitelist.cha_key, KEY_LENGTH,
			key_config->cha_key, KEY_LENGTH);
	if (ret_tmp != EOK) {
		tloge("memcpy_s fail\n");
		return AR_ERR_SYS_ERROR;
	}

	DUMP_HEX(g_whitelist.cha_req_key, KEY_LENGTH,
		"g_whitelist.cha_req_key");
	DUMP_HEX(g_whitelist.cha_key, KEY_LENGTH, "g_whitelist.cha_key");

	tlogi("cmd_set_wlist ok\n");

	ret = TEE_ANTI_ROOT_CreateTimer(TIME_SCAN_CYCLE);
	if (ret != TEE_SUCCESS) {
		tloge("cmd_set_wlist: TEE_ANTI_ROOT_CreateTimer error, ret = %x\n", ret);
		return AR_ERR_SYS_ERROR;
	}
	tlogd("create timer1\n");

	return TEE_SUCCESS;
}

static TEE_Result cmd_set_wlist(const tee_rm_command *cmd)
{
	TEE_Result ret;

	tlogd("------sizeof tee_rm_config = %u\n", sizeof(tee_rm_config));

	if (cmd == NULL) {
		tloge("cmd set wlist failed, cmd is NULL\n");
		return AR_ERR_INVOKE_ERROR;
	}

	tee_rm_config *rm_config = (tee_rm_config *)(&(cmd->content));
	tee_rm_white_list *list_config = &(rm_config->white_list);
	tee_rm_cipher_key *key_config = &(rm_config->cipher_key);

	ret = set_whitelist_value(list_config, cmd);
	if (ret != TEE_SUCCESS)
		return ret;

	/* add for encrypt&decrypt key and counter */
	ret = set_challenge_req_key(key_config);

	return ret;
}

/* assume we can scan in time: 11pm-7am, user may sleep. */
static uint32_t is_sleep_time(uint32_t curtime, uint32_t timezone_min)
{
	uint32_t localtime_min = (curtime / ONE_HOUR_MINUTES - timezone_min) %
				(ONE_DAY_HOURS * ONE_HOUR_MINUTES);

	return ((localtime_min > USER_SLEEP_TIME) ||
		(localtime_min < USER_WAKE_UP_TIME));
}

/*
 * busy_ratio=0: idle & charging. good for heavy challenge
 * busy_ratio=100: low battery, high cpu load. bad for heavy challenge
 */
static int busy_radio_count(const tee_rm_challenge *tmp_chg)
{
	int busy_ratio = 0;

	if (tmp_chg->cpu > HIGH_CPU_LOAD)
		busy_ratio++;
	if (tmp_chg->power < LOW_BATTERY)
		busy_ratio++;
	if (!(tmp_chg->charger))
		busy_ratio++;
	if (!is_sleep_time(tmp_chg->time, tmp_chg->timezone))
		busy_ratio++;
	busy_ratio *= BUSY_RATIO_RADIX;

	tlogd("busy_ratio = %d\n", busy_ratio);
	return busy_ratio;
}

static TEE_Result decrypt_challenge_request(tee_rm_command **dec_cmd,
					const tee_rm_command *cmd)
{
	uint32_t dst_len = 0;
	TEE_Result ret;

	*dec_cmd = (tee_rm_command *)TEE_Malloc(ANTIROOT_DST_LEN, 0);
	if (*dec_cmd == NULL) {
		tloge("SendChallenge: malloc failed");
		return AR_ERR_OUT_OF_MEM;
	}
	tlogd("SendChallenge: cmd %p, en&de %d, src %p , len %d, len addr %p\n",
		cmd, ANTIROOT_DECRYPTO,
		(uint8_t *)cmd + ANTIROOT_IV_LEN,
		ANTIROOT_SRC_LEN, &dst_len);

	ret = TEE_EXT_AES_CRYPTO(ANTIROOT_DB,
				(uint8_t *)cmd, ANTIROOT_DECRYPTO,
				TEE_ALG_AES_CBC_NOPAD,
				g_whitelist.cha_req_key,
				ARRAY_SIZE(g_whitelist.cha_req_key),
				(uint8_t *)cmd + ANTIROOT_IV_LEN,
				(uint8_t *)*dec_cmd,
				ANTIROOT_SRC_LEN, &dst_len);
	if (ret != TEE_SUCCESS) {
		tloge("invoke decrypt failed %x\n", ret);
		TEE_Free(*dec_cmd);
		*dec_cmd = NULL;
		return AR_ERR_SYS_ERROR;
	}
	return ret;
}

static void print_send_challenge_log(const tee_rm_challenge *tmp_chg)
{
	tlogd("SendChallenge: cpu = %u\n", tmp_chg->cpu);
	tlogd("SendChallenge: power = %u\n", tmp_chg->power);
	tlogd("SendChallenge: charger = %u\n", tmp_chg->charger);
	tlogd("SendChallenge: time = %u\n", tmp_chg->time);
	tlogd("SendChallenge: timezone = %u\n", tmp_chg->timezone);

	(void)tmp_chg;
}

static bool get_challenge_continue_check(uint32_t count)
{
	uint32_t root_status;

	/*
	 * the __SRE_WriteRootStatus only allow change bits from "0" to "1",
	 * so if the item has abnormal, TA continue check is useless,
	 * CA continue to check in eng version, can resume for testing.
	 */
	if (get_eng_status() == ENG_VERSION)
		return true;

	/*
	 * The user version not need check item, when it has abnormal,
	 * the __SRE_WriteRootStatus only allow change bits from "0" to "1",
	 * so if the item is abnormal, TA continue check is useless,
	 * if the item is abnormal, CA continue check maybe not safe.
	 */
	root_status = __SRE_ReadRootStatus();
	if (root_status & (1U << (g_operation_configs[count].root_status_bit)))
		return false;

	return true;
}

static TEE_Result get_challenge_and_statistics_freq(uint32_t idx,
						int busy_ratio, long *freq)
{
	if (g_operation_configs[idx].max_period <
		g_operation_configs[idx].idle_period) {
		tloge("SendChallenge config period is error!\n");
		return AR_ERR_INVOKE_ERROR;
	}
	*freq = (g_operation_configs[idx].max_period -
		g_operation_configs[idx].idle_period) *
		busy_ratio / BUSY_RATIO_PERCENT +
		g_operation_configs[idx].idle_period;

	return TEE_SUCCESS;
}

static TEE_Result check_challenge_and_statistics_freq(uint32_t idx,
		uint32_t *tmp_chid, int tmp_chid_len, int *count, long freq)
{
	uint16_t ran = 0;
	int count_tmp = *count;

	TEE_GenerateRandom(&ran, RANDOM_RAN_LEN);
	if (((ran & 0xffff) * freq) <= ANTIROOT_RAND_MAX) {
		if (count_tmp >= tmp_chid_len) {
			tloge("Invalid count %d in operation config\n", count_tmp);
			return AR_ERR_INVOKE_ERROR;
		}

		tmp_chid[count_tmp++] = idx + 1;
		*count = count_tmp;
		g_challenge |= 1 << idx;
		g_statistics[idx] += 1;
	}

	return TEE_SUCCESS;
}

static TEE_Result get_challenge_and_statistics_value(int busy_ratio,
				uint32_t *tmp_chid, int tmp_chid_len)
{
	uint32_t i;
	bool is_continue = true;
	long freq = 0;
	int count = 0;
	TEE_Result ret;

	g_challenge = 0;
	for (i = 0; i < ARRAY_SIZE(g_operation_configs); i++) {
		is_continue = get_challenge_continue_check(i);
		if (is_continue == false)
			continue;

		if (!g_operation_configs[i].enabled) {
			if (g_operation_configs[i].opid >= tmp_chid_len) {
				tloge("Invalid opid %d in operation config\n",
					g_operation_configs[i].opid);
				return AR_ERR_INVOKE_ERROR;
			}

			tmp_chid[g_operation_configs[i].opid] = 0;
			continue;
		}

		ret = get_challenge_and_statistics_freq(i, busy_ratio, &freq);
		if (ret != TEE_SUCCESS)
			return ret;

		ret = check_challenge_and_statistics_freq(i, tmp_chid,
						tmp_chid_len, &count, freq);
		if (ret != TEE_SUCCESS)
			return ret;
	}
#ifdef LOG_ON
	for (i = 0; (i < ARRAY_SIZE(g_operation_configs)) && (i < MAX_CHALLENGE_LENGTH); i++) {
		if (g_statistics[i] != 0)
			tlogd("g_statistics[%u] = %u\n", i, g_statistics[i]);
	}
#endif

	tlogd("SendChallenge: g_challenge = 0x%x\n", g_challenge);
	return TEE_SUCCESS;
}

static TEE_Result get_challengeid_and_nounce_value(tee_rm_challenge *tmp_chg,
						const uint32_t *tmp_chid,
						int tmp_chid_len)
{
	int tmp_ret;

	tmp_ret = memcpy_s(tmp_chg->challengeid, sizeof(tmp_chg->challengeid),
			tmp_chid, tmp_chid_len);
	if (tmp_ret != EOK) {
		tloge("memcpy_s fail\n");
		return AR_ERR_SYS_ERROR;
	}

	tmp_ret = memset_s(g_nounce, COUNTER_LENGTH, 0, COUNTER_LENGTH);
	if (tmp_ret != EOK) {
		tloge("memset_s fail\n");
		return AR_ERR_SYS_ERROR;
	}

	TEE_GenerateRandom(g_nounce, COUNTER_LENGTH);
	tmp_ret = memcpy_s(tmp_chg->nounce, COUNTER_LENGTH,
			g_nounce, sizeof(g_nounce));
	if (tmp_ret != EOK) {
		tloge("memcpy_s fail\n");
		return AR_ERR_SYS_ERROR;
	}

	tlogd("SendChallenge: tmp_chg 0x%p\n", tmp_chg);
	return TEE_SUCCESS;
}

static TEE_Result antiroot_generate_new_iv_and_encrypt(tee_rm_command *cmd,
					tee_rm_command *dec_cmd)
{
	int tmp_ret;
	uint32_t src_len = 0;
	uint8_t cha_iv[ANTIROOT_IV_LEN] = {0};
	TEE_Result ret;

	TEE_GenerateRandom(cha_iv, ANTIROOT_IV_LEN);

	tmp_ret = memcpy_s(cmd, ANTIROOT_IV_LEN, cha_iv, ANTIROOT_IV_LEN);
	if (tmp_ret != EOK) {
		tloge("memcpy_s fail\n");
		return AR_ERR_SYS_ERROR;
	}

	ret = TEE_EXT_AES_CRYPTO(ANTIROOT_DB, cha_iv,
				ANTIROOT_ENCRYPTO, TEE_ALG_AES_CBC_NOPAD,
				g_whitelist.cha_key,
				ARRAY_SIZE(g_whitelist.cha_key),
				(uint8_t *)dec_cmd,
				(uint8_t *)cmd + ANTIROOT_IV_LEN,
				ANTIROOT_SRC_LEN, &src_len);
	tlogd("SendChallenge: src_len = %u\n", src_len);
	if (ret != TEE_SUCCESS) {
		tloge("invoke encrypto failed %x\n", ret);
		ret = AR_ERR_SYS_ERROR;
	}
	return ret;
}

static TEE_Result cmd_send_challenge(tee_rm_command *cmd)
{
	TEE_Result ret;
	int busy_ratio;
	uint32_t tmp_chid[MAX_CHALLENGE_LENGTH] = {0};
	tee_rm_command *dec_cmd = NULL;

	if (cmd == NULL) {
		tloge("SendChallenge: failed, cmd is NULL.\n");
		return AR_ERR_INVOKE_ERROR;
	}

	ret = TEE_ANTI_ROOT_DestoryTimer();
	if (ret != TEE_SUCCESS)
		tloge("DestoryTimer fail, ret = %x\n", ret);

	ret = TEE_ANTI_ROOT_CreateTimer(TIME_GET_RESPON);
	if (ret != TEE_SUCCESS) {
		tloge("cmd send challenge TEE_ANTI_ROOT_CreateTimer error, ret = %x\n", ret);
		return AR_ERR_SYS_ERROR;
	}
	tlogd("destory timer1, create timer2\n");

	/* for decrypt the challenge request */
	ret = decrypt_challenge_request(&dec_cmd, cmd);
	if (ret != TEE_SUCCESS)
		return ret;

	tee_rm_challenge *tmp_chg = (tee_rm_challenge *) &(dec_cmd->content);

	print_send_challenge_log(tmp_chg);

	/*
	 * busy_ratio=0: idle & charging. good for heavy challenge
	 * busy_ratio=100: low battery, high cpu load. bad for heavy challenge
	 */
	busy_ratio = busy_radio_count(tmp_chg);
	ret = get_challenge_and_statistics_value(busy_ratio,
					tmp_chid, MAX_CHALLENGE_LENGTH);
	if (ret != TEE_SUCCESS) {
		TEE_Free(dec_cmd);
		dec_cmd = NULL;
		return ret;
	}

	ret = get_challengeid_and_nounce_value(tmp_chg, tmp_chid,
						sizeof(tmp_chid));
	if (ret != TEE_SUCCESS) {
		TEE_Free(dec_cmd);
		dec_cmd = NULL;
		return ret;
	}

	/* generate new IV */
	ret = antiroot_generate_new_iv_and_encrypt(cmd, dec_cmd);
	TEE_Free(dec_cmd);
	dec_cmd = NULL;

	return ret;
}

static int hash_cmp(const hash_t *a, const hash_t *b)
{
	return memcmp(a, b, sizeof(hash_t));
}

static TEE_Result eima_check(const hash_t *hash,
		const hash_t *hash_expected,
		uint32_t *status, uint32_t bit,
		const char *comment)
{
	if ((hash == NULL) || (hash_expected == NULL) ||
		(status == NULL) || (comment == NULL)) {
		tloge("eima check input error\n");
		return TEE_ERROR_GENERIC;
	}
	tlogd("-------------------verifying %s\n", comment);
	dump_hash(hash_expected, "(according to white list)");

	int cmp = hash_cmp(hash, hash_expected);
	if (cmp) {
		tlogd("%s hash MISMATCH\n", comment);
		*status |= 1u << bit;
	} else {
		tlogd("%s hash matched\n", comment);
	}
	return TEE_SUCCESS;
}

static void set_error_information(TEE_Result code, struct check_status *result)
{
	if ((code != TEE_SUCCESS) && (result->error_count++ == 0))
		result->first_error = code;
}

static TEE_Result cmd_get_rsp_init(tee_rm_command *cmd,
				tee_rm_command **tmp_cmd)
{
	TEE_Result ret;
	uint32_t dst_len = 0;

	if (cmd == NULL) {
		tloge("GetRsp: failed, cmd is NULL\n");
		return AR_ERR_INVOKE_ERROR;
	}

	ret = TEE_ANTI_ROOT_DestoryTimer();
	if (ret != TEE_SUCCESS)
		tloge("cmd_get_rsp DestoryTimer fail, ret = %x\n", ret);

	ret = TEE_ANTI_ROOT_CreateTimer(TIME_SCAN_CYCLE);
	if (ret != TEE_SUCCESS) {
		tloge("cmd_get_rsp TEE_ANTI_ROOT_CreateTimer , ret = %x\n",
			ret);
		return AR_ERR_SYS_ERROR;
	}

	tlogd("create timer1\n");
	tlogd("------ sizeof tee_rm_command = %u\n", sizeof(tee_rm_command));

	/* decrypt the rsp content */
	*tmp_cmd = (tee_rm_command *)TEE_Malloc(ANTIROOT_DST_LEN, 0);
	if (*tmp_cmd == NULL) {
		tloge("GetRsp: malloc failed");
		return AR_ERR_OUT_OF_MEM;
	}
	tlogd("remain buff len = %d\n",
		(ANTIROOT_DST_LEN - sizeof(tee_rm_command)));

	DUMP_HEX(g_nounce, KEY_LENGTH, "g_nounce");
	DUMP_HEX(cmd, 32, "GetRsp-cmd");
	ret = TEE_EXT_AES_CRYPTO(ANTIROOT_DB, (uint8_t *)cmd,
				ANTIROOT_DECRYPTO, TEE_ALG_AES_CBC_NOPAD,
				g_nounce, sizeof(g_nounce),
				(uint8_t *)cmd + ANTIROOT_IV_LEN,
				(uint8_t *)*tmp_cmd,
				ANTIROOT_SRC_LEN, &dst_len);

	tlogd("GetRsp: dst_len = %u, dump_hex tmp_cmd:\n", dst_len);

	if (ret != TEE_SUCCESS) {
		tloge("GetRsp: invoke decrypt failed %x\n", ret);
		TEE_Free(*tmp_cmd);
		*tmp_cmd = NULL;
		return AR_ERR_SYS_ERROR;
	}
	return TEE_SUCCESS;
}

static void kernel_code_handle(const tee_rm_white_list *tmp_config,
			struct check_status *result)
{
	TEE_Result ret;
	hash_t hash;

#ifdef TEE_KERNEL_MEASUREMENT
	(void)tmp_config;
	ret = sha256_address_range(g_kstart, g_kend, &hash);
	if (ret != TEE_SUCCESS) {
		tloge("kcode do hash failed %x\n", ret);
		set_error_information(ret, result);
		return;
	}
	ret = eima_check(&hash,
			&g_whitelist.kernel_hash,
			&result->status, KERNELCODEBIT,
			"kernel code");
#else
	ret = eima_check(&tmp_config->kcode,
			&g_whitelist.kernel_hash,
			&result->status, KERNELCODEBIT,
			"kernel code");
#endif
	if (ret != TEE_SUCCESS)
		tloge("kcode hash check failed %x\n", ret);
	set_error_information(ret, result);
}

static void system_call_handle(const tee_rm_white_list *tmp_config,
			struct check_status *result)
{
	TEE_Result ret;
	hash_t hash;

#ifdef TEE_KERNEL_MEASUREMENT /* EIMA 2.0 */
	(void)tmp_config;
	ret = sha256_address_range(g_sys_call_phy_start,
				g_sys_call_phy_end, &hash);
	if (ret != TEE_SUCCESS) {
		tloge("syscall do hash failed %x\n", ret);
		set_error_information(ret, result);
		return;
	}

	ret = eima_check(&hash,
			&g_whitelist.sys_call_hash,
			&result->status, SYSTEMCALLBIT,
			"syscalls");
#else /* EIMA 1.0 */
	ret = eima_check(&tmp_config->syscalls,
			&g_whitelist.sys_call_hash,
			&result->status, SYSTEMCALLBIT,
			"syscalls");
#endif
	if (ret != TEE_SUCCESS)
		tloge("syscall hash check failed %x\n", ret);
	set_error_information(ret, result);
}

static void se_hook_handle(const tee_rm_white_list *tmp_config,
			struct check_status *result)
{
	TEE_Result ret;
	hash_t hash;

#ifdef TEE_KERNEL_MEASUREMENT /* EIMA 2.0 */
	(void)tmp_config;
	ret = sha256_hooks(g_se_hooks_phy, g_se_hooks_num, &hash);
	if (ret != TEE_SUCCESS) {
		tloge("sehooks do hash failed %x\n", ret);
		set_error_information(ret, result);
		return;
	}
	ret = eima_check(&hash,
		&g_whitelist.se_hooks_hash,
		&result->status, SEHOOKBIT,
		"selinux hooks");
#else /* EIMA 1.0 */
	ret = eima_check(&tmp_config->sehooks,
		&g_whitelist.se_hooks_hash,
		&result->status, SEHOOKBIT,
		"selinux hooks");
#endif
	if (ret != TEE_SUCCESS)
		tloge("sehooks hash check failed %x\n", ret);
	set_error_information(ret, result);
}

static void root_proc_handle(const tee_rm_white_list *tmp_config,
			const tee_rm_command *tmp_cmd,
			struct check_status *result)
{
	uint32_t len;
	unsigned char *tmp_list = NULL;
	int sret;

	if (g_operation_configs[ROOTPROC].enabled == 0) {
		tloge("RSP: ROOTPROC check is not support for now\n");
		set_error_information(AR_ERR_INVOKE_ERROR, result);
		return;
	}
	/* procs_len's max len is same with REE's rootscan */
	len = tmp_config->procs_len;
	if ((len <= 0) || (len >= (MAX_PROCSLEN - 1))) {
		tloge("RSP: ERROR tmp_config->procs_len = %u\n",
			len);
		result->status |= 0x1 << ROOTPROCBIT;
		return;
	}

	tmp_list = (unsigned char *)TEE_Malloc(len + 1, 0);
	if (tmp_list == NULL) {
		tloge("RSP: ERROR NO MEMORY for rootproclist!\n");
		set_error_information(AR_ERR_OUT_OF_MEM, result);
		return;
	}

	sret = memcpy_s(tmp_list, len, tmp_cmd->buf, len);
	if (sret != EOK) {
		tloge("memcpy_s fail.\n");
		set_error_information(AR_ERR_SYS_ERROR, result);
	} else if (!is_procs_list_valid((char *)tmp_list)) {
		tloge("RSP: ERROR for rootproc list!\n");
		result->status |= 0x1 << ROOTPROCBIT;
	} else {
		tlogd("RSP: SUCCESS for  root proclist value!\n");
	}
	TEE_Free(tmp_list);
}

static void se_status_handle(const tee_rm_white_list *tmp_config,
			struct check_status *result)
{
	tlogd("tmp_config->selinux = %u, g_whitelist.se_linux_switch = %u\n",
		tmp_config->selinux,
		g_whitelist.se_linux_switch);
	if (tmp_config->selinux != g_whitelist.se_linux_switch) {
		tloge("RSP: ERROR for selinux value!\n");
		result->status |= 0x1 << SESTATUSBIT;
	} else {
		tlogd("RSP: SUCCESS for selinux value!\n");
	}
}

static void se_tid_handle(const tee_rm_white_list *tmp_config,
			struct check_status *result)
{
	tlogd(" tmp_config->setid = %u, g_whitelist.setid= %u\n",
		tmp_config->setid, g_whitelist.setid);
	if (tmp_config->setid != g_whitelist.setid) {
		tloge("RSP: ERROR for setid value!\n");
		result->status |= 0x1 << SETIDBIT;
	} else {
		tlogd("RSP: SUCCESS for setid value!\n");
	}
}

#ifdef TEE_RODATA_MEASUREMENT
static void read_only_data_handle(const tee_rm_white_list *tmp_config,
			struct check_status *result)
{
	TEE_Result ret;
	hash_t hash;

#ifdef TEE_KERNEL_MEASUREMENT /* EIMA 2.0 */
	(void)tmp_config;
	ret = sha256_address_range(g_ro_data_start, g_ro_data_end, &hash);
	if (ret != TEE_SUCCESS) {
		tloge("rodata do hash failed %x\n", ret);
		set_error_information(ret, result);
		return;
	}
	ret = eima_check(&hash,
			&g_whitelist.ro_data_hash,
			&result->status, RODATABIT,
			"ro data");
#else /* EIMA 1.0 */
	ret = eima_check(&tmp_config->rodata,
			&g_whitelist.ro_data_hash,
			&result->status, RODATABIT,
			"ro data");
#endif
	if (ret != TEE_SUCCESS)
		tloge("rodata hash check failed %x\n", ret);
	set_error_information(ret, result);
}
#endif

static void cmd_get_rsp_do(chagellenge_id count,
				const tee_rm_response *tmp_rsp,
				const tee_rm_white_list *tmp_config,
				const tee_rm_command *tmp_cmd,
				struct check_status *result)
{
	switch (count) {
	case KERNELCODE:
		kernel_code_handle(tmp_config, result);
		break;
	case SYSTEMCALL:
		system_call_handle(tmp_config, result);
		break;
	case SEHOOK:
		se_hook_handle(tmp_config, result);
		break;
	case ROOTPROC:
		root_proc_handle(tmp_config, tmp_cmd, result);
		break;
	case SESTATUS:
		se_status_handle(tmp_config, result);
		break;
	case SETID:
		se_tid_handle(tmp_config, result);
		break;
#ifdef TEE_RODATA_MEASUREMENT
	case RODATA:
		read_only_data_handle(tmp_config, result);
		break;
#endif
	case NOOP:
		if (tmp_rsp->noop) {
			tloge("RSP: ERROR for noop value!\n");
			result->status |= 0x1 << NOOPBIT;
		} else {
			tlogd("RSP: SUCCESS for NOOP value!\n");
		}
		break;
	default:
		/*
		 * goes here, means we not support this check,
		 * then we threat it like check successed.
		 * we need this to avoid false alarm.
		 */
		tlogi("RSP: unknown g_challenge id!\n");
		break;
	}
}

static struct check_status cmd_get_rsp(tee_rm_command *cmd)
{
	struct check_status result = {
		.status = 0,
		.error_count = 0,
		.first_error = TEE_SUCCESS
	};

	chagellenge_id count;
	tee_rm_response *tmp_rsp = NULL;
	tee_rm_white_list *tmp_config = NULL;
	tee_rm_command *tmp_cmd = NULL;
	TEE_Result ret;

	ret = cmd_get_rsp_init(cmd, &tmp_cmd);
	if (ret != TEE_SUCCESS) {
		set_error_information(ret, &result);
		return result;
	}

	tmp_rsp = (tee_rm_response *)&(tmp_cmd->content);
	tmp_config = (tee_rm_white_list *)&(tmp_rsp->white_list);
	for (count = 0; count < TOTALNUM; count++) {
		/* TA determines not check this item in this timer periods */
		if (!((g_challenge >> (unsigned int)count) & 1))
			continue;

		tlogd("GetRsp: switch count %d\n", count);
		cmd_get_rsp_do(count, tmp_rsp, tmp_config, tmp_cmd, &result);
	}
	TEE_Free(tmp_cmd);
	if (result.status != 0) {
		tloge("the ph is root, status is 0x%x\n", result.status);

		/* write status every time. */
		if (__SRE_WriteRootStatus(result.status)) {
			tloge("antiroot: write status error!\n");
			set_error_information(AR_ERR_SYS_ERROR, &result);
		}
	}

	return result;
}

TEE_Result antiroot_open_session(void)
{
	int ret;

	ret = memset_s(&g_whitelist, sizeof(g_whitelist),
		0x00, sizeof(g_whitelist));
	if (ret != EOK) {
		tloge("memset_s fail\n");
		return AR_ERR_SYS_ERROR;
	}

	return TEE_SUCCESS;
}

static TEE_Result check_error_count(TEE_Result result,
				uint32_t root_status,
				TEE_Param params[TEE_MAX_PARAM_NUM])
{
	if (result != TEE_SUCCESS) {
		g_invoke_err_counter++;
		tloge("err_counter = %u, result = %x\n",
			g_invoke_err_counter, result);
	} else {
		g_invoke_err_counter = 0;
		return result;
	}

	if (g_invoke_err_counter >= MAX_ERROR_TIME) {
		root_status = 0x1 << CHECKFAILBIT;
		tloge("rstatus is 0x%x\n", root_status);
		if (__SRE_WriteRootStatus(root_status)) {
			tloge("antiroot: write rstatus error!\n");
			return AR_ERR_SYS_ERROR;
		}
		params[1].value.a = REV_ROOTED;
	}
	return result;
}

static TEE_Result cmd_send_challenge_handle(tee_rm_command *arcmd)
{
	TEE_Result ret;

	if (g_invoke_cmd_state == STATE_WHITELIST) {
		ret = cmd_send_challenge(arcmd);
		if (ret == TEE_SUCCESS)
			g_invoke_cmd_state = STATE_CHALLENGE;
		else
			tloge("antiroot: CMD_SEND_CHALLENGE fail\n");
	} else {
		tloge("antiroot: CMD_SEND_CHALLENGE state:[%d] is wrong\n",
			g_invoke_cmd_state);
		ret = AR_ERR_INVOKE_ERROR;
	}

	return ret;
}

static TEE_Result cmd_set_whitelist_handle(const tee_rm_command *arcmd)
{
	TEE_Result ret;

	if (g_invoke_cmd_state == STATE_INIT) {
		ret = cmd_set_wlist(arcmd);
		if (ret == TEE_SUCCESS) {
			g_invoke_cmd_state = STATE_WHITELIST;
		} else {
			if (g_whitelist.root_procs != NULL) {
				TEE_Free(g_whitelist.root_procs);
				g_whitelist.root_procs = NULL;
			}
			tloge("antiroot: CMD_SET_WHITELIST fail\n");
		}
	} else {
		tloge("antiroot: CMD_SET_WHITELIST state:[%d] is wrong\n",
			g_invoke_cmd_state);
		ret = AR_ERR_INVOKE_ERROR;
	}

	return ret;
}

#if defined(DEF_ENG) && defined(TEE_KERNEL_MEASUREMENT)
static void cmd_tee_status_test(int test_item)
{
	switch (test_item) {
	case KERNELCODEBIT:
		g_kstart = g_kstart + 1;
		g_kend = g_kend - 1;
		tlogd("antiroot: tee kcode test\n");
		break;
	case SYSTEMCALLBIT:
		g_sys_call_phy_start = g_sys_call_phy_start + 1;
		g_sys_call_phy_end = g_sys_call_phy_end - 1;
		tlogd("antiroot: tee syscall test\n");
		break;
	case SEHOOKBIT:
		g_se_hooks_num = g_se_hooks_num - 1;
		tlogd("antiroot: tee sehooks test\n");
		break;
	case CHECKFAILBIT:
		g_get_kernel_address = false;
		tlogd("antiroot: no kernel address test\n");
		break;
#ifdef TEE_RODATA_MEASUREMENT
	case RODATABIT:
		g_ro_data_start = g_ro_data_start + 1;
		g_ro_data_end = g_ro_data_end - 1;
		tlogd("antiroot: tee rodata test\n");
		break;
#endif
	default:
		tloge("invalid test_item\n");
		break;
	}
}
#endif

static TEE_Result cmd_get_response_handle(TEE_Param params[TEE_MAX_PARAM_NUM],
					tee_rm_command *arcmd)
{
	TEE_Result ret = TEE_SUCCESS;

	if (arcmd == NULL) {
		tloge("get response cmd is faild, cmd is null\n");
		return AR_ERR_INVOKE_ERROR;
	}

	if (g_invoke_cmd_state == STATE_CHALLENGE) {
#ifdef TEE_KERNEL_MEASUREMENT
		if (!g_get_kernel_address) {
			tloge("antiroot: kernel address should send at first\n");
			g_invoke_cmd_state = STATE_WHITELIST;
			ret = AR_ERR_INVOKE_ERROR;
			return ret;
		}

		if (g_pause_measurement) {
			tloge("antiroot: Measurement is paused\n");
			g_invoke_cmd_state = STATE_WHITELIST;
			ret = TEE_ANTI_ROOT_DestoryTimer();
			if (ret != TEE_SUCCESS)
				tloge("at paused DestoryTimer fail, ret = %x\n", ret);
			ret = TEE_ANTI_ROOT_CreateTimer(TIME_SCAN_CYCLE);
			if (ret != TEE_SUCCESS) {
				tloge("at paused TEE_ANTI_ROOT_CreateTimer, ret = %x\n", ret);
				return TEE_ERROR_TIMER_CREATE_FAILED;
			}
			tlogd("at paused create timer1\n");
			return ret;
		}
#endif
		struct check_status status = cmd_get_rsp(arcmd);
		/* set invokecmd return value */
		if (status.status)
			params[1].value.a = REV_ROOTED;

		if (!status.error_count)
			g_invoke_cmd_state = STATE_WHITELIST;
		else
			tloge("antiroot: CMD_GET_RESPONSE fail, %u errors, first is %x\n",
				status.error_count, status.first_error);
	} else {
		tloge("antiroot: CMD_GET_RESPONSE state:[%d] is wrong\n",
			g_invoke_cmd_state);
		ret = AR_ERR_INVOKE_ERROR;
	}
	return ret;
}

#ifdef TEE_KERNEL_MEASUREMENT
static TEE_Result calculate_kernel_hash(TEE_Param params[TEE_MAX_PARAM_NUM])
{
	TEE_Result ret;

	g_kstart = ((paddr_t *)params[0].memref.buffer)[OFFSET_KCODE_ADDR_START];
	g_kend = ((paddr_t *)params[0].memref.buffer)[OFFSET_KCODE_ADDR_END];
	ret = sha256_address_range(g_kstart, g_kend, &g_whitelist.kernel_hash);
	if (ret != TEE_SUCCESS) {
		tloge("antiroot: CMD_GET_REE_KERNEL_PHYSICAL_ADDR fail, line = %d, ret = %x\n", __LINE__, ret);
		return AR_ERR_SYS_ERROR;
	}
	dump_hash(&g_whitelist.kernel_hash, "g_whitelist.kernel_hash");
	return TEE_SUCCESS;
}

static TEE_Result calculate_sys_call_hash(TEE_Param params[TEE_MAX_PARAM_NUM])
{
	TEE_Result ret;

	g_sys_call_phy_start = ((paddr_t *)params[0].memref.buffer)[OFFSET_SYSCALL_ADDR_START];
	g_sys_call_phy_end = g_sys_call_phy_start +
		((paddr_t *)params[0].memref.buffer)[OFFSET_SYSCALL_NUM];
	ret = sha256_address_range(g_sys_call_phy_start,
				g_sys_call_phy_end, &g_whitelist.sys_call_hash);
	if (ret != TEE_SUCCESS) {
		tloge("antiroot: CMD_GET_REE_KERNEL_PHYSICAL_ADDR (sys_call) fail, line = %d, ret = %x\n", __LINE__, ret);
		return AR_ERR_SYS_ERROR;
	}
	dump_hash(&g_whitelist.sys_call_hash, "g_whitelist.sys_call_hash");
	return TEE_SUCCESS;
}

#ifdef TEE_RODATA_MEASUREMENT
static TEE_Result calculate_readonly_data_hash(TEE_Param params[TEE_MAX_PARAM_NUM])
{
	TEE_Result ret;

	/*
	 * ro data
	 * [se_hooks_num + 5(6)] is offset of start(end) rodata's
	 * physical address in buffer.
	 */
	g_ro_data_start =
		((paddr_t *)params[0].memref.buffer)[OFFSET_RODATA_ADDR_START];
	g_ro_data_end =
		((paddr_t *)params[0].memref.buffer)[OFFSET_RODATA_ADDR_END];
	ret = sha256_address_range(g_ro_data_start, g_ro_data_end,
				&g_whitelist.ro_data_hash);
	if (ret != TEE_SUCCESS) {
		tloge("antiroot: CMD_GET_REE_KERNEL_PHYSICAL_ADDR (ro_data) fail, line = %d, ret = %x\n", __LINE__, ret);
		ret = AR_ERR_SYS_ERROR;
		return ret;
	}
	dump_hash(&g_whitelist.ro_data_hash, "g_whitelist.ro_data_hash");
	return TEE_SUCCESS;
}
#endif

static TEE_Result copy_se_physical_address(TEE_Param params[TEE_MAX_PARAM_NUM])
{
	errno_t s_ret;

	g_se_hooks_num =
		((paddr_t *)params[0].memref.buffer)[OFFSET_SEHOOKS_NUM];
	if (g_se_hooks_num > MAX_SE_HOOKS) {
		tloge("antiroot: Failed: too many SE Linux hooks\n");
		return AR_ERR_SYS_ERROR;
	}
	s_ret = memcpy_s(g_se_hooks_phy, sizeof(g_se_hooks_phy),
			&((paddr_t *)params[0].memref.buffer)[OFFSET_SEHOOKS_ADDR_START],
			g_se_hooks_num * sizeof(paddr_t));
	if (s_ret != EOK) {
		tloge("antiroot: Failed to copy SE Linux hooks\n");
		return AR_ERR_SYS_ERROR;
	}
	return TEE_SUCCESS;
}

static TEE_Result cmd_resume_measure_handle(TEE_Param params[TEE_MAX_PARAM_NUM])
{
	TEE_Result ret;

	if (!g_get_kernel_address && !g_pause_measurement) {
		/* Linux kernel code section & capture ref values */
		ret = calculate_kernel_hash(params);
		if (ret != TEE_SUCCESS)
			return ret;

		/* SYSCALL Measurement & capture ref values */
		ret = calculate_sys_call_hash(params);
		if (ret != TEE_SUCCESS)
			return ret;

		/* Copy SE physical addresses from NwD to secure world */
		ret = copy_se_physical_address(params);
		if (ret != TEE_SUCCESS)
			return ret;

		/* SELINUX policy & capture ref values */
		ret = sha256_hooks(g_se_hooks_phy, g_se_hooks_num,
				&g_whitelist.se_hooks_hash);
		if (ret != TEE_SUCCESS) {
			tloge("antiroot: CMD_GET_REE_KERNEL_PHYSICAL_ADDR (se_hook) fail, line = %d, ret = %x\n",
				__LINE__, ret);
			ret = AR_ERR_SYS_ERROR;
			return ret;
		}
		dump_hash(&g_whitelist.se_hooks_hash,
			"g_whitelist.se_hooks_hash");
#ifdef TEE_RODATA_MEASUREMENT
		ret = calculate_readonly_data_hash(params);
		if (ret != TEE_SUCCESS)
			return ret;
#endif

		g_get_kernel_address = true;
		tlogi("antiroot: baseling line is ok\n");
		/* EIMA Policy & capture ref values */
	} else if (g_get_kernel_address && g_pause_measurement) {
		ret = sha256_address_range(g_kstart, g_kend,
					&g_whitelist.kernel_hash);
		if (ret != TEE_SUCCESS) {
			tloge("antiroot: CMD_RESUME_MEASURE (kcode)fail, line = %d, ret = %x\n", __LINE__, ret);
			ret = AR_ERR_SYS_ERROR;
			return ret;
		}
		g_pause_measurement = false;
		tlogi("antiroot: Measurement is resumed\n");
		dump_hash(&g_whitelist.kernel_hash, "g_whitelist.kernel_hash");
	} else {
		tloge("antiroot: CMD_GET_ADDR or CMD_RESUME_MEASURE state is wrong\n");
		ret = AR_ERR_INVOKE_ERROR;
	}

	return ret;
}
#endif

static TEE_Result check_antiroot_cmd_param(TEE_Param params[TEE_MAX_PARAM_NUM],
					uint32_t cmd_id)
{
	if ((params == NULL) || (params[0].memref.buffer == NULL)) {
		tloge("ERROR: bad params!\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].memref.size != SIZE_CMD_BUFF) {
		tloge("ERROR: command id: 0x%x, size: %u\n", cmd_id,
			params[0].memref.size);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	return TEE_SUCCESS;
}

TEE_Result antiroot_hand_cmd(TEE_Param params[TEE_MAX_PARAM_NUM],
			uint32_t cmd_id)
{
	TEE_Result ret = TEE_SUCCESS;
	tee_rm_command *arcmd = NULL;
	uint32_t root_status = 0;

#if defined(DEF_ENG) && defined(TEE_KERNEL_MEASUREMENT)
	int test_item;
#endif

	if (check_antiroot_cmd_param(params, cmd_id) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;
	arcmd = params[0].memref.buffer;

	switch (cmd_id) {
	case CMD_SET_WHITELIST:
		ret = cmd_set_whitelist_handle(arcmd);
		break;
	case CMD_SEND_CHALLENGE:
		ret = cmd_send_challenge_handle(arcmd);
		break;
	case CMD_GET_RESPONSE:
		ret = cmd_get_response_handle(params, arcmd);
		if (ret == TEE_ERROR_TIMER_CREATE_FAILED)
			return AR_ERR_SYS_ERROR;
		break;
#ifdef TEE_KERNEL_MEASUREMENT
	case CMD_GET_REE_KERNEL_PHYSICAL_ADDR:
	case CMD_RESUME_MEASURE:
		ret = cmd_resume_measure_handle(params);
		break;
	case CMD_PAUSE_MEASURE:
		g_pause_measurement = true;
		ret = TEE_SUCCESS;
		tlogi("antiroot: Measurement is paused\n");
		break;
#ifdef DEF_ENG
	case CMD_TEE_STATUS_TEST:
		test_item = ((int *)params[0].memref.buffer)[0];
		tlogd("antiroot: tee status test test_item = %d", test_item);
		cmd_tee_status_test(test_item);
		break;
#endif
#endif

	default:
		tloge("invalid cmd id\n");
		ret = AR_ERR_INVOKE_ERROR;
	}
	/*
	 *  add a counter.
	 *  to avoid malicous CA keep send wrong challenge
	 *  cmd to cause TA never write rootstatus.
	 */
	ret = check_error_count(ret, root_status, params);
	if (ret != TEE_SUCCESS)
		tloge("antiroot:check_error_count error!\n");

	return ret;
}

void antiroot_close_session(void)
{
	TEE_Result ret;
	uint32_t root_status;

	tlogi("---- atni root close session! -----\n");
	if (g_whitelist.root_procs != NULL) {
		TEE_Free(g_whitelist.root_procs);
		g_whitelist.root_procs = NULL;
	}

	/* if closesession after setWhiteList fail, don't set rootstatus. */
	if (g_invoke_cmd_state == STATE_INIT) {
		tloge("CloseSession on SetWhitelist fail\n");
	} else {
		/*
		 * in user(non-eng) version, CA will closesession
		 * when CA receiveerrors(one time AR_ERR_RSP_CHECK_FAIL,
		 * other error three times).
		 * if CA closesession when root is NOT detected, we can
		 * assum CA is compromised, set CHECKFAILBIT before
		 * DestoryTimer.
		 */
		root_status = __SRE_ReadRootStatus();
		if (root_status & (0x1 << ROOTSTATE_BIT)) {
			tlogd("antiroot: CloseSession, read status 0x%x\n",
				root_status);
		} else {
			root_status = 0x1 << CHECKFAILBIT;
			tloge("CloseSession rstatus is 0x%x\n", root_status);
			if (__SRE_WriteRootStatus(root_status)) {
				tloge("CloseSession write rstatus error!\n");
				return;
			}
		}
	}

	ret = TEE_ANTI_ROOT_DestoryTimer();
	if (ret != TEE_SUCCESS)
		tloge("CloseSession DestoryTimer fail, ret = %x\n", ret);
}

/*
 * root_status_bit is define the valid check bit in __SRE_ReadRootStatus
 * __SRE_ReadRootStatus value is defined root_status_bit in antiroot_task.h
 * The root_status_bit is a uint32 type.
 * The valid bit is
 *      FBLOCK_YELLOW_BIT,              // 2    on
 *      FBLOCK_RED_BIT,                 // 3    on
 *      FBLOCK_ORANGE_BIT,              // 4    on
 *      //dy scan result
 *      KERNELCODEBIT   = 6,            // 6    on
 *      SYSTEMCALLBIT,                  // 7    on
 *      ROOTPROCBIT,                    // 8    off
 *      SESTATUSBIT,                    // 9    on
 *      SEHOOKBIT       = 10,           // 10   off
 *      SETIDBIT,                       // 18   on
 *      ==> 100 0000 0010 1101 1100 ==> 0x402dc ==> ROOT_STATUS_BIT_INIT
 */
static void set_root_status_bit_mask(uint32_t *params_mask)
{
	*params_mask |= ((1U << FBLOCK_YELLOW_BIT) |
		(1U << FBLOCK_RED_BIT) |
		(1U << FBLOCK_ORANGE_BIT) |
		(1U << KERNELCODEBIT) |
		(1U << SYSTEMCALLBIT) |
		(1U << SESTATUSBIT) |
		(1U << SETIDBIT));
}

uint32_t antiroot_get_root_status(void)
{
	uint32_t root_status = __SRE_ReadRootStatus();
	uint32_t root_status_bit_mask = 0;

	/* add fastboot lock mask */
	set_root_status_bit_mask(&root_status_bit_mask);

	root_status = ((root_status) & (root_status_bit_mask)) != 0 ? 1 : 0;
	return root_status;
}

uint32_t antiroot_get_root_status_detail(void)
{
	uint32_t root_status = __SRE_ReadRootStatus();
	uint32_t root_status_bit_mask = 0;

	/* add fastboot lock mask */
	set_root_status_bit_mask(&root_status_bit_mask);

	root_status = ((root_status) & (root_status_bit_mask));
	return root_status;
}

uint32_t get_eng_status(void)
{
	return g_whitelist.d_status;
}
