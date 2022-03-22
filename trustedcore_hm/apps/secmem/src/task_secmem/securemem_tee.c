/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2018. All rights reserved.
 * Description: tee securemem test
 * Create: 2017
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"

/* ----------------------------------------------------------------------------
 * Includes
 * ----------------------------------------------------------------------------
 */
#include "securemem_tee.h"
#include "tee_internal_api.h"
#include "tee_log.h"
#include "libhwsecurec/securec.h"
#include "sre_syscalls_ext.h"
#include "dynion.h"
#include "vltmm_client_api.h"

int do_swi_call(unsigned int ion_ta_tag, void *mcl)
{
	return __sion_ioctl((int)ion_ta_tag, mcl);
}

/* ----------------------------------------------------------------------------
 *   Trusted Application Entry Points
 * ----------------------------------------------------------------------------
 */

/*
 * Function TA_CreateEntryPoint
 * Description:
 * The function TA_CreateEntryPoint is the Trusted Application's constructor,
 * which the Framework calls when it creates a new instance of the Trusted
 * Application.
 */
__attribute__((visibility ("default"))) TEE_Result TA_CreateEntryPoint(void)
{
	tlogd("----- %s -----\n", __func__);
	TEE_Result ret;

#ifdef SECMEM_UT
	ret = (TEE_Result)AddCaller_CA_exec("sec_mem", SECMEM_TEST_UID);
	if (ret != TEE_SUCCESS) {
		tloge("----- %s failed = 0x%lx-----\n", __func__, ret);
		return ret;
	}
#endif

	ret = (TEE_Result)AddCaller_CA_exec("sec_mem", 0);
	if (ret != TEE_SUCCESS) {
		tloge("----- %s failed = 0x%lx-----\n", __func__, ret);
		return ret;
	}

	ret = (TEE_Result)AddCaller_CA_exec("vltmm", 0);
	if (ret != TEE_SUCCESS) {
		tloge("----- %s failed = 0x%lx-----\n", __func__, ret);
		return ret;
	}

	ret = (TEE_Result)AddCaller_CA_exec("/vendor/bin/hiepsca", 0);
	if (ret != TEE_SUCCESS) {
		tloge("----- %s failed = 0x%lx-----\n", __func__, ret);
		return ret;
	}

	ret = (TEE_Result)AddCaller_CA_exec("sec_mem", MEDIA_UID);
	if (ret != TEE_SUCCESS) {
		tloge("----- %s failed = 0x%lx-----\n", __func__, ret);
		return ret;
	}

	ret = (TEE_Result)AddCaller_CA_exec("sec_mem", MEDIA_CODEC_UID);
	if (ret != TEE_SUCCESS) {
		tloge("----- %s failed = 0x%lx-----\n", __func__, ret);
		return ret;
	}

	ret = (TEE_Result)AddCaller_CA_exec("sec_mem", SYSTEM_SERVER_UID);
	if (ret != TEE_SUCCESS) {
		tloge("----- %s failed = 0x%lx-----\n", __func__, ret);
		return ret;
	}

	ret = (TEE_Result)AddCaller_CA_exec("/vendor/bin/hiaiserver",
					    SYSTEM_SERVER_UID);
	if (ret != TEE_SUCCESS) {
		tloge("----- %s failed = 0x%lx-----\n", __func__, ret);
		return ret;
	}

	ret = (TEE_Result)AddCaller_CA_exec(MEDIADRMSERVER_NAME, MEDIA_UID);
	if (ret != TEE_SUCCESS) {
		tloge("-----[%d] failed = 0x%lx-----\n", __LINE__, ret);
		return ret;
	}

	ret = (TEE_Result)AddCaller_CA_exec(MEDIASERVER_NAME, MEDIA_UID);
	if (ret != TEE_SUCCESS) {
		tloge("-----[%d] failed = 0x%lx-----\n", __LINE__, ret);
		return ret;
	}

#ifdef VCODEC_ENG_VERSION
	ret = (TEE_Result)AddCaller_CA_exec(SAMPLE_OMXVDEC_NAME, ROOT_UID);
	if (ret != TEE_SUCCESS) {
		tloge("-----[%d] failed = 0x%lx-----\n", __LINE__, ret);
		return ret;
	}
#endif

#ifdef SECIVP_LLT
	ret = (TEE_Result)AddCaller_CA_exec("/vendor/bin/ivp_algo_test", 0);
	if (ret != TEE_SUCCESS) {
		tloge("----- ivp_algo_test %s failed = 0x%lx-----\n", __func__, ret);
		return ret;
	}
#endif
	return ret;
}

/*
 *  Function TA_OpenSessionEntryPoint
 *  Description:
 *    The Framework calls the function TA_OpenSessionEntryPoint
 *    when a client requests to open a session with the Trusted Application.
 *    The open session request may result in a new Trusted Application instance
 *    being created.
 */
/*lint -save -e715*/
__attribute__((visibility ("default"))) TEE_Result TA_OpenSessionEntryPoint(
	uint32_t paramTypes, TEE_Param params[4], void **sessionContext)
{
	TEE_Result ret = TEE_SUCCESS;

	tlogd("---- %s --------\n", __func__);

	return ret;
}
/*lint -restore*/

static int check_params_type(uint32_t paramTypes, uint32_t valid0,
	uint32_t valid1, uint32_t valid2, uint32_t valid3)
{
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != valid0 ||
		(TEE_PARAM_TYPE_GET(paramTypes, 1) != valid1) ||
		(TEE_PARAM_TYPE_GET(paramTypes, 2) != valid2) ||
		(TEE_PARAM_TYPE_GET(paramTypes, 3) != valid3)) {
		tloge("START_ENROLLMENT: Bad expected parameter types\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return 0;
}

static int secmem_input_check(TEE_Param params[], uint32_t paramtypes)
{
	int ret = 0;
	unsigned int ion_ta_tag;

	if (TEE_PARAM_TYPE_GET(paramtypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT)
		return TEE_ERROR_BAD_PARAMETERS;

	ion_ta_tag = params[0].value.a;

	switch (ion_ta_tag) {
	case ION_SEC_CMD_ALLOC:
		ret = check_params_type(paramtypes, TEE_PARAM_TYPE_VALUE_INPUT,
			TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_NONE);
		break;
	case ION_SEC_CMD_MAP_IOMMU:
		ret = check_params_type(paramtypes, TEE_PARAM_TYPE_VALUE_INPUT,
			TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);
		break;
	case ION_SEC_CMD_FREE:
	case ION_SEC_CMD_UNMAP_IOMMU:
		ret = check_params_type(paramtypes, TEE_PARAM_TYPE_VALUE_INPUT,
			TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);
		break;
	case ION_SEC_CMD_TABLE_SET:
	case ION_SEC_CMD_TABLE_CLEAN:
		ret = check_params_type(paramtypes, TEE_PARAM_TYPE_VALUE_INPUT,
			TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_NONE);
		break;
	case ION_SEC_CMD_VLTMM:
		ret = check_params_type(paramtypes, TEE_PARAM_TYPE_VALUE_INPUT,
			TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_MEMREF_INOUT,
			TEE_PARAM_TYPE_NONE);
		break;
#ifdef SECMEM_UT
	case ION_SEC_CMD_TEST:
		ret = check_params_type(paramtypes, TEE_PARAM_TYPE_VALUE_INPUT,
			TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_NONE);
		break;
	case ION_SEC_CMD_TEST_RECY:
		ret = check_params_type(paramtypes, TEE_PARAM_TYPE_VALUE_INPUT,
			TEE_PARAM_TYPE_ION_SGLIST_INPUT, TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);
		break;
#endif
	default:
		tloge("Invalid ION CMD ID: %d\n", ion_ta_tag);
		return TEE_ERROR_INVALID_CMD;
	}

	if (ret)
		tloge("Bad expected parameter types, cmd %d\n", ion_ta_tag);

	return ret;
}

#ifdef SECMEM_UT
void release_sec_cfg_test(struct sglist *sglist)
{
	int ret;

	ret = ddr_sec_cfg(sglist, DDR_SEC_SION, DDR_SET_SEC);
	if (ret) {
		tloge("***TA sec config test failed***");
		return;
	}

	ret = ddr_sec_cfg(sglist, DDR_SEC_SION, DDR_UNSET_SEC);
	if (ret) {
		tloge("unconfig sec_region fail\n");
		return;
	}
	tloge("***Now TA release secure config test succeed!!!***");
}
void ta_crash_test(struct sglist *sglist)
{
	int ret;

	ret = ddr_sec_cfg(sglist, DDR_SEC_SION, DDR_SET_SEC);
	if (ret) {
		tloge("***TA sec config test failed***");
		return;
	}
	/* make TA to crash */
	(void)memset_s((void *)1, sglist->ion_size, 0, sglist->ion_size);
}

static struct sglist *create_sglist(TEE_PAGEINFO *array, u32 nents)
{
	struct sglist *sglist = NULL;
	u64 sglistSize;
	u32 i;

	sglistSize = sizeof(TEE_PAGEINFO) * nents + sizeof(struct sglist);
	sglist = (struct sglist *)TEE_Malloc(sglistSize, 0);
	if (!sglist) {
		tloge("%s: alloc sglist fail!\n", __func__);
		return NULL;
	}

	for (i = 0; i < nents; i++)
		sglist->info[i] = array[i];

	sglist->infoLength = nents;
	sglist->sglistSize = sglistSize;
	tloge("%s:sglist infoLength(0x%x) sglistSize(0x%llx)!\n", __func__,
		nents, sglistSize);

	return sglist;
}

static void test_sion_recycle(struct mem_chunk_list *mcl)
{
	struct sglist *sglist = NULL;
	TEE_PAGEINFO *array = NULL;
	u32 array_size = mcl->size;
	int ret;

	array = (TEE_PAGEINFO *)TEE_Malloc(array_size, 0);
	if (!array) {
		tloge("array SRE_MemAlloc alloc fail, size 0x%x\n", array_size);
		return;
	}

	tloge("%s: mcl->buffer_addr 0x%x!\n", __func__, mcl->buffer_addr);
	ret = memcpy_s((void *)array, array_size, mcl->buffer_addr, array_size);
	if (ret) {
		tloge("memcpy array fail\n");
		return;
	}
	sglist = create_sglist(array, mcl->nents);
	if (!sglist) {
		tloge("%s: create sglist fail!\n", __func__);
		return;
	}
	/* in test, we use va to record ion_buffer size */
	sglist->ion_size = mcl->va;

	release_sec_cfg_test(sglist);
	ta_crash_test(sglist);
}

#ifdef TEE_SUPPORT_VLTMM_SRV
static uint64_t get_time()
{
	TEE_Time t = {0};
	TEE_GetSystemTime(&t);
	return (t.seconds * 1000ull) + t.millis;
}

static void __smem_test_sharemem(TEE_Param params[])
{
	u32 size = params[1].value.b;
	void *ptr = NULL;
	void *ptr1 = NULL;
	u32 fd;
	int ret;

	fd = vlt_open(size);
	if (!fd) {
		tloge("vlt open failed\n");
		return;
	}
	ptr = vlt_map(fd, TRUE);
	if (!ptr) {
		tloge("vlt mmap failed\n");
		return;
	}

	ret = vlt_import_fd(fd);
	if (ret)
		tloge("import fd failed\n");

	ptr1 = vlt_map(fd, TRUE);
	if (!ptr1) {
		tloge("vlt mmap failed\n");
		return;
	}

	tloge("share memory test, fd: %d, ptr: %p, ptr1: %p\n", fd, ptr, ptr1);

	vlt_unmap(fd, ptr);
	vlt_unmap(fd, ptr1);
	vlt_close(fd);
	vlt_close(fd);
}

static void __smem_test_perf(TEE_Param params[])
{
	u32 count = params[1].value.a;
	u32 size = params[1].value.b;
	void **ptr_az = NULL;
	u64 start, end;
	u32 i;

	if (count == 0 || size == 0)
		return;
	if (count > VLTMM_TEST_MACCNT)
		count = VLTMM_TEST_MACCNT;
	if (count * size > VLTMM_TEST_256M) {
		tloge("test vltmm param error, count:%u size:%x\n", count, size);
		return;
	}
	ptr_az = TEE_Malloc(count * sizeof(void *), 0);
	if (!ptr_az)
		return;
	start = get_time();
	tloge("vlt malloc performance %u begin: %llu\n", count, start);
	for (i = 0; i < count; i++)
		ptr_az[i] = vlt_malloc(size);
	end = get_time();
	tloge("vlt malloc performance cnt: %u begin: %llu end: %llu  interval: %llu\n",
		count, start, end, end - start);
	for (i = 0; i < count; i++)
		vlt_free(ptr_az[i], size);

	TEE_Free(ptr_az);
}

static void __smem_test_perf_ext(TEE_Param params[])
{
	u32 count = params[1].value.a;
	u32 size = params[1].value.b;
	void *ptr = NULL;
	u64 start, end;
	u32 i;
	u32 fail_cnt = 0;
	u32 current_cnt = 0;

	if (count == 0 || size == 0)
		return;

	if (size > VLTMM_TEST_256M) {
		tloge("test vltmm param error, count:%x size:%x", count, size);
		return;
	}

	tloge("vlt malloc-free performance begin count: %u\n", count);
	for (i = 0; i < count; i++) {
		start = get_time();
		ptr = vlt_malloc(size);
		end = get_time();
		if ((current_cnt) % VLTMM_TEST_PRINTCNT == 0)
			tloge("vlt malloc-free performance current: %u begin: %llu end: %llu  interval: %llu\n",
				current_cnt, start, end, end - start);
		current_cnt++;
		if (!ptr) {
			fail_cnt++;
			tloge("vlt malloc failed, count: %u\n", fail_cnt);
		} else {
			vlt_free(ptr, size);
		}
	}
}

static void __smem_test_cmd_proc(struct mem_chunk_list *mcl, TEE_Param params[])
{
	u32 subcmd = mcl->protect_id;
	u32 addr = params[1].value.a;
	u32 size = params[1].value.b;
	void *ptr = NULL;

	vlt_create_zone(SEC_HIAI, VLTMM_TEST_256M, PAGE_SIZE);

	tloge("smem test cmd: %u addr: 0x%x size: 0x%x\n", subcmd, addr, size);
	tloge("smem get version: %d\n", secmem_get_version());
	switch (subcmd) {
	case SUB_CMD_UT_MALLOC:
		tloge("vlt malloc begin\n");
		ptr = vlt_malloc(size);
		if (!ptr) {
			tloge("vlt malloc failed\n");
			break;
		}
		tloge("vlt malloc succ, ptr: %p\n", ptr);
		(void)memset_s(ptr, size, 0, size);
		params[1].value.a = (u32)(uintptr_t)ptr;
		params[1].value.b = size;
		break;
	case SUB_CMD_UT_FREE:
		vlt_free((void *)(uintptr_t)addr, size);
		tloge("vlt free, addr: 0x%x\n", addr);
		break;
	case SUB_CMD_UT_SHAREMEM:
		__smem_test_sharemem(params);
		break;
	case SUB_CMD_UT_PERF:
		__smem_test_perf(params);
		break;
	case SUB_CMD_UT_PERF_EXT:
		__smem_test_perf_ext(params);
		break;
	default:
		tloge("no support sub command: %u\n", subcmd);
		break;
	}
}
#endif
#endif

#ifdef TEE_SUPPORT_VLTMM_SRV
static void __smem_sub_command_proc(struct mem_chunk_list *mcl, TEE_Param params[])
{
	u32 cmd = mcl->protect_id;
	u32 num;
	u64 addr[SHRINKER_MAX] = {0};
	int ret;

	if (cmd == SUB_CMD_FREE) {
		num = vlt_shrinker(addr, sizeof(addr));
		if (num) {
			if (num > SHRINKER_MAX)
				num = SHRINKER_MAX;
			ret = memcpy_s(params[2].memref.buffer, params[2].memref.size,
					addr, num * sizeof(u64));
			if (ret) {
				num = 0;
			}
			params[1].value.a = num;
		}
		return;
	}

	if (cmd == SUB_CMD_DUMP) {
		vlt_pool_dump();
		return;
	}
#ifdef SECMEM_UT
	__smem_test_cmd_proc(mcl, params);
	tloge("test cmd return: p1.a: %x p1.b: %x\n", params[1].value.a, params[1].value.b);
#endif
}
#endif

/*
 *  Function TA_InvokeCommandEntryPoint:
 *  Description:
 *    The Framework calls this function when the client invokes a command
 *    within the given session.
 */
/*lint -save -e715 -e835 -e845*/
__attribute__((visibility ("default"))) TEE_Result TA_InvokeCommandEntryPoint(void *session_context, uint32_t cmd_id,
	uint32_t paramTypes, TEE_Param params[4])
{
	int ret;
	unsigned int ion_ta_tag;
	struct mem_chunk_list mcl;

	tlogd("---- %s -----------\n", __func__);
	if (cmd_id != SECBOOT_CMD_ID_MEM_ALLOCATE) {
		tloge("invalid command ID: %d", cmd_id);
		return TEE_FAIL;
	}

	ret = secmem_input_check(params, paramTypes);
	if (ret)
		return TEE_ERROR_BAD_PARAMETERS;

	ion_ta_tag = params[0].value.a;
	mcl.protect_id = params[0].value.b;

	switch (ion_ta_tag) {
	case ION_SEC_CMD_ALLOC:
		mcl.nents = params[1].value.a;
		mcl.buffer_addr = params[2].memref.buffer;
		mcl.size = params[2].memref.size;
		if (mcl.size != mcl.nents * sizeof(TEE_PAGEINFO)) {
			tloge("invalid parameters of buffer size %x, %x\n",
				mcl.size, mcl.nents * sizeof(TEE_PAGEINFO));
			return TEE_ERROR_BAD_PARAMETERS;
		}
		break;
	case ION_SEC_CMD_FREE:
		mcl.buff_id = params[1].value.a;
		mcl.buffer_addr = NULL;
		mcl.size = 0;
		break;
	case ION_SEC_CMD_TABLE_SET:
	case ION_SEC_CMD_TABLE_CLEAN:
		mcl.nents = params[1].value.a;
		mcl.buffer_addr = params[2].memref.buffer;
		mcl.size = params[2].memref.size;
		if (mcl.size != mcl.nents * sizeof(TEE_PAGEINFO)) {
			tloge("invalid parameters of buffer size %x, %x\n",
				mcl.size, mcl.nents * sizeof(TEE_PAGEINFO));
			return TEE_ERROR_BAD_PARAMETERS;
		}
		break;
#ifdef TEE_SUPPORT_VLTMM_SRV
	case ION_SEC_CMD_VLTMM:
		__smem_sub_command_proc(&mcl, params);
		return 0;
#endif
#ifdef SECMEM_UT
	case ION_SEC_CMD_TEST:
		tloge("mcl.protect_id: %d\n", mcl.protect_id);
		mcl.buff_id = params[1].value.a;
		if (mcl.protect_id == 0) {
			mcl.buffer_addr = NULL;
			mcl.size = params[1].value.b;
		} else {
			mcl.va = params[1].value.b;
			mcl.buffer_addr = params[2].memref.buffer;
			mcl.size = params[2].memref.size;
			if (mcl.size != mcl.nents * sizeof(TEE_PAGEINFO)) {
				tloge("invalid params of buffer size %x, %x\n",
					mcl.size,
					mcl.nents * sizeof(TEE_PAGEINFO));
				return TEE_ERROR_BAD_PARAMETERS;
			}
		}
		tloge("buf_id/nents = 0x%x, cmd_id = %d.\n", mcl.buff_id,
			ion_ta_tag);

		test_sion_recycle(&mcl);
		break;
#endif
	default:
		tloge("Invalid ION CMD ID: %d\n", ion_ta_tag);
		return TEE_ERROR_INVALID_CMD;
	}

	ret = do_swi_call(ion_ta_tag, &mcl);

	/* return iova(in case iommu_map) or secbuf id(in case alloc) to CA */
	if (ion_ta_tag == ION_SEC_CMD_ALLOC) {
		tlogd("secbuf id = 0x%x, cmd_id = %d.\n", mcl.buff_id,
			ion_ta_tag);
		params[1].value.b = mcl.buff_id;
	}

	return (ret ? TEE_FAIL : TEE_SUCCESS);
}
/*lint -restore*/

/*
 *  Function TA_CloseSessionEntryPoint:
 *  Description:
 *    The Framework calls this function to close a client session.
 *    During the call to this function the implementation can use
 *    any session functions.
 */
/*lint -save -e715*/
__attribute__((visibility ("default"))) void TA_CloseSessionEntryPoint(void *session_context)
{
	tlogd("---- %s -----\n", __func__);
}
/*lint -restore*/

/*
 *  Function TA_DestroyEntryPoint
 *  Description:
 *    The function TA_DestroyEntryPoint is the Trusted Application's destructor,
 *    which the Framework calls when the instance is being destroyed.
 */
__attribute__((visibility ("default"))) void TA_DestroyEntryPoint(void)
{
	tlogd("---- %s ----\n", __func__);
}

#pragma GCC diagnostic pop
