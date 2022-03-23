/*
 * Copyright (C) 2015 MediaTek Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include "tui_m4u.h"
#include "m4u_reg.h"
#include "m4u_pgtable.h"
#include "dr_api/dr_api.h"
#include "log.h"
#include "tz_mem.h"
#include <tz_tags.h>
#include <tee_drStd.h>
#include "cache_flush.h"

#define LOG_TAG "TUI_M4U"
#define M4ULOGD(fmt, args...)	TUI_LOGW("["LOG_TAG"]"fmt, ##args)
#define M4ULOGE(fmt, args...)	TUI_LOGE("["LOG_TAG"]error:"fmt, ##args)
#define M4ULOGV(fmt, args...)   TUI_LOGW("["LOG_TAG"]"fmt, ##args)
/*depend on CMDQ api for config port*/
#define DISP_REG_MASK_EXT(handle, reg_va, reg_pa, val, mask) 	\
	do { \
	   if(handle==NULL) \
	   { \
			 M4U_REG_SET((unsigned int)(M4U_REG_GET(reg_va)&~(mask))|(val),(volatile void*)(reg_va) );\
	   } \
	   else \
	   { \
			 cmdqRecWrite(handle, reg_pa, val, mask); \
	   }  \
	} while (0)

struct m4u_pt_base {
	uint64_t pagetable_base_pa;
	uint64_t pagetable_base_va;
};

static unsigned int g_m4u_secure_status = 0;
#ifndef MTK_TUI_BYPASS_IOVA
static short mvaGraph[MVA_MAX_BLOCK_NR+1];
static unsigned char moduleGraph[MVA_MAX_BLOCK_NR+1];
static unsigned int g_m4u_reg_base_original_val = 0;
volatile unsigned long g_m4u_reg_base_va[1] = {0};
struct m4u_pt_base g_sec_pt_base;
static unsigned int sec_mem_shared_secmem = 0;
static unsigned int reserved_m4u_mem_start = 0;
static unsigned int reserved_m4u_mem_size = 0;
#define TUI_RESERVED_BUFFER_OFFSET (0x20000)

static int tui_m4u_get_reserved_memory(uint64_t *sec_mem_start, uint32_t *sec_mem_size)
{
	uint32_t ret;
	uint8_t *tee_parm_vaddr = 0;
	uint8_t sec_mem_tag_buf[TAG_STRUCT_MAX_SIZE];
	uint8_t *sec_mem_tag_ptr = sec_mem_tag_buf;

    ret = dr_api_map_physical_buffer((uint64_t)TEE_PARAMETER_BASE, 0x1000, MAP_READABLE, (void **) &tee_parm_vaddr);
	if (ret != 0) {
		M4ULOGV("MAP SRAM to virtual address fail! ERROR: %d\n", ret);
		*sec_mem_start = 0;
		*sec_mem_size = 0;
		return -1;
	}
	M4ULOGV("m4u_get_reserved_memory info, secmem_vaddr=0x%x, tee_addr=0x%x, tee_base=0x%x\n",tee_parm_vaddr, TEE_PARAMETER_ADDR, TEE_PARAMETER_BASE);

	// copy memory pool information to sec_mem_arg
	if (memcpy_s((void *)sec_mem_tag_buf, TAG_STRUCT_MAX_SIZE,
				(uint8_t *) (tee_parm_vaddr + (TEE_PARAMETER_ADDR - TEE_PARAMETER_BASE)), TAG_STRUCT_MAX_SIZE) != EOK)
		return -1;
	// unmap tee_parm_vaddr since it's useless
    dr_api_unmap_buffer(tee_parm_vaddr, 0x1000);

	if (IS_TAG_FMT((struct tz_tag*)(sec_mem_tag_ptr))) {
		struct tz_tag* sec_mem_tag = find_tag((unsigned long)sec_mem_tag_ptr, TZ_TAG_SEC_MEM_CFG);
		struct tz_tag* res_m4u_tag = find_tag((unsigned long)sec_mem_tag_ptr, TZ_TAG_RESERVED_MEM_M4U_BUF);
		if (!IS_NULL_TAG(sec_mem_tag))
			sec_mem_shared_secmem = sec_mem_tag->u.sec_mem_cfg.shared_secmem;
		if (!IS_NULL_TAG(res_m4u_tag)) {
			reserved_m4u_mem_start = res_m4u_tag->u.res_mem_cfg.start;
			reserved_m4u_mem_size = res_m4u_tag->u.res_mem_cfg.size;
		}
		M4ULOGV("m4u tui reserved0, start:0x%08x%08x, size:0x%x\n", VALUE_64(reserved_m4u_mem_start), reserved_m4u_mem_size);
	} else {
		sec_mem_arg_t *sec_mem_arg = (sec_mem_arg_t *)sec_mem_tag_ptr;
        sec_mem_arg->m4u_mem_start = 0x73f00000; /* m4u user teeos mem*/
        sec_mem_arg->m4u_mem_size = TUI_RESERVED_BUFFER_OFFSET + 0x4000;
        sec_mem_arg->shared_secmem = 1;
		sec_mem_shared_secmem = sec_mem_arg->shared_secmem;
		reserved_m4u_mem_start = sec_mem_arg->m4u_mem_start;
		reserved_m4u_mem_size = sec_mem_arg->m4u_mem_size;
		M4ULOGV("m4u tui reserved1, start:0x%08x%08x, size:0x%x\n", VALUE_64(reserved_m4u_mem_start), reserved_m4u_mem_size);
	}

	if (sec_mem_shared_secmem == 1) {
		*sec_mem_start = reserved_m4u_mem_start;
		*sec_mem_size = reserved_m4u_mem_size;
		M4ULOGV("m4u tui reserved2, start=0x(%08x%08x), size=0x%x, return:0x%08x%08x+0x%x\n",
				VALUE_64(reserved_m4u_mem_start), reserved_m4u_mem_size, VALUE_64(*sec_mem_start), *sec_mem_size);
	} else {
		*sec_mem_start = 0;
		*sec_mem_size = 0;
		M4ULOGV("m4utl_init failed without reserved memory\n");
	}

	return 0;
}
#endif

static int tui_m4u_pagetable_init(void)
{
#ifndef MTK_TUI_BYPASS_IOVA
	uint64_t local_sec_pt_pa = 0;
	uint32_t local_sec_pt_size = 0;
	uint32_t ret;

	ret = tui_m4u_get_reserved_memory(&local_sec_pt_pa, &local_sec_pt_size);
	if(ret || !local_sec_pt_pa || local_sec_pt_size < TUI_RESERVED_BUFFER_OFFSET + IMU_PGD_SIZE) {
		M4ULOGV("error to get pagetable reserved memory: ret=0x%x, pa=0x%llx, size:0x%x\n",
			(unsigned int)ret, VALUE_64(local_sec_pt_pa), local_sec_pt_size);
		return -1;
	}

	// tui pgtable is the last 64KB of reserved secure buffer
	g_sec_pt_base.pagetable_base_pa =
		((local_sec_pt_pa + TUI_RESERVED_BUFFER_OFFSET + IMU_PGD_ALIGN) & (~IMU_PGD_ALIGN));

    ret = dr_api_map_physical_buffer(g_sec_pt_base.pagetable_base_pa, IMU_PGD_SIZE, MAP_READABLE | MAP_WRITABLE,
                                     (void **)&g_sec_pt_base.pagetable_base_va);
	if (ret != 0) {
		M4ULOGV("MAP pagetable base va fail! ERROR: %d, pa:0x%08x%08x\n", ret, VALUE_64(g_sec_pt_base.pagetable_base_pa));
		return -1;
	} else {
		M4ULOGV("MAP pagetable base addr: pa:0x%08x%08x, va:0x%08x%08x, offset:0x%x\n",
			VALUE_64(g_sec_pt_base.pagetable_base_pa), VALUE_64(g_sec_pt_base.pagetable_base_va), TUI_RESERVED_BUFFER_OFFSET);
	}

	if (memset_s((void *)g_sec_pt_base.pagetable_base_va, IMU_PGD_SIZE, 0, IMU_PGD_SIZE) != EOK)
		return -1;
#endif

	return 0;
}

static void tui_m4u_mvaGraph_init(void)
{
#ifndef MTK_TUI_BYPASS_IOVA
	if (memset_s(mvaGraph, sizeof(short) * (MVA_MAX_BLOCK_NR + 1), 0,
				 sizeof(short) * (MVA_MAX_BLOCK_NR + 1)) != EOK)
		return;
	if (memset_s(moduleGraph, sizeof(unsigned char) * (MVA_MAX_BLOCK_NR + 1), 0,
				 sizeof(unsigned char) * (MVA_MAX_BLOCK_NR + 1)) != EOK)
		return;
	mvaGraph[0] = 1|MVA_BUSY_MASK;
	moduleGraph[0] = M4U_PORT_UNKNOWN;
	mvaGraph[1] = MVA_MAX_BLOCK_NR;
	moduleGraph[1] = M4U_PORT_UNKNOWN;
	mvaGraph[MVA_MAX_BLOCK_NR] = MVA_MAX_BLOCK_NR;
	moduleGraph[MVA_MAX_BLOCK_NR] = M4U_PORT_UNKNOWN;
#endif
}

static int tui_m4u_hw_init(void)
{
	unsigned int ret, i;

	if(g_m4u_secure_status)
		return 0;

#ifndef MTK_TUI_BYPASS_IOVA
    ret = dr_api_map_io(M4U_BASE0_SEC_PA, 0x1000, MAP_HARDWARE,
                        (void **)&g_m4u_reg_base_va[0]);
	if (ret) {
		M4ULOGE("map reg addr to virtual addr failed.\n");
		return -1;
	}

#if 0 //debug of the m4u translation fualt at normal MVA, switch to sec mapping table ,after display frame done.
	tui_m4u_switch_to_sec();
#endif
#endif

	/*map larb 1 base address*/
	//map LARB registers

	for (i = 0; i < SMI_LARB_NR; i ++) {
        ret = dr_api_map_io(smiLarbBasePA[i], SMI_LARB_SZ, MAP_HARDWARE, (void **)&smiLarbBaseAddr[i]);
		if(ret) {
			M4ULOGE("map larb %d register fail: pa=0x%x, size=0x%x, ret=%d\n", i,  smiLarbBasePA[i], SMI_LARB_SZ, ret);
			return -1;
		}
		M4ULOGV("smi larb %d map register: va=0x%x, pa=0x%x, size=0x%x\n", i, smiLarbBaseAddr[i], smiLarbBasePA[i], SMI_LARB_SZ);

	}

	return 0;
}

#ifndef MTK_TUI_BYPASS_IOVA
static unsigned int tui_m4u_do_alloc_mva(unsigned int port_id,
						const uint64_t buf_addr,
						const unsigned int buf_size)
{
	short s,end;
	short new_start, new_end;
	short required_block_cnt = 0;
	unsigned int mva_start;
	unsigned long start_required, end_required, size_required;
	unsigned int original_port_id;

	if (buf_size == 0)
		return 0;

	/*calculate mva block number*/
	start_required = buf_addr & (~M4U_VA_PAGE_MASK);
	end_required = (buf_addr + buf_size - 1)| M4U_VA_PAGE_MASK;
	size_required = end_required - start_required + 1;
	required_block_cnt = (size_required + MVA_BLOCK_ALIGN_MASK) >> MVA_BLOCK_SIZE_ORDER;

	/*find first match free region*/
	for(s = 1; (s < (MVA_MAX_BLOCK_NR + 1)) && (mvaGraph[s] < required_block_cnt);
	    s += (mvaGraph[s] & MVA_BLOCK_NR_MASK))
		;
	if (s > MVA_MAX_BLOCK_NR) {
		M4ULOGE("mva_alloc error: no available MVA region for %d blocks!\n",
		       required_block_cnt);
		return 0;
	}

	/*get a total mva region(from s to end) to insert our required mva region*/
	end = s + mvaGraph[s] - 1;

	if ((required_block_cnt == mvaGraph[s])) {
		MVA_SET_BUSY(s);
		MVA_SET_BUSY(end);
		moduleGraph[s] = port_id;
		moduleGraph[end] = port_id;
	} else {
		/*new_end is the end of our required mva region */
		new_end = s + required_block_cnt - 1;
		/*new_start is the start of remained mva region (total - required)*/
		new_start = new_end + 1;
		//note: new_start may equals to end
		/*update the remained region*/
		mvaGraph[new_start] = (mvaGraph[s] - required_block_cnt);
		mvaGraph[end] = mvaGraph[new_start];
		/*our required region is from s to new_end*/
		mvaGraph[s] = required_block_cnt | MVA_BUSY_MASK;
		mvaGraph[new_end] = mvaGraph[s];

		/*update module*/
		original_port_id = moduleGraph[s];
		moduleGraph[s] = port_id;
		moduleGraph[new_end] = port_id;
		moduleGraph[new_start] = original_port_id;
		moduleGraph[end] = original_port_id;
	}

	mva_start = (unsigned int)s;
	return (mva_start << MVA_BLOCK_SIZE_ORDER) + MVA_PAGE_OFFSET(buf_addr);
}

static int m4u_fill_section(unsigned int mva, uint64_t pa, unsigned int prot)
{
	unsigned int pgprot;
	unsigned int padscpt;
	imu_pgd_t *pgd;
	/*write section into page table buffer directly*/
	imu_pgd_t *g_pgd = (imu_pgd_t *)g_sec_pt_base.pagetable_base_va;

	if ((mva & (~F_PGD_PA_SECTION_MSK)) != ((unsigned int)pa & (~F_PGD_PA_SECTION_MSK))) {
		M4ULOGE("error to map section: mva=0x%lx, pa=0x%lx.\n", mva, pa);
		return -1;
	}

	mva &= F_PGD_PA_SECTION_MSK;
	/*set 32bit*/
	padscpt = (unsigned int)pa & F_PGD_PA_SECTION_MSK;
	if ((pa >> 32) & 0x01)
		padscpt |= F_PGD_BIT32_BIT;
	if ((pa >> 33) & 0x01)
		padscpt |= F_PGD_BIT33_BIT;
	if ((pa >> 34) & 0x01)
		padscpt |= F_PGD_BIT34_BIT;
	pgprot = __m4u_get_pgd_attr_1M(prot);
	/*compute offset from page table buffer base address*/
	pgd = imu_pgd_offset(g_pgd, mva);

	if ((imu_pgd_val(*pgd))) {
		M4ULOGE("%s: mva=0x%lx, pgd=0x%x\n", __func__, mva, imu_pgd_val(*pgd));
		return -1;
	}

	/*write section*/
	imu_pgd_val(*pgd) = pa | padscpt | pgprot;
#if 0
	M4ULOGV("imu_pgd = 0x%08x, pa=0x%08x%08x, mva= %x\n",
		imu_pgd_val(*pgd), VALUE_64(pa), mva);
#endif

	return 0;
}

static int tui_m4u_fill_pagetable(uint64_t phy_buf_addr,
				       unsigned int buf_size,
				       unsigned int mva_start,
				       unsigned int prot)
{
	int ret;
	unsigned int mva;
	unsigned int mva_end = mva_start + buf_size - 1;
	unsigned int required_desc_cnt = 0;
	uint64_t phy_buf_addr_orig = phy_buf_addr;

	required_desc_cnt = M4U_GET_PAGE_NUM(mva_start, buf_size);
	M4ULOGV("mva_start = 0x%x, mva_end = 0x%x, pa=0x%08x%08x, buf size = 0x%x, required_desc_cnt = %u\n",
		mva_start, mva_end, VALUE_64(phy_buf_addr), buf_size, required_desc_cnt);
	/*align to 1M*/
	mva_start &= F_PGD_PA_SECTION_MSK;
	phy_buf_addr &= F_PGD_PA_SECTION_MSK;
	for(mva=mva_start; required_desc_cnt != 0; required_desc_cnt--) {
		m4u_fill_section(mva, phy_buf_addr, prot);
		mva += MMU_SECTION_SIZE;
		phy_buf_addr+=MMU_SECTION_SIZE;
	}
	/*flush pt buffer in cpu cache to dram*/
	__dma_clean_range(phy_buf_addr_orig, phy_buf_addr_orig + required_desc_cnt * 4);
	if (0) {
		M4ULOGE("flush pt buffer in cpu cache to dram failed,\n");
		return -1;
	}
	return 0;
}

//bank4(sec m4u hw) don't support invalid all, range instead
static int tui_m4u_invalid_tlb(int m4u_id,
				   int L2_en,
				   int isInvAll,
				   unsigned int mva_start,
				   unsigned int mva_end)
{
    unsigned int reg = 0;
    unsigned long m4u_base = g_m4u_reg_base_va[0];

    if(L2_en)
        reg = F_MMU_INV_EN_L2;

    reg |= F_MMU_INV_EN_L1;

    /*invalid high 4G tlb*/
    //reg |= F_MMU_INV_VA_32;

    M4U_WriteReg32(m4u_base, REG_INVLID_SEL, reg);

    if(isInvAll)
    {
        M4U_WriteReg32(m4u_base, REG_MMU_INVLDT, F_MMU_INVLDT_ALL);
    }
    else
    {
        M4U_WriteReg32(m4u_base, REG_MMU_INVLD_START_A ,mva_start);
        M4U_WriteReg32(m4u_base, REG_MMU_INVLD_END_A, mva_end);
        M4U_WriteReg32(m4u_base, REG_MMU_INVLDT, F_MMU_INVLDT_RNG);
    }

    if(!isInvAll)
    {
        while(!M4U_ReadReg32(m4u_base, REG_MMU_CPE_DONE));
        M4U_WriteReg32(m4u_base, REG_MMU_CPE_DONE, 0);
    }


    return 0;

}

static void tui_m4u_invalid_tlb_all(int m4u_id, int L2_en)
{
    tui_m4u_invalid_tlb(m4u_id, L2_en, 1, 0, 0);
}

void dump_mva_graph()
{
	int index = 1, i;
	int count;
	unsigned int owner;
	char *status;

	M4ULOGV("***************dump mva graph****************\n");
	M4ULOGD("graph[%04s]%8s%8s%8s\n", "index", "count", "status", "owner");
	for (index = 1; index <= MVA_MAX_BLOCK_NR;) {
		if (MVA_IS_BUSY(index))
			status= "busy";
		else
			status= "free";
		owner = (unsigned int)moduleGraph[index];
		count = MVA_GET_NR(index);
		M4ULOGD("graph[%04u]%8u%8s%8u\n", index, count, status, owner);
		index += count;
	}

	M4ULOGV("*************dump mva graph done*************\n\n");
}
/*dump page table by mva status. only print one at busy status.*/
void dump_pagetable_in_use(void)
{
	/*our mva graph start with 1 not 0, so the index should start with 16th pgd.*/
	unsigned int pt_start_idx = 0x10, pt_offset = 0x10;
	unsigned int pt_jump_count = 0;
	unsigned int* p =
		(unsigned int*)g_sec_pt_base.pagetable_base_va + pt_start_idx;
	unsigned int* tmp_end;
	unsigned int block_count = 0;
	int graph_index;

    /* todo huawei */
	__dma_clean_range(g_sec_pt_base.pagetable_base_va, g_sec_pt_base.pagetable_base_va + IMU_PGD_SIZE);
	if (0) {
		M4ULOGE("flush pt buffer in cpu cache to dram failed,\n");
		return;
	}
	M4ULOGV("*************dump busy page table*************\n");
	M4ULOGV("%12s %20s %p\n","graph index", "descriptor", p);
	for (graph_index = 1; graph_index <= MVA_MAX_BLOCK_NR; graph_index++) {
		/*get block count at current graph index*/
		block_count = MVA_GET_NR(graph_index);
		/*get pt pointer next start address*/
		pt_jump_count = block_count * pt_offset;
		tmp_end = p + pt_jump_count;

		/*ignore free blocks*/
		if (!MVA_IS_BUSY(graph_index)) {
			p = tmp_end;
			//M4ULOGD("ignore mva graph %u\n", graph_index);
			continue;
		}
		for (; p < tmp_end; p++) {
			M4ULOGE("%12u 0x%20x\n", graph_index, *p);
		}
		p = tmp_end;
	}
	M4ULOGV("***********dump busy page table done***********\n\n");

}
static int tui_m4u_dealloc_mva(unsigned int mva, unsigned int size)
{
	unsigned int startRequire, endRequire, sizeRequire;
	short nrRequire;
	unsigned long irq_flags;
	/*compute mva graph start/end index and the block count needed to dealloc*/
	short startIdx = mva >> MVA_BLOCK_SIZE_ORDER;
	short dealloc_block_cnt = mvaGraph[startIdx] & MVA_BLOCK_NR_MASK;
	short endIdx = startIdx + dealloc_block_cnt - 1;

	/* -------------------------------- */
	/* check the input arguments */
	/* right condition: startIdx is not NULL && region is busy && right module && right size */
	startRequire = mva & (unsigned int)(~M4U_VA_PAGE_MASK);
	endRequire = (mva + size - 1) | (unsigned int)M4U_VA_PAGE_MASK;
	sizeRequire = endRequire - startRequire + 1;
	nrRequire = (sizeRequire + MVA_BLOCK_ALIGN_MASK) >> MVA_BLOCK_SIZE_ORDER;
	/* (sizeRequire>>MVA_BLOCK_SIZE_ORDER) + ((sizeRequire&MVA_BLOCK_ALIGN_MASK)!=0); */
	if (!(startIdx != 0	/* startIdx is not NULL */
		&& MVA_IS_BUSY(startIdx)
		&& (dealloc_block_cnt == nrRequire))) {
		M4ULOGE("error to free mva========================>\n");
		M4ULOGE("BufSize=%d(unit:0x%xBytes) (expect %d)\n",
		       nrRequire, MVA_BLOCK_SIZE, dealloc_block_cnt);
		M4ULOGE("mva=0x%x, (IsBusy?)=%d (expect %d)\n",
		       mva, MVA_IS_BUSY(startIdx), 1);
		return -1;
	}

	/*revert to defualt value*/
	moduleGraph[startIdx] = M4U_PORT_UNKNOWN;
	moduleGraph[endIdx] = M4U_PORT_UNKNOWN;

	/* -------------------------------- */
	/* merge with followed region */
	if ((endIdx + 1 <= MVA_MAX_BLOCK_NR) && (!MVA_IS_BUSY(endIdx + 1))) {
		dealloc_block_cnt += mvaGraph[endIdx + 1];
		mvaGraph[endIdx] = 0;
		mvaGraph[endIdx + 1] = 0;
	}
	/* -------------------------------- */
	/* merge with previous region */
	if ((startIdx - 1 > 0) && (!MVA_IS_BUSY(startIdx - 1))) {
		int pre_nr = mvaGraph[startIdx - 1];

		mvaGraph[startIdx] = 0;
		mvaGraph[startIdx - 1] = 0;
		startIdx -= pre_nr;
		dealloc_block_cnt += pre_nr;
	}
	/* -------------------------------- */
	/* set region flags */
	mvaGraph[startIdx] = dealloc_block_cnt;
	mvaGraph[startIdx + dealloc_block_cnt - 1] = dealloc_block_cnt;

	return 0;
}


static int tui_m4u_clean_section(unsigned int mva)
{
	imu_pgd_t *pgd;
	/*write section into page table buffer directly*/
	imu_pgd_t *g_pgd = (imu_pgd_t *)g_sec_pt_base.pagetable_base_va;
	/*compute offset from page table buffer base address*/
	pgd = imu_pgd_offset(g_pgd, mva);
	if (!imu_pgd_val(*pgd)) {
		M4ULOGE("the section need to clean is NULL\n");
		return -1;
	} else
		imu_pgd_val(*pgd) = 0;
	return 0;
}


static int tui_m4u_clean_pagetable(unsigned int mva_start,
					 unsigned int buf_size)
{
	unsigned int mva;
	unsigned int mva_end = mva_start + buf_size - 1;

	for(mva = mva_start; mva <= mva_end; mva += MMU_SECTION_SIZE) {
		if(tui_m4u_clean_section(mva))
			return -1;
	}
	return 0;
}
#endif

int tui_m4u_Init(void)
{
	int ret;

	ret = tui_m4u_pagetable_init();
	if (ret) {
		M4ULOGE("init page table failed.\n");
		return -1;
	}

	tui_m4u_mvaGraph_init();

	/*restore original secure page table address to avoid corruption after quite tui*/
	ret = tui_m4u_hw_init();
	if (ret) {
		M4ULOGE("init hw failed.\n");
		return -1;
	}
	return 0;
}

int tui_m4u_switch_to_sec(void)
{
#ifndef MTK_TUI_BYPASS_IOVA
	uint64_t pt_base_pa = g_sec_pt_base.pagetable_base_pa;
	int ret = 0;
#endif
	if(g_m4u_secure_status)
		return 0;

#ifndef MTK_TUI_BYPASS_IOVA
	g_m4u_reg_base_original_val = M4U_REG_GET(g_m4u_reg_base_va[0] + REG_MMU_PT_BASE_ADDR);

	M4ULOGV("%s, %d: remove the normal mva mapping table at: 0x%x\n", __func__, __LINE__, g_m4u_reg_base_original_val);

	/*check if pt buffer exists*/
	if (!g_sec_pt_base.pagetable_base_va) {
		M4ULOGE("page table buffer was not initailized.\n");
		return -1;
	}

	/*fill TUI secure page table address*/
	M4U_REG_SET(g_m4u_reg_base_va[0] + REG_MMU_PT_BASE_ADDR,
		    ((unsigned int)pt_base_pa & F_MMU_PT_BASE_ADDR_MSK) |
		    (((unsigned int)(pt_base_pa) >> 32) & F_MMU_PT_BASE_ADDR_BIT32));
	M4ULOGV("%s, %d: add the secure mva mapping table at: 0x%x\n", __func__, __LINE__, M4U_REG_GET(g_m4u_reg_base_va[0] + REG_MMU_PT_BASE_ADDR));
#endif
	g_m4u_secure_status = 1;

	return 0;

}
void tui_m4u_config_port_sec(cmdqRecHandle cmdq_handle, uint32_t port, int mmu_en, int sec)
{
	unsigned int larbid = m4u_port_2_larb_id(port);
	unsigned int larb_port = m4u_port_2_larb_port(port);
	if (larbid >= SMI_LARB_NR)
		return;
	unsigned long larb_base = smiLarbBaseAddr[larbid];

	(void)cmdq_handle;
#ifndef MTK_TUI_BYPASS_IOVA
	if (!mmu_en) {
		M4ULOGV("m4u_config_port_sec error, port=%d, cannot bypass iova\n", port);
		return;
	}
#else
	if (mmu_en) {
		M4ULOGV("m4u_config_port_sec error, port=%d, cannot use iova\n", port);
		return;
	}
#endif
	m4uHw_set_field_by_mask(larb_base, SMI_LARB_SEC_CONx(larb_port),\
				F_SMI_SEC_MMU_EN((uint32_t)1), F_SMI_SEC_MMU_EN((uint32_t)(!!(mmu_en))));

	m4uHw_set_field_by_mask(larb_base, SMI_LARB_SEC_CONx(larb_port),\
				F_SMI_SEC_EN((uint32_t)1), F_SMI_SEC_EN((uint32_t)(!!(sec))));

	//debug use
	mmu_en = m4uHw_get_field_by_mask(larb_base, SMI_LARB_SEC_CONx(larb_port), F_SMI_SEC_MMU_EN((uint32_t)1));
	if(!!(mmu_en) != mmu_en) {
		M4ULOGV("m4u_config_port_sec error, port=%d, Virtuality=%d, mmu_en=%x (%x, %x)\n",
			   port, mmu_en, larb_port, M4U_ReadReg32(larb_base, SMI_LARB_SEC_CONx(larb_port)), F_SMI_SEC_MMU_EN((uint32_t)1));
	}
	M4ULOGV("%s, port=%d, Virtuality=%d, sec=0x%x, mmu_en=%x reg0x%x, value(%x, %x)\n", __func__, port, larb_port, sec,
			mmu_en, (larb_base+SMI_LARB_SEC_CONx(larb_port)), M4U_ReadReg32(larb_base, SMI_LARB_SEC_CONx(larb_port)), F_SMI_SEC_MMU_EN((uint32_t)1));

}


unsigned int tui_m4u_alloc_mva(unsigned int port_id,
				const uint64_t phy_buf_addr,
				const unsigned int size)
{
	unsigned int mva_start;
#ifndef MTK_TUI_BYPASS_IOVA
	int ret;
	/*page attribute: uncacheable/secure/unshared*/
	unsigned int attribute = F_PGD_TYPE_SECTION | M4U_PROT_SEC;

	/* tui os is very sample
	 * m4u have only one user: display
	 */

	if (port_id < M4U_PORT_DISPLAY_MIN ||
	    port_id > M4U_PORT_DISPLAY_MAX) {
		M4ULOGE("%s: invalid port id[%d]\n", __func__, port_id);
		return 0;
	}
	/*use virtual start address to get mva*/
	mva_start = tui_m4u_do_alloc_mva(port_id, phy_buf_addr, size);

	if (!mva_start) {
		M4ULOGE("%s: m4u alloc mva failed\n", __func__);
		return 0;
	}

	/*use mva to fill section page table*/
	ret = tui_m4u_fill_pagetable(phy_buf_addr, size, mva_start, attribute);
	if (ret) {
		M4ULOGE("%s: m4u fill page table failed\n", __func__);
		return 0;
	}

	/*invalid high 4G tlb*/
	tui_m4u_invalid_tlb_all(0,1);
#else
	(void)size;
	unsigned int larbid = m4u_port_2_larb_id(port_id);
	unsigned int larb_port = m4u_port_2_larb_port(port_id);
	if (larbid >= SMI_LARB_NR)
		return 0;
	unsigned long larb_base = smiLarbBaseAddr[larbid];
	unsigned int regval = 0, old_reg = 0;
	unsigned int bit32 = phy_buf_addr >> 32;

	if (port_id < M4U_PORT_DISPLAY_MIN ||
	    port_id > M4U_PORT_DISPLAY_MAX) {
		M4ULOGE("%s: invalid port id[%d]\n", __func__, port_id);
		return 0;
	}
	mva_start = phy_buf_addr & 0xffffffff;
	if (!bit32)
		return mva_start;

	old_reg = M4U_ReadReg32(larb_base, SMI_LARB_NON_SEC_CONx(larb_port));
	regval = (old_reg & ~F_SMI_ADDR_BIT32) |
		(bit32 << 8) | (bit32 << 10) |
		(bit32 << 12) | (bit32 << 14);
	if (regval == old_reg)
		return mva_start;

	M4U_WriteReg32(larb_base, SMI_LARB_NON_SEC_CONx(larb_port), regval);
	M4ULOGV("%s, port=%d, pa=0x%x, mva=%x reg:x%x\n", __func__, port_id,
			phy_buf_addr, mva_start, M4U_ReadReg32(larb_base, SMI_LARB_NON_SEC_CONx(larb_port)));
#endif
	return mva_start;
}

int tui_m4u_free(unsigned int mva_start, unsigned int buf_size)
{
#ifndef MTK_TUI_BYPASS_IOVA
	int ret;

	M4ULOGV("dealloc mva start, at mva 0x%x, size=0x%x, ret=%d\n", mva_start, buf_size, ret);
	ret = tui_m4u_clean_pagetable(mva_start, buf_size);
	if (ret) {
		M4ULOGE("clean page table error at mva 0x%x\n", mva_start);
		return -1;
	}
	ret = tui_m4u_dealloc_mva(mva_start, buf_size);
	if (ret) {
		M4ULOGE("dealloc mva graph error at mva 0x%x\n", mva_start);
		dump_mva_graph();
		return -1;
	}

	M4ULOGV("dealloc mva done, at mva 0x%x, size=0x%x, ret=%d\n", mva_start, buf_size, ret);
#endif
	(void)mva_start;
	(void)buf_size;
	return 0;
}

void tui_m4u_deinit(void)
{
	int i =0;
	int ret = 0;

	g_m4u_secure_status = 0;
#ifndef MTK_TUI_BYPASS_IOVA
	/*restore secure pgd*/
	M4U_REG_SET(g_m4u_reg_base_va[0] + REG_MMU_PT_BASE_ADDR,
		    g_m4u_reg_base_original_val);
	M4ULOGV("%s, %d: restore the normal mva mapping table at: 0x%x\n", __func__, __LINE__, M4U_REG_GET(g_m4u_reg_base_va[0] + REG_MMU_PT_BASE_ADDR));
    /* unmap page table buffer */
    dr_api_unmap_buffer((void *)g_sec_pt_base.pagetable_base_va, IMU_PGD_SIZE);
    /* unmap register to virtual address */
    dr_api_unmap_io(M4U_BASE0_SEC_PA, (void *)(uintptr_t)g_m4u_reg_base_va[0]);
#endif
	for (i = 0; i < SMI_LARB_NR; i ++) {
        ret = dr_api_unmap_io(smiLarbBasePA[i], (void *)(uintptr_t)smiLarbBaseAddr[i]);
		if (ret)
			M4ULOGE("%s, %d, failed to unmap larb%d, base addr\n", __func__, __LINE__);
	}
	M4ULOGV("%s, %d\n", __func__, __LINE__);
}
