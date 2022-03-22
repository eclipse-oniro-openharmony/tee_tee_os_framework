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

#ifndef __TUI_M4U_H__
#define __TUI_M4U_H__
#include "m4u_port.h"
#include "cmdq_sec_record.h"
#define MTK_TUI_BYPASS_IOVA
//------------------------------------------------------------------------------
/** init m4u must be called firstly.include init page table and mva graph. 
 *
 * @returns 0 in case of success
 * @returns -1 in case of error
 */
int tui_m4u_Init(void);


//------------------------------------------------------------------------------
/** switch m4u from normal world to secure world, after the normal frame done. 
 *
 * @returns 0 in case of success
 * @returns -1 in case of error
 */
int tui_m4u_switch_to_sec(void);


//------------------------------------------------------------------------------
/** cmdq call it after m4u inited. 
 *
 * @param cmdqRecHandle: [in] cmdqRecHandle
 * @param port: [in] port id.
 * @param mmu_en: [in] pass(1) or bypass(0) m4u.
 * @param sec: [in] security(1), non-security(0).
 */
void tui_m4u_config_port_sec(cmdqRecHandle cmdq_handle, uint32_t port, int mmu_en, int sec);

//------------------------------------------------------------------------------
/** translate 64bit physical buffer start address to 32bit modified virtual start address
 *   which is used for m4u. user can use mva to trigger mm engine to work instead.
 *
 * @param port_id: [in] which port use m4u.
 * @param phy_buf_addr: [in] 64bit physical buffer start address.
 * @param size: [in] buffer size.
 * @returns non-zero mva in case of success
 * @returns 0 in case of error.
 */
unsigned int tui_m4u_alloc_mva(unsigned int port_id,
				const uint64_t phy_buf_addr,
				const unsigned int size);

//------------------------------------------------------------------------------
/** When you don't use a mva region any more, you must recycle it. 
 * @param mva_start: [in] mva start address.
 * @param buf_size: [in] buffer size.
 * @returns 0 in case of success.
 * @returns -1 in case of error.
 */
int tui_m4u_free(unsigned int mva_start, unsigned int buf_size);

//------------------------------------------------------------------------------
/** must be called when quite TUI!!! Or, corruption will occur in secure mode.(ex: SVP)
 */
void tui_m4u_deinit(void);
#endif
