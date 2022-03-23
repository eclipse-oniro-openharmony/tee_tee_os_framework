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

/* MDP/Display start frame */
/* MDP/Display frame done */
DECLARE_CMDQ_EVENT(CMDQ_EVENT_DISP_RDMA0_EOF,		28)

/* Mutex frame done */
DECLARE_CMDQ_EVENT(CMDQ_EVENT_MUTEX0_STREAM_EOF,	130)

/* Keep this at the end of HW events */
DECLARE_CMDQ_EVENT(CMDQ_MAX_HW_EVENT_COUNT, 512)

/* SW Sync Tokens (Pre-defined) */
/* Config thread notify trigger thread */
DECLARE_CMDQ_EVENT(CMDQ_SYNC_TOKEN_CONFIG_DIRTY, 640)
/* Trigger thread notify config thread */
DECLARE_CMDQ_EVENT(CMDQ_SYNC_TOKEN_STREAM_EOF, 641)
/* Notify normal CMDQ there are some secure task done */
DECLARE_CMDQ_EVENT(CMDQ_SYNC_SECURE_THR_EOF, 647)
/* SW Sync Tokens (User-defined) */
DECLARE_CMDQ_EVENT(CMDQ_SYNC_TOKEN_USER_0, 649)
/* GPR access tokens (for HW register backup) */
/* There are 15 32-bit GPR, 3 GPR form a set (64-bit for address, 32-bit for value) */
DECLARE_CMDQ_EVENT(CMDQ_SYNC_TOKEN_GPR_SET_4, 704)
/* event id is 9 bit */
DECLARE_CMDQ_EVENT(CMDQ_SYNC_TOKEN_MAX, (0x3FF))
DECLARE_CMDQ_EVENT(CMDQ_SYNC_TOKEN_INVALID, (-1))
