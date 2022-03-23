/*
* Copyright (C) Huawei Technologies Co., Ltd. 2012-2015. All rights reserved.
* foss@huawei.com
*
* If distributed as part of the Linux kernel, the following license terms
* apply:
*
* * This program is free software; you can redistribute it and/or modify
* * it under the terms of the GNU General Public License version 2 and
* * only version 2 as published by the Free Software Foundation.
* *
* * This program is distributed in the hope that it will be useful,
* * but WITHOUT ANY WARRANTY; without even the implied warranty of
* * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* * GNU General Public License for more details.
* *
* * You should have received a copy of the GNU General Public License
* * along with this program; if not, write to the Free Software
* * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA
*
* Otherwise, the following license terms apply:
*
* * Redistribution and use in source and binary forms, with or without
* * modification, are permitted provided that the following conditions
* * are met:
* * 1) Redistributions of source code must retain the above copyright
* *    notice, this list of conditions and the following disclaimer.
* * 2) Redistributions in binary form must reproduce the above copyright
* *    notice, this list of conditions and the following disclaimer in the
* *    documentation and/or other materials provided with the distribution.
* * 3) Neither the name of Huawei nor the names of its contributors may
* *    be used to endorse or promote products derived from this software
* *    without specific prior written permission.
*
* * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
*/
#include <bsp_modem_call.h>
#include <osl_balong.h>
#include <bsp_icc.h>
#include <drv_module.h>
#include <securec.h>
#include <crys_rnd.h>
#include "tee_log.h"

#define TRNG_SEED_LENGTH                     (96)

int trng_seed_get(unsigned char *buffer,unsigned int length)
{
    int ret = 0;

    if (buffer == NULL){
        tloge("buffer is NULL!!\n");
        return -1;
    }

    ret = CRYS_RND_GenerateVector(length, buffer);
    if (ret != 0) {
        tloge("CRYS_RND_GenerateVector fail, ret = %d.\n",ret);
        (void)memset_s(buffer, length, 0, length);
        return ret;
    }
    return 0;
}

int trng_seed_send(unsigned char* buf,unsigned int length)
{
    unsigned int send_length =0;

    u32 channel_id = (ICC_CHN_SEC_IFC << 16) | IFC_RECV_FUNC_TRNG_SEED_GET;
    send_length = bsp_icc_send(ICC_CPU_MODEM, channel_id, buf, length);
    if (send_length != length) {
        tloge("send len(%x) != expected len(%x).\n", send_length, length);
        return -1;
    }
    return 0;
}

int bsp_sec_call_trng_seed_request(unsigned int arg1 __attribute__((unused)), void *arg2 __attribute__((unused)), unsigned int arg3 __attribute__((unused)))
{
    int ret = 0;
    unsigned char trng_seed[TRNG_SEED_LENGTH] = {0};

    ret = trng_seed_get(&trng_seed[0], sizeof(trng_seed)/sizeof(unsigned char));
    if (ret != 0) {
        tloge("trng_seed_get error, ret = %d.", ret);
        goto error;
    }

    ret = trng_seed_send(&trng_seed[0], sizeof(trng_seed)/sizeof(unsigned char));
    if (ret != 0) {
        tloge("trng_seed_send error, ret = %d.", ret);
        goto error;
    }

error:
    (void)memset_s(&trng_seed[0], TRNG_SEED_LENGTH, 0, TRNG_SEED_LENGTH);
    return ret;
}

int trng_seed_init(void)
{
    int ret = 0;

    ret = bsp_modem_call_register(FUNC_TRNG_SEED_REQUEST, bsp_sec_call_trng_seed_request);
    if (ret != 0) {
        tloge("register modem call fail,ret = %d.", ret);
        return ret;
    }

    return 0;
}

DECLARE_TC_DRV(
	trng_seed_driver,
	0,
	0,
	0,
	TC_DRV_MODULE_INIT,
	trng_seed_init,
	NULL,
	NULL,
	NULL,
	NULL
);

