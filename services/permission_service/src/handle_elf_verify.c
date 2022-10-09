/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:c9SPtfxMWZMlOvcDia+6WHAr59HhILlflASQHv7o128+mg20phJTfOcfFn53MPjpO8GHRgax
tPhOXI1/WJ/LbjDIJ8+dAdseptkps6hvCJuKGe+mhDqxNCKx7bYzhqwCa9jqkJuZhopbxD/4
0/1+I7yaQL7ITawf6zZtPiDNYPc=#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/

/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: perm service do elf verify
 * Author: lipeng
 * Create: 2021-08-11
 */

#include "handle_elf_verify.h"
#include <securec.h>
#include <tee_log.h>
#include <msg_ops.h>
#include <ta_framework.h>
#include <target_type.h>
#include "tee_elf_verify.h"
#include "permission_service.h"
#include "handle_config.h"

TEE_Result perm_serv_elf_verify(const perm_srv_req_msg_t *msg, uint32_t sndr)
{
    elf_verify_req req;
    elf_verify_reply reply;

    if (msg == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (sndr != GLOBAL_HANDLE) {
        tloge("has no elf verify req permission\n");
        return TEE_ERROR_ACCESS_DENIED;
    }

    if (msg->header.send.msg_size != sizeof(elf_verify_req)) {
        tloge("elf verify req msg size %u invalid\n", msg->header.send.msg_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (memcpy_s(&req, sizeof(req), &(msg->req_msg.verify_req),
                 msg->header.send.msg_size) != EOK) {
        tloge("copy elf verify req failed\n");
        return TEE_ERROR_GENERIC;
    }

    (void)memset_s(&reply, sizeof(reply), 0, sizeof(reply));
    TEE_Result ret = secure_elf_verify(&req, &reply);
    if (ret != TEE_SUCCESS) {
        tloge("secure elf verify failed, ret=0x%x\n", ret);
    } else {
        if (reply.payload_hdr.ta_conf_size > 0)
            ret = ta_run_authorization_check(&(reply.srv_uuid),
                &(reply.ta_property), reply.mani_ext.target_version,
                reply.mani_ext.mem_page_align);
    }

    reply.verify_result = ret;

    uint32_t result = ipc_msg_snd(REGISTER_ELF_REQ, sndr, &reply, sizeof(reply));
    if (result != SRE_OK) {
        tloge("send reg elf req msg to failed, ret=0x%x\n", result);
        return TEE_ERROR_COMMUNICATION;
    }
    return TEE_SUCCESS;
}
