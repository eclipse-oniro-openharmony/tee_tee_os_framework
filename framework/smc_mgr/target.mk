# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

ifneq ($(CONFIG_SMCMGR_EMBEDDED), y)
apps-$(CONFIG_TEE_SUPPORT) += teesmcmgr
endif

ifeq ($(CONFIG_ARCH_AARCH64),y)
teesmcmgr: common \
    libcrt0       \
    libdebug      \
    libsyscalls   \
    libhongmeng   \
    libmmgr       \
    libipc        \
    libc          \
    libhwsecurec  \
    libfileio     \
    libirqmgr     \
    libpathmgr    \
    libasan
else
teesmcmgr: common \
    libcrt0_a32       \
    libdebug_a32      \
    libsyscalls_a32   \
    libhongmeng_a32   \
    libmmgr_a32       \
    libipc_a32        \
    libc_a32          \
    libhwsecurec_a32  \
    libfileio_a32     \
    libirqmgr_a32     \
    libpathmgr_a32    \
    libasan_a32
endif
