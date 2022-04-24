# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

#[[
add_custom_target(teesmcmgr_headers
                  COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/include ${HMSDKINCLUDE}
                  VERBATIM)
]]#

set(SUPPORTED_ARCHS
    aarch64
    arm
)

if ("${ARCH}" STREQUAL "arm")
    set(TARGET_IS_ARM32 y)
endif()

set(TEESMCMGR_INCLUDES
    ${TEESMCMGR_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/syslib/libmmgr/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/syslib/libpathmgr/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/teelib/libteeos/include/TEE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/teelib/libteeos/include/legacy
    ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/syslib/libhwi/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/syslib/libhmlog/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/syslib/libcrt0/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/syslib/libsyscalls/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if ("${CONFIG_ENABLE_XOM}" STREQUAL "y" AND "${ARCH}" STREQUAL "aarch64")
    set(TEESMCMGR_LDFLAGS
        ${TEESMCMGR_LDFLAGS}
        -Wl,-execute-only
    )
endif()

set(TEESMCMGR_LDFLAGS
    ${TEESMCMGR_LDFLAGS}
    -Wl,--entry=_hm_start
    -Wl,--undefined=_hm_start
    -Wl,-z,noexecstack
)

if ("${CONFIG_SSA_EMBEDDED}" STREQUAL "y")
       set(TEESMCMGR_CDEFS
        ${TEESMCMGR_CDEFS}
        SSA_EMBEDDED
    )
endif()

if (ARCH IN_LIST SUPPORTED_ARCHS)
tee_add_executable(teesmcmgr.elf
    SOURCES
    src/idle.c
    src/main.c
    src/utils.c
    src/teesmc.c

    COMPILE_TOOL
    clang

    PRIVATE_INCLUDES
    ${COMMON_INCLUDES}
    ${COMMON_NWEFLAG_INCLUDES}
    ${COMMON_FLAG_INCLUDES}
    ${BOOTSTRAP_INCLUDES}
    ${TEESMCMGR_INCLUDES}
    ${HMAPPSINCLUDE}
    ${COMMON_LIBC_INCLUDES}

    COMPILER_FLAGS
    -include${HMSDKINCLUDE}/autoconf.h
    ${COMMON_CFLAGS}
    ${COMMON_FLAG_CFLAGS}
    -fvisibility=hidden

    COMPILER_DEFINITIONS
    ${COMMON_DEFS}
    ${TEESMCMGR_CDEFS}

    LD_FLAGS
    ${COMMON_LDFLAGS}
    ${TEESMCMGR_LDFLAGS}

    LINKGROUP
    c
    hongmeng
    mmgr
    syscalls
    crt0
    pathmgr
    debug
    ipc
    hwsecurec
    irqmgr
    hmlog
    ${COMMON_LIBGCC_COMPS}

    INSTALL_DIR
    bin
)
endif()
