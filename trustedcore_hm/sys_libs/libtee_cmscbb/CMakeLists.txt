include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/sys_libs/libtee_cmscbb/include
    ${PROJECT_SOURCE_DIR}/thirdparty/huawei/libcmscbb/cmscbb/include
    ${PREBUILD_DIR}/headers/openssl
)

if ("${CONFIG_CMS_CAHASH_AUTH}" STREQUAL "y")
    set(LIBTEE_CMSCBB_CDEFS
        ${LIBTEE_CMSCBB_CDEFS}
        SUPPORT_UPDATE_CRL
    )
endif()

tee_add_library(tee_cmscbb STATIC
    SOURCES
    src/cms_signature_verify.c
    src/tee_cmscbb.c

    COMPILE_TOOL
    clang

    COMPILER_FLAGS
    ${TEE_C_FLAGS}

    COMPILER_DEFINITIONS
    ${TEE_C_DEFINITIONS}

    PRIVATE_INCLUDES
    ${TEE_INCLUDE_PATH}

    COMPILER_DEFINITIONS
    ${LIBTEE_CMSCBB_CDEFS}

    NO_INSTALL
)
