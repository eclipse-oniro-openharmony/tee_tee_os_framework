include(apps_asan)

list(APPEND TEE_INCLUDE_PATH
    ${PREBUILD_DIR}/headers/
    ${PROJECT_SOURCE_DIR}/tools/
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/inse_crypto/
    ${PROJECT_SOURCE_DIR}/thirdparty/huawei/libhwsecurec/include/libhwsecurec/
    ${PROJECT_SOURCE_DIR}/thirdparty/huawei/libhwsecurec/include/
)

list(APPEND TEE_INC_FLAGS
    -I${PROJECT_SOURCE_DIR}/thirdparty/huawei/libhwsecurec/include/libhwsecurec
    -I${PROJECT_SOURCE_DIR}/thirdparty/huawei/libhwsecurec/include
)

list(APPEND TEE_C_FLAGS
    -Wall
    -Wextra
    -fno-omit-frame-pointer
    -fno-short-enums
    -DHAVE_AUTOCONF
    -DVFMW_EXTRA_TYPE_DEFINE
    -DENV_SOS_KERNEL
    -fno-builtin
    -fno-common
)

if ("${CONFIG_HW_SECUREC_MIN_MEM}" STREQUAL "y")
    list(APPEND TEE_C_FLAGS
        -DSECUREC_WARP_OUTPUT=1
        -DSECUREC_WITH_PERFORMANCE_ADDONS=0
    )
endif()

if ("${CONFIG_UBSAN}" STREQUAL "y")
    list(APPEND TEE_C_FLAGS
        -fsanitize=bounds-strict
        -fsanitize-address-use-after-scope
        -fsanitize-undefined-trap-on-error
    )
endif()

list(APPEND TEE_CXX_FLAGS
    -funwind-tables
    -fexceptions
    -std=gnu++11
    -frtti
    -fno-builtin
)
