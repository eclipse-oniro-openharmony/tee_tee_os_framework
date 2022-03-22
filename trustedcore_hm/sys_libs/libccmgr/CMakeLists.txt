add_custom_target(libccmgr_headers
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/include ${HDR_L_DIR}
    VERBATIM)

include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_FLAGS
    -fno-builtin
)

if ("${MTK_CC_FEATURE}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS SUPPORT_M_CC)
endif()

if ("${CONFIG_CIPHER_ENABLE}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        DX_ENABLE=1
    )
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/host/src/cclib
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/ccdriver_lib/include
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api/cc7x_tee
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/proj/cc7x_tee/
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/host/src/cc7x_teelib
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/pal
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/cc_util
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/host/src/cclib
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/shared/include/pal
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/pal/include
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/shared/include/crys
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/shared/include/dx_util
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/host/include
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/shared/include
    )
endif()

list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
)
tee_add_library(ccmgr STATIC
    SOURCES
    src/ccmgr.c

    COMPILE_TOOL
    clang

    COMPILER_FLAGS
    ${TEE_C_FLAGS}

    COMPILER_DEFINITIONS
    ${TEE_C_DEFINITIONS}

    PRIVATE_INCLUDES
    ${TEE_INCLUDE_PATH}

    NO_INSTALL
)
