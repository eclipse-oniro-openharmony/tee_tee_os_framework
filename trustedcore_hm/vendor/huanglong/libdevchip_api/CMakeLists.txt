 add_custom_target(libdevchip_api_headers
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hi_tee_cert.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hi_tee_chip_task.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hi_tee_cipher.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hi_tee_demux.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hi_tee_errno.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hi_tee_descrambler.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hi_tee_hdmitx.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hi_tee_keyslot.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hi_tee_klad.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hi_tee_klad_irdeto.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hi_tee_klad_nagra.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hi_tee_log.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hi_tee_mem.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hi_tee_otp.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hi_tee_otp_nagra.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hi_tee_otp_verimatrix.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hi_tee_security.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hi_tee_ssm.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hi_tee_taload.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hi_tee_tsr2rcipher.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hi_tee_version.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/include/hi_type_dev.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/ta_al/itrustee/hi_tee_hal.h ${HDR_L_DIR}
VERBATIM)

include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

list(APPEND DEVCHIP_LIBS mem)
list(APPEND DEVCHIP_LIBS ta_al/itrustee)
include(${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/mem/Makefile.cmake)

if ("${CFG_HI_TEE_COMMON_SUPPORT}" STREQUAL "y")
    list(APPEND DEVCHIP_LIBS common)
    list(APPEND TEE_C_FLAGS -DSOS_VERSION=0x0 -DCFG_HI_TEE_COMMON_SUPPORT)
    include(${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/common/Makefile.cmake)
endif()

if ("${CFG_HI_TEE_DYNAMIC_TA_LOAD}" STREQUAL "y")
    list(APPEND DEVCHIP_LIBS taload)
    list(APPEND TEE_C_FLAGS -DCFG_HI_TEE_DYNAMIC_TA_LOAD)
    include(${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/taload/Makefile.cmake)
endif()

if ("${CFG_HI_TEE_DEMO_SUPPORT}" STREQUAL "y")
    list(APPEND DEVCHIP_LIBS demo)
    list(APPEND TEE_C_FLAGS -DCFG_HI_TEE_DEMO_SUPPORT)
    include(${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/demo/Makefile.cmake)
endif()

if ("${CFG_HI_TEE_SSM_SUPPORT}" STREQUAL "y")
    list(APPEND DEVCHIP_LIBS ssm)
    list(APPEND TEE_C_FLAGS -DCFG_HI_TEE_SSM_SUPPORT)
    include(${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/ssm/Makefile.cmake)
endif()

if ("${CFG_HI_TEE_LOG_SUPPORT}" STREQUAL "y")
    list(APPEND DEVCHIP_LIBS common/log)
    list(APPEND TEE_C_FLAGS -DCFG_HI_TEE_LOG_SUPPORT)
    include(${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/common/log/Makefile.cmake)
endif()

if ("${CFG_HI_TEE_DEMUX_SUPPORT}" STREQUAL "y")
    list(APPEND DEVCHIP_LIBS demux)
    list(APPEND TEE_C_FLAGS -DCFG_HI_TEE_DEMUX_SUPPORT)
    include(${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/demux/Makefile.cmake)
endif()

if ("${CFG_HI_TEE_OTP_SUPPORT}" STREQUAL "y")
    list(APPEND DEVCHIP_LIBS otp)
    list(APPEND TEE_C_FLAGS -DCFG_HI_TEE_OTP_SUPPORT)
    include(${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/otp/Makefile.cmake)
endif()

if ("${CFG_HI_TEE_KLAD_SUPPORT}" STREQUAL "y")
    list(APPEND DEVCHIP_LIBS klad)
    list(APPEND TEE_C_FLAGS -DCFG_HI_TEE_KLAD_SUPPORT)
    include(${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/klad/Makefile.cmake)
endif()

if ("${CFG_HI_TEE_HDMITX_SUPPORT}" STREQUAL "y")
    list(APPEND DEVCHIP_LIBS hdmitx)
    list(APPEND TEE_C_FLAGS -DCFG_HI_TEE_HDMITX_SUPPORT)
    include(${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/hdmitx/Makefile.cmake)
endif()

if ("${CFG_HI_TEE_KEYSLOT_SUPPORT}" STREQUAL "y")
    list(APPEND DEVCHIP_LIBS keyslot)
    list(APPEND TEE_C_FLAGS -DCFG_HI_TEE_KEYSLOT_SUPPORT)
    include(${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/keyslot/Makefile.cmake)
endif()

if ("${CFG_HI_TEE_CIPHER_SUPPORT}" STREQUAL "y")
    list(APPEND DEVCHIP_LIBS cipher)
    list(APPEND TEE_C_FLAGS -DCFG_HI_TEE_CIPHER_SUPPORT)
    include(${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/cipher/Makefile.cmake)
endif()

if ("${CFG_HI_TEE_TSR2RCIPHER_SUPPORT}" STREQUAL "y")
    list(APPEND DEVCHIP_LIBS tsr2rcipher)
    list(APPEND TEE_C_FLAGS -DCFG_HI_TEE_TSR2RCIPHER_SUPPORT)
    include(${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/tsr2rcipher/Makefile.cmake)
endif()

if ("${CFG_HI_TEE_PVR_SUPPORT}" STREQUAL "y")
    list(APPEND DEVCHIP_LIBS pvr)
    list(APPEND TEE_C_FLAGS -DCFG_HI_TEE_PVR_SUPPORT)
    include(${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/pvr/Makefile.cmake)
endif()

if ("${CFG_HI_TEE_HDMIRX_SUPPORT}" STREQUAL "y")
    list(APPEND DEVCHIP_LIBS hdmirx)
    list(APPEND TEE_C_FLAGS -DCFG_HI_TEE_HDMIRX_SUPPORT)
    include(${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/hdmirx/Makefile.cmake)
endif()

if ("${CFG_HI_TEE_NPU_SUPPORT}" STREQUAL "y")
    list(APPEND DEVCHIP_LIBS npu)
    list(APPEND TEE_C_FLAGS -DCFG_HI_TEE_NPU_SUPPORT)
    include(${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/npu/Makefile.cmake)
endif()

if ("${CFG_ADVCA_NAGRA}" STREQUAL "y")
#set CHINADRM_EXIST false for now
    set(CHINADRM_EXIST false)
    if ("${CHINADRM_EXIST}" STREQUAL "true")
        list(APPEND DEVCHIP_LIBS cdrm_hal)
        include(${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/cdrm_hal/Makefile.cmake)
    endif()
endif()

if ("${CFG_TEE_RPMB_SUPPORT}" STREQUAL "y")
    list(APPEND DEVCHIP_LIBS flash)
    list(APPEND TEE_C_FLAGS -DCFG_TEE_RPMB_SUPPORT)
    include(${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/flash/Makefile.cmake)
endif()

list(APPEND TEE_C_FLAGS
    ${TRUSTEDCORE_PLATFORM_FLAGS}
    -Wno-unused-parameter
    -fno-builtin
    -Wall -Wextra
)

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/include
    ${PROJECT_SOURCE_DIR}/platform/huanglong/ta_load
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/include
)

if ("${CFG_ADVCA_NAGRA}" STREQUAL "y")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/klad/nagra/
    )
endif()

list(FIND PRODUCT_APPS "devchip_api" index)

tee_add_library(devchip_api STATIC
    SOURCES
    ${TEE_C_SOURCES}

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
if ("${ARCH}" STREQUAL "arm")
    set_target_properties(devchip_api PROPERTIES OUTPUT_NAME "devchip_api_a32")
endif()
