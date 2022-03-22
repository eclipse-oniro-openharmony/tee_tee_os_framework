list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/sec/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/trng/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/sec_hal/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/hsm/scmi
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/sfc
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/hsm/hsm_update
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/efuse
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/hsm/hsm_pg_info
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/plat_cap
)

list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/sec/api/sec_api.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/sec/api/sec.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/trng/api/trng_api.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/trng/api/trng.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/sec_hal/src/sec_hal.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/hsm/scmi/scmi_api.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/hsm/scmi/scmi.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/sfc/sfc_api.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/sfc/sfc_driver.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/hsm/hsm_update/hsm_update_api.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/hsm/hsm_update/hsm_dev_id.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/hsm/hsm_update/hsm_secure_rw.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/efuse/efuse_api.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/efuse/efuse.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/hsm/hsm_pg_info/hsm_pg_info_api.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/plat_cap/plat_cap_hal.c
)

if ("${CONFIG_HSM}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS
        -DTEE_SUPPORT_HSM
    )
endif()

if ("${CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS
        -DCRYPTO_MGR_SERVER_ENABLE
    )
endif()
