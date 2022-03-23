list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/taload/taload.c
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/taload/taload_verify.c
)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/include
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/mem/include
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/taload/common
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/taload
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/os_hal/itrustee
)
