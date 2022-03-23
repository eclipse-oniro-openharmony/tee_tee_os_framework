list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/npu/utilis/tee_npu_utils.c
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/npu/npu_test/tee_npu_test.c
)
list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/npu/include
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/npu/npu_test
)