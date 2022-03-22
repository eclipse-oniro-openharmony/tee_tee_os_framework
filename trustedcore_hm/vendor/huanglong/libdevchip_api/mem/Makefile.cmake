
if ("${CFG_HI_TEE_SMMU_SUPPORT}" STREQUAL "y")
list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/mem/hi_tee_mem.c
)
endif()
if ("${CFG_HI_TEE_SEC_MMZ_SUPPORT}" STREQUAL "y")
list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/mem/hi_tee_mmz.c
)
endif()
