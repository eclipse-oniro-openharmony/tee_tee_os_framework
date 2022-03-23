if ("${CFG_HI_TEE_DDR_SIZE}" STREQUAL "")
# 0x22200000 --------------------- 290M ---------------------
#             4M  ATF + Parameter
# 0x22600000 --------------------- 294M
#             4M  SMMU Page Table
# 0x22A00000 --------------------- 298M
#             2M SMMU_MMZ
# 0x22C00000 --------------------- 300M
#             14M Secure MMZ
# 0x23A00000 --------------------- 314M        Total: 156M
#             48M Secure OS
# 0x26A00000 --------------------- 362M
#             15M VMCU
# 0x27900000 --------------------- 377M
#             25M ADSP
# 0x29200000 --------------------- 402M
#             40M VQ6
# 0x2BA00000 --------------------- 442M
#             (4M - 64k) SEC reserve
# 0x2BDf0000 ----------------------
#             64k Smmu garbage
# 0x2BE00000 --------------------- 446M ---------------------
#TRUSTEDCORE_PHY_TEXT_BASE := 0x23A08000
    list(APPEND TEE_C_FLAGS -DCFG_HI_TEE_DDR_SIZE_NA)
    set(TRUSTEDCORE_OS_MEM_SIZE 48)
endif()

if ("${CFG_HI_TEE_DDR_SIZE}" STREQUAL "2G")
    list(APPEND TEE_C_FLAGS -DCFG_HI_TEE_DDR_SIZE_2G)
    set(TRUSTEDCORE_PHY_TEXT_BASE 0x19808000)
endif()

if ("${CFG_HI_TEE_DDR_SIZE}" STREQUAL "2G")
    list(APPEND TEE_C_FLAGS -DCFG_HI_TEE_DDR_SIZE_1G)
    set(TRUSTEDCORE_PHY_TEXT_BASE 0x19808000)
endif()

#============================================================
# default mem size
#============================================================
if ("${TRUSTEDCORE_OS_MEM_SIZE}" STREQUAL "")
    set(TRUSTEDCORE_OS_MEM_SIZE 48)
endif()
if ("${TRUSTEDCORE_SEC_MMZ_MEM_SIZE}" STREQUAL "")
    set(TRUSTEDCORE_SEC_MMZ_MEM_SIZE 14)
endif()
if ("${TRUSTEDCORE_SEC_SMMU_MMZ_MEM_SIZE}" STREQUAL "")
    set(TRUSTEDCORE_SEC_SMMU_MMZ_MEM_SIZE 2)
endif()
if ("${TRUSTEDCORE_SEC_SMMU_PAGETABLE_SIZE}" STREQUAL "")
    set(TRUSTEDCORE_SEC_SMMU_PAGETABLE_SIZE 4)
endif()
if ("${TRUSTEDCORE_VMCU_MEM_SIZE}" STREQUAL "")
    set(TRUSTEDCORE_VMCU_MEM_SIZE 15)
endif()
if ("${TRUSTEDCORE_ADSP_MEM_SIZE}" STREQUAL "")
    set(TRUSTEDCORE_ADSP_MEM_SIZE 25)
endif()
if ("${TRUSTEDCORE_VQ6_MEM_SIZE}" STREQUAL "")
    set(TRUSTEDCORE_VQ6_MEM_SIZE 40)
endif()
if ("${ATF_MEM_SIZE}" STREQUAL "")
    set(ATF_MEM_SIZE 2)
endif()
