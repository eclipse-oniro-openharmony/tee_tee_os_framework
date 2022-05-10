if (NOT "${CONFIG_NO_VENDOR_LIB_EMBEDDED}" STREQUAL "true")
   include(${PLATFORM_DIR}/common/vendor_shared.cmake)
endif()

if ("${BUILD_KERNEL}" STREQUAL "y")
    if ("${CONFIG_ARCH_AARCH64}" STREQUAL "y")
        list(APPEND KERNEL_RELEASE_64 kernel.elf)
        list(APPEND KERNEL_RELEASE_64 elfloader.o)
    endif()
    if ("${CONFIG_ARCH_AARCH32}" STREQUAL "y")
        list(APPEND KERNEL_RELEASE_32 kernel.elf)
        list(APPEND KERNEL_RELEASE_32 elfloader.o)
    endif()
endif()

if ("${CONFIG_SUPPORT_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_64 teeconfig tee_shared base_shared drv_shared)
else()
    list(APPEND PRODUCT_RELEASE_64 teeconfig tee_shared base_shared drv_shared)
    list(APPEND PRODUCT_RELEASE_32 teeconfig tee_shared base_shared drv_shared)
endif()

list(APPEND PRODUCT_RELEASE_HOST hwsecurec_host ramfsmkimg scramb_syms_host xom)
if ("${CONFIG_SUPPORT_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_64 tee_cmscbb elf_verify_key ac_policy teeagentcommon teeagentcommon_client drv_frame ccmgr hmdrv_stub timer swcrypto_engine crypto_hal dynconfmgr dynconfbuilder spawn_common teedynsrv)
else()
    list(APPEND PRODUCT_RELEASE_64 tee_cmscbb elf_verify_key ac_policy teeagentcommon teeagentcommon_client drv_frame ccmgr hmdrv_stub timer swcrypto_engine crypto_hal dynconfmgr dynconfbuilder spawn_common teedynsrv)
    list(APPEND PRODUCT_RELEASE_32 tee_cmscbb elf_verify_key ac_policy teeagentcommon teeagentcommon_client drv_frame ccmgr hmdrv_stub timer swcrypto_engine crypto_hal dynconfmgr dynconfbuilder spawn_common teedynsrv)
endif()
list(APPEND PRODUCT_RELEASE_32 bz_hm)
if ("${CONFIG_SUPPORT_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_64 hwsecurec)
else()
    list(APPEND PRODUCT_RELEASE_64 hwsecurec)
    list(APPEND PRODUCT_RELEASE_32 hwsecurec)
endif()

if ("${CONFIG_DX_ENABLE}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_32 dx_cc7)
endif()

if ("${CONFIG_ARCH_AARCH64}" STREQUAL "y")
    if (NOT "${CONFIG_FILEMGR_EMBEDDED}" STREQUAL "y")
        list(APPEND PRODUCT_RELEASE_64 hmsysmgr)
    endif()
else()
    if (NOT "${CONFIG_FILEMGR_EMBEDDED}" STREQUAL "y")
        list(APPEND PRODUCT_RELEASE_32 hmsysmgr)
    endif()
endif()

if ("${CONFIG_GTASK_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_64 gtask.elf)
endif()
if ("${CONFIG_GTASK_64BIT}" STREQUAL "false")
    list(APPEND PRODUCT_RELEASE_32 gtask.elf)
endif()

if ("${CONFIG_TA_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_64 tarunner.elf)
endif()

if ("${CONFIG_TA_64BIT}" STREQUAL "false" OR "${CONFIG_TA_32BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_32 tarunner.elf)
endif()

if("${CONFIG_SSA_64BIT}")
    if ("${CONFIG_SSA_64BIT}" STREQUAL "true")
        list(APPEND PRODUCT_RELEASE_64 ssa.elf)
    else()
        list(APPEND PRODUCT_RELEASE_32 ssa.elf)
    endif()
endif()

if ("${CONFIG_RPMB_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_64 rpmb.elf)
endif()
if ("${CONFIG_RPMB_64BIT}" STREQUAL "false")
    list(APPEND PRODUCT_RELEASE_32 rpmb.elf)
endif()

if ("${CONFIG_PERMSRV_64BIT}")
    if ("${CONFIG_PERMSRV_64BIT}" STREQUAL "true")
        list(APPEND PRODUCT_RELEASE_64 permission_service.elf)
    else()
        list(APPEND PRODUCT_RELEASE_32 permission_service.elf)
    endif()
endif()

if ("${CONFIG_PLATDRV_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_64 platdrv.elf)
endif()
if ("${CONFIG_PLATDRV_64BIT}" STREQUAL "false")
    list(APPEND PRODUCT_RELEASE_32 platdrv.elf)
endif()

if (NOT "${CONFIG_OFF_DRV_TIMER}" STREQUAL "y")
if ("${CONFIG_DRV_TIMER_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_64 drv_timer.elf)
endif()
if ("${CONFIG_DRV_TIMER_64BIT}" STREQUAL "false")
    list(APPEND PRODUCT_RELEASE_32 drv_timer.elf)
endif()
endif()

if ("${CONFIG_HUK_SERVICE_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_64 huk_service.elf)
endif()
if ("${CONFIG_HUK_SERVICE_32BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_32 huk_service.elf)
endif()

if ("${CONFIG_KMS}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_64 kms.elf)
endif()

if ("${CONFIG_TUI_32BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_32 tui_internal_shared)
elseif ("${CONFIG_TUI_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_64 tui_internal_shared)
endif()
if ("${CONFIG_REMOTE_ATTESTATION_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_64 tcmgr_service.elf)
endif()
if ("${CONFIG_REMOTE_ATTESTATION_32BIT}" STREQUAL "true")
    list(APPEND PRODUCT_RELEASE_32 tcmgr_service.elf)
endif()

if ("${CONFIG_HUK_SERVICE_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_APPS_64
        huk_service.elf
    )
    list(APPEND CHECK_SYMS
        huk_service.elf
    )
endif()
if ("${CONFIG_HUK_SERVICE_32BIT}" STREQUAL "true")
    list(APPEND PRODUCT_APPS_32
        huk_service.elf
    )
    list(APPEND CHECK_SYMS
        huk_service.elf
    )
endif()

if ("${CONFIG_SSA_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_APPS_64
        ssa.elf
    )
    list(APPEND CHECK_SYMS
        ssa.elf
    )
endif()
if ("${CONFIG_SSA_64BIT}" STREQUAL "false")
    list(APPEND PRODUCT_APPS_32
        ssa.elf
    )
    list(APPEND CHECK_SYMS
        ssa.elf
    )
endif()

if ("${CONFIG_RPMB_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_APPS_64
        rpmb.elf
    )
    list(APPEND CHECK_SYMS
        rpmb.elf
    )
endif()
if ("${CONFIG_RPMB_64BIT}" STREQUAL "false")
    list(APPEND PRODUCT_APPS_32
        rpmb.elf
    )
    list(APPEND CHECK_SYMS
        rpmb.elf
    )
endif()

if ("${CONFIG_PERMSRV_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_APPS_64
        permission_service.elf
    )
endif()
if ("${CONFIG_PERMSRV_64BIT}" STREQUAL "false")
    list(APPEND PRODUCT_APPS_32
        permission_service.elf
    )
endif()

if ("${CONFIG_TUI_32BIT}" STREQUAL "true" OR "${CONFIG_TUI_64BIT}" STREQUAL "true")
    if ("${CONFIG_TUI_32BIT}" STREQUAL "true")
        list(APPEND PRODUCT_APPS_32
            tui_internal_shared
        )
        list(APPEND CHECK_SYMS
            libtui_internal_shared_a32.so
        )
    endif()
    if ("${CONFIG_TUI_64BIT}" STREQUAL "true")
        list(APPEND PRODUCT_APPS_64
            tui_internal_shared
        )
        list(APPEND CHECK_SYMS
            libtui_internal_shared.so
        )
    endif()
endif()

if ("${CONFIG_TA_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_APPS_64
        tee_shared
        tarunner.elf
        base_shared
    )
    list(APPEND CHECK_SYMS
        libtee_shared.so
        libbase_shared.so
    )
endif()

if ("${CONFIG_TA_32BIT}" STREQUAL "true")
    list(APPEND PRODUCT_APPS_32
        tee_shared
        tarunner.elf
        base_shared
    )
    list(APPEND CHECK_SYMS
        libtee_shared.so
        libbase_shared.so
    )
endif()

if ("${CONFIG_GTASK_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_APPS_64
        gtask.elf
    )
    list(APPEND CHECK_SYMS
        gtask.elf
    )
endif()
if ("${CONFIG_GTASK_64BIT}" STREQUAL "false")
    list(APPEND PRODUCT_APPS_32
        gtask.elf
    )
    list(APPEND CHECK_SYMS
        gtask.elf
    )
endif()

if (NOT "${CONFIG_OFF_DRV_TIMER}" STREQUAL "y")
if ("${CONFIG_DRV_TIMER_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_APPS_64
        drv_timer.elf
    )
    list(APPEND CHECK_SYMS
        drv_timer.elf
    )
endif()
if ("${CONFIG_DRV_TIMER_64BIT}" STREQUAL "false")
    list(APPEND PRODUCT_APPS_32
        drv_timer.elf
    )
    list(APPEND CHECK_SYMS
        drv_timer.elf
    )
endif()
endif()

if ("${CONFIG_PLATDRV_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_APPS_64
        platdrv.elf
    )
    list(APPEND CHECK_SYMS
        platdrv.elf
    )
endif()
if ("${CONFIG_PLATDRV_64BIT}" STREQUAL "false")
    list(APPEND PRODUCT_APPS_32
        platdrv.elf
    )
    list(APPEND CHECK_SYMS
        platdrv.elf
    )
endif()

if ("${CONFIG_KMS}" STREQUAL "true")
    list(APPEND PRODUCT_APPS_64
        kms.elf
    )
endif()

if (DEFINED CONFIG_PLATDRV_64BIT)
if (NOT DEFINED CONFIG_SUPPORT_64BIT)
    list(APPEND PRODUCT_APPS_32
        drv_shared
    )
    list(APPEND PRODUCT_APPS_64
        drv_shared
    )
endif()
if ("${CONFIG_SUPPORT_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_APPS_64
        drv_shared
    )
endif()
if ("${CONFIG_SUPPORT_64BIT}" STREQUAL "false")
    list(APPEND PRODUCT_APPS_32
        drv_shared
    )
endif()
endif()

if (DEFINED CONFIG_TEE_DRV_SERVER_64BIT)
if (NOT DEFINED CONFIG_SUPPORT_64BIT)
    list(APPEND PRODUCT_APPS_32
        drv_shared
    )
    list(APPEND PRODUCT_APPS_64
        drv_shared
    )
endif()
if ("${CONFIG_SUPPORT_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_APPS_64
        drv_shared
    )
endif()
if ("${CONFIG_SUPPORT_64BIT}" STREQUAL "false")
    list(APPEND PRODUCT_APPS_32
        drv_shared
    )
endif()
endif()

if ("${CONFIG_TEE_DRV_SERVER_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_APPS_64
        tee_drv_server.elf
    )
    list(APPEND CHECK_SYMS
        tee_drv_server.elf
    )
endif()

if ("${CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_APPS_64
        crypto_mgr.elf
    )
    list(APPEND CHECK_SYMS
        crypto_mgr.elf
    )
endif()
if ("${CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT}" STREQUAL "false")
    list(APPEND PRODUCT_APPS_32
        crypto_mgr.elf
    )
    list(APPEND CHECK_SYMS
        crypto_mgr.elf
    )
endif()

if ("${CONFIG_TEE_MISC_DRIVER_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_APPS_64
        tee_misc_driver.elf
    )
    list(APPEND CHECK_SYMS
        tee_misc_driver.elf
    )
endif()

if ("${CONFIG_TEE_MISC_DRIVER_64BIT}" STREQUAL "false")
    list(APPEND PRODUCT_APPS_32
        tee_misc_driver.elf
    )
    list(APPEND CHECK_SYMS
        tee_misc_driver.elf
    )
endif()

if ("${CONFIG_REMOTE_ATTESTATION_64BIT}" STREQUAL "true")
    list(APPEND PRODUCT_APPS_64
        tcmgr_service.elf
    )
    list(APPEND CHECK_SYMS
        tcmgr_service.elf
    )
endif()
if ("${CONFIG_REMOTE_ATTESTATION_32BIT}" STREQUAL "true")
    list(APPEND PRODUCT_APPS_32
        tcmgr_service.elf
    )
    list(APPEND CHECK_SYMS
        tcmgr_service.elf
    )
endif()

if ("${BUILD_TEST}" STREQUAL "y")
    if ("${BUILD_TA_NAME}" STREQUAL "build_all")
        if ("${CONFIG_TA_64BIT}" STREQUAL "true")
            list(APPEND PRODUCT_RELEASE_64
                drv_test_module
                drv_test_module_copy
                drv_test_module_copy2
                drv_test_module_copy3
                drv_test_module_copy4
                drv_test_module_copy5
                dtfuzz
                platdrv_libdemo
                platdrv_libdemo_dependent
                test_service
            )
            list(APPEND PRODUCT_APPS_64
                communication_perf_test_a64.elf
                crl_ctrl_agent_a64.elf
                crl_ctrl_test_a64.elf
                crypto_full_scale_test_ta_api1_0_a64.elf
                crypto_full_scale_test_ta_api1_1_1_a64.elf
                crypto_full_scale_test_ta_api1_2_0_a64.elf
                crypto_modellized_test_api1_0_a64.elf
                crypto_modellized_test_api1_1_1_a64.elf
                crypto_modellized_test_api1_2_0_a64.elf
                crypto_perf_test_a64.elf
                echo_srv_a64.elf
                fuzz_API_a64.elf
                gm_test_a64.elf
                hello-secure-world_a64.elf
                init_test_a64.elf
                keymaster_byod_test_a64.elf
                mem_pt_pool_recycle_test_a64.elf
                openssl_exchng_test_a64.elf
                perso_perf_test_a64.elf
                pki-test_a64.elf
                receiver_a64.elf
                rpmb_perf_test_a64.elf
                rpmb_pkiperm_a64.elf
                sec_storage_perf_a64.elf
                sender_a64.elf
                ta_api_test_a64.elf
                ta_attestation_test_ta_a64.elf
                ta_attestation_test_ta_2_a64.elf
                test_crypto_func_a64.elf
                test_framwork1_a64.elf
                test_generate_key_perf_a64.elf
                test_huk_service_a64.elf
                test_permsrv_a64.elf
                test_rpmb_a64.elf
                test_sec_storage_a64.elf
                test_secflash_a64.elf
                test_session_pool_a64.elf
                test_srv_a64.elf
                test_tee_api_a64.elf
                test_tui_a64.elf
                timer_ut_a64.elf
                TTA_answerErrorTo_OpenSession_a64.elf
                TTA_answerSuccessTo_OpenSession_Invoke_a64.elf
                TTA_answerSuccessTo_OpenSession_Invoke_Multi_a64.elf
                TTA_Arithmetica_a64.elf
                TTA_Crypto_a64.elf
                TTA_Crypto2_a64.elf
                TTA_DS_a64.elf
                TTA_SML_a64.elf
                TTA_SML2_a64.elf
                TTA_TCF_a64.elf
                TTA_TCF_SingleInstanceTA_a64.elf
                TTA_TCF2_a64.elf
                TTA_testingClientAPI_a64.elf
                TTA_testingInternalAPI_TrustedCoreFramework_ICA_a64.elf
                TTA_Time_a64.elf
            )
            list(APPEND TEST_APPS_DIR_64
                communication_perf_test_a64
                crl_ctrl_agent_a64
                crl_ctrl_test_a64
                crypto_full_scale_test_ta_api1_0_a64
                crypto_full_scale_test_ta_api1_1_1_a64
                crypto_full_scale_test_ta_api1_2_0_a64
                crypto_modellized_test_api1_0_a64
                crypto_modellized_test_api1_1_1_a64
                crypto_modellized_test_api1_2_0_a64
                crypto_perf_test_a64
                drv_test_module
                drv_test_module_copy
                drv_test_module_copy2
                drv_test_module_copy3
                drv_test_module_copy4
                drv_test_module_copy5
                echo_srv_a64
                fuzz_API_a64
                gm_test_a64
                hello-secure-world_a64
                init_test_a64
                keymaster_byod_test_a64
                libdtfuzz
                libtest_service
                mem_pt_pool_recycle_test_a64
                openssl_exchng_test_a64
                perso_perf_test_a64
                pki-test_a64
                platdrv_libdemo
                platdrv_libdemo_dependent
                receiver_a64
                rpmb_perf_test_a64
                rpmb_pkiperm_a64
                sec_storage_perf_a64
                sender_a64
                ta_api_test_a64
                ta_attestation_test_ta_a64
                ta_attestation_test_ta_2_a64
                test_crypto_func_a64
                test_crypto_func_ext_a64
                test_framwork1_a64
                test_generate_key_perf_a64
                test_huk_service_a64
                test_permsrv_a64
                test_rpmb_a64
                test_sec_storage_a64
                test_secflash_a64
                test_session_pool_a64
                test_srv_a64
                test_tee_api_a64
                test_tui_a64
                timer_ut_a64
                TTA_answerErrorTo_OpenSession_a64
                TTA_answerSuccessTo_OpenSession_Invoke_a64
                TTA_answerSuccessTo_OpenSession_Invoke_Multi_a64
                TTA_Arithmetica_a64
                TTA_Crypto_a64
                TTA_Crypto2_a64
                TTA_DS_a64
                TTA_SML_a64
                TTA_SML2_a64
                TTA_TCF_a64
                TTA_TCF_SingleInstanceTA_a64
                TTA_TCF2_a64
                TTA_testingClientAPI_a64
                TTA_testingInternalAPI_TrustedCoreFramework_ICA_a64
                TTA_Time_a64
            )
            if (NOT "${CONFIG_NO_VENDOR_LIB_EMBEDDED}" STREQUAL "true")
                list(APPEND PRODUCT_APPS_64
                   test_crypto_func_ext_a64.elf
                )
                list(APPEND TEST_APPS_DIR_64
                    test_crypto_func_ext_a64
                )
            endif()
        endif()

        if ("${CONFIG_TA_32BIT}" STREQUAL "true")
            list(APPEND PRODUCT_RELEASE_32
                drv_test_module_a32
                drv_test_module_copy_a32
                drv_test_module_copy2_a32
                dtfuzz_a32
                test_service_a32
                platdrv_libdemo_a32
                platdrv_libdemo_dependent_a32
            )
            list(APPEND PRODUCT_APPS_32
                communication_perf_test.elf
                crl_ctrl_agent.elf
                crl_ctrl_test.elf
                crypto_full_scale_test_ta_api1_0.elf
                crypto_full_scale_test_ta_api1_1_1.elf
                crypto_full_scale_test_ta_api1_2_0.elf
                crypto_modellized_test_api1_0.elf
                crypto_modellized_test_api1_1_1.elf
                crypto_modellized_test_api1_2_0.elf
                crypto_perf_test.elf
                echo_srv.elf
                fuzz_API.elf
                gatekeeper_get_state.elf
                gm_test.elf
                hello-secure-world.elf
                init_test.elf
                just_save_log_ta.elf
                keymaster_byod_test.elf
                openssl_exchng_test.elf
                perso_perf_test.elf
                pki-test.elf
                receiver.elf
                rpmb_perf_test.elf
                rpmb_pkiperm.elf
                sec_storage_perf.elf
                sectest.elf
                sender.elf
                ta_api_test.elf
                ta_attestation_test_ta.elf
                ta_attestation_test_ta_2.elf
                ta_load_test_v1_ta.elf
                ta_load_test_v2_ta.elf
                ta_load_test_v3_ta.elf
                test_crypto_func.elf
                test_crypto_func_ext.elf
                test_framwork1.elf
                test_generate_key_perf.elf
                test_huk_service.elf
                test_km_rot_api.elf
                test_permsrv.elf
                test_rpmb.elf
                test_sec_storage.elf
                test_secflash.elf
                test_session_pool.elf
                test_srv.elf
                test_tee_api.elf
                test_tui.elf
                timer_ut.elf
                TTA_answerErrorTo_OpenSession.elf
                TTA_answerSuccessTo_OpenSession_Invoke.elf
                TTA_answerSuccessTo_OpenSession_Invoke_Multi.elf
                TTA_Arithmetica.elf
                TTA_Crypto.elf
                TTA_Crypto2.elf
                TTA_DS.elf
                TTA_SML.elf
                TTA_SML2.elf
                TTA_TCF.elf
                TTA_TCF_SingleInstanceTA.elf
                TTA_TCF2.elf
                TTA_testingClientAPI.elf
                TTA_testingInternalAPI_TrustedCoreFramework_ICA.elf
                TTA_Time.elf
                TTA1.elf
                TTA2.elf
            )
            list(APPEND TEST_APPS_DIR_32
                communication_perf_test
                crl_ctrl_agent
                crl_ctrl_test
                crypto_full_scale_test_ta_api1_0
                crypto_full_scale_test_ta_api1_1_1
                crypto_full_scale_test_ta_api1_2_0
                crypto_modellized_test_api1_0
                crypto_modellized_test_api1_1_1
                crypto_modellized_test_api1_2_0
                crypto_perf_test
                drv_test_module_a32
                drv_test_module_copy_a32
                drv_test_module_copy2_a32
                echo_srv
                fuzz_API
                gatekeeper_get_state
                gm_test
                hello-secure-world
                init_test
                just_save_log_ta
                keymaster_byod_test
                libdtfuzz_a32
                libtest_service_a32
                openssl_exchng_test
                perso_perf_test
                platdrv_libdemo_a32
                platdrv_libdemo_dependent_a32
                pki-test
                receiver
                rpmb_perf_test
                rpmb_pkiperm
                sec_storage_perf
                sectest
                sender
                ta_api_test
                ta_attestation_test_ta
                ta_attestation_test_ta_2
                ta_load_test_v1_ta
                ta_load_test_v2_ta
                ta_load_test_v3_ta
                test_crypto_func
                test_crypto_func_ext
                test_framwork1
                test_generate_key_perf
                test_huk_service
                test_km_rot_api
                test_permsrv
                test_rpmb
                test_sec_storage
                test_secflash
                test_session_pool
                test_srv
                test_tee_api
                test_tui
                timer_ut
                TTA_answerErrorTo_OpenSession
                TTA_answerSuccessTo_OpenSession_Invoke
                TTA_answerSuccessTo_OpenSession_Invoke_Multi
                TTA_Arithmetica
                TTA_Crypto
                TTA_Crypto2
                TTA_DS
                TTA_SML
                TTA_SML2
                TTA_TCF
                TTA_TCF_SingleInstanceTA
                TTA_TCF2
                TTA_testingClientAPI
                TTA_testingInternalAPI_TrustedCoreFramework_ICA
                TTA_Time
                TTA1
                TTA2
            )
            if (NOT "${CONFIG_NO_VENDOR_LIB_EMBEDDED}" STREQUAL "true")
                list(APPEND PRODUCT_APPS_64
                    test_crypto_func_ext.elf
                )
                list(APPEND TEST_APPS_DIR_64
                    test_crypto_func_ext
                )
            endif()
        endif()
    else()
        foreach(r ${PRODUCT_RELEASE_64})
            string(FIND ${r} ".elf" pos)
            if (${pos} GREATER 0)
                list(REMOVE_ITEM PRODUCT_RELEASE_64 ${r})
            endif()
        endforeach(r)

        foreach(r ${PRODUCT_RELEASE_32})
            string(FIND ${r} ".elf" pos)
            if (${pos} GREATER 0)
                list(REMOVE_ITEM PRODUCT_RELEASE_32 ${r})
            endif()
        endforeach(r)

        if ("${CONFIG_TA_64BIT}" STREQUAL "true" AND EXISTS ${PROJECT_SOURCE_DIR}/tee-tests/tests64/${BUILD_TA_NAME})
            list(APPEND PRODUCT_RELEASE_64
                drv_test_module
                drv_test_module_copy
                drv_test_module_copy2
                drv_test_module_copy3
                drv_test_module_copy4
                drv_test_module_copy5
                dtfuzz
                platdrv_libdemo
                platdrv_libdemo_dependent
                test_service
            )
            list(APPEND PRODUCT_APPS_64
                "${BUILD_TA_NAME}.elf"
            )
            set(TEST_APPS_DIR_64 "${BUILD_TA_NAME}")
        endif()

        if ("${CONFIG_TA_32BIT}" STREQUAL "true" AND EXISTS ${PROJECT_SOURCE_DIR}/tee-tests/tests32/${BUILD_TA_NAME})
            list(APPEND PRODUCT_RELEASE_32
                drv_test_module_a32
                drv_test_module_copy_a32
                drv_test_module_copy2_a32
                dtfuzz_a32
                test_service_a32
                platdrv_libdemo_a32
                platdrv_libdemo_dependent_a32
            )
            list(APPEND PRODUCT_APPS_32
                "${BUILD_TA_NAME}.elf"
            )
            set(TEST_APPS_DIR_32 "${BUILD_TA_NAME}")
        endif()
    endif()
endif()
