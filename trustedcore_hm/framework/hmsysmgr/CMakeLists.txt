include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)
include(apps_asan)

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND HMSYSMGR_LIBRARIES
        debug
        syscalls
        syscalls_sysmgr
        cs_sysmgr
        c_sysmgr
        fileio
        mmgr_sysmgr
        pathmgr
        vfs_sysmgr
        ac
        hmlog
        asan_sysmgr
        agent_base
    )
    list(APPEND HMSYSMGR_INTERNAL_LIBRARIES
        ac_policy
        hwsecurec
    )
    list(APPEND HMSYSMGR_WHOLEARCHIVE_LIBRARIES
        security
    )
else()
    list(APPEND HMSYSMGR_LIBRARIES
        debug_a32
        syscalls_a32
        syscalls_sysmgr_a32
        cs_sysmgr_a32
        c_sysmgr_a32
        fileio_a32
        mmgr_sysmgr_a32
        pathmgr_a32
        vfs_sysmgr_a32
        ac_a32
        hmlog_a32
        asan_sysmgr_a32
        agent_base_a32
    )
    list(APPEND HMSYSMGR_INTERNAL_LIBRARIES
        ac_policy
        hwsecurec
    )
    list(APPEND HMSYSMGR_WHOLEARCHIVE_LIBRARIES
        security_a32
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND HMSYSMGR_LDFLAGS
        --undefined=__vsyscall_ptr
        -T${PREBUILD_TOOLS}/common/boot-app-unxom-${ARCH}.lds
    )
else()
    list(APPEND HMSYSMGR_LDFLAGS
        --undefined=__vsyscall_ptr
        -T${PREBUILD_TOOLS}/common/boot-app-${ARCH}.lds
    )
endif()

list(APPEND HMSYSMGR_LDFLAGS
    --gc-sections
    -L${PREBUILD_ARCH_PLAT_LIBS}
    --undefined=_hm_start
    --entry=_hm_start
    -z max-page-size=0x1000
    -nostdlib
    --build-id=none
    -z noexecstack
    -z now
    -z relro
)
list(APPEND HMSYSMGR_LDFLAGS
    -s
)

list(APPEND HMSYSMGR_LDFLAGS
    ${RUNTIMELIB_LINK_PATH}
)

set(HMSYSMGR_TARGET_LIBRARIES)
foreach(l ${HMSYSMGR_INTERNAL_LIBRARIES})
    list(APPEND HMSYSMGR_TARGET_LIBRARIES $<TARGET_FILE:${l}>)
endforeach()
foreach(l ${HMSYSMGR_LIBRARIES})
    list(APPEND HMSYSMGR_TARGET_LIBRARIES -l${l})
endforeach()
foreach(l ${HMSYSMGR_WHOLEARCHIVE_LIBRARIES})
    list(APPEND HMSYSMGR_TARGET_WHOLEARCHIVE_LIBRARIES -l${l})
endforeach()
foreach(l ${COMMON_LIBGCC_COMPS})
    list(APPEND HMSYSMGR_TARGET_LIBRARIES -l${l})
endforeach()

set(COOKED_DRV_LDFLAGS)
foreach(l ${DRV_LDFLAGS})
    if (${l} MATCHES "-Wl,")
        string(SUBSTRING ${l} 4 -1 stripped_l)
        string(REPLACE "," ";" replaced_l ${stripped_l})
        list(APPEND COOKED_DRV_LDFLAGS ${replaced_l})
    else()
        list(APPEND COOKED_DRV_LDFLAGS ${l})
    endif()
endforeach()

if ("${BUILD_TOOL}" STREQUAL "clang")
add_custom_target(hmsysmgr
    COMMAND ${CMAKE_LINKER} ${COOKED_DRV_LDFLAGS} ${HMSYSMGR_LDFLAGS} -o ${CMAKE_CURRENT_BINARY_DIR}/hmsysmgr --start-group ${HMSYSMGR_TARGET_LIBRARIES} --end-group --whole-archive ${PREBUILD_ARCH_PLAT_LIBS}/hmsysmgr.bin.a ${HMSYSMGR_TARGET_WHOLEARCHIVE_LIBRARIES} --no-whole-archive
    VERBATIM)
add_dependencies(hmsysmgr ac_policy hwsecurec)
endif()
