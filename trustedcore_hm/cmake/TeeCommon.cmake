string(FIND ${PROJECT_SOURCE_DIR} "hm-teeos" IS_TEEOS)
if (IS_TEEOS GREATER 0)
    set(TOP_IS_TEEOS "true")
    set(TOP_TEEOS_DIR ${PROJECT_SOURCE_DIR}/..)
else()
    set(TOP_IS_TEEOS "false")
    set(TOP_TEEOS_DIR ${PROJECT_SOURCE_DIR}/../..)
endif()

set(LIB_PREFIX lib)
set(SO_SUFFIX so)
set(AR_SUFFIX a)

if("${ARCH}" STREQUAL "aarch64")
    set(GCC_TOOLCHAIN_PATH ${GCC64_TOOLCHAIN_PATH})
else()
    set(GCC_TOOLCHAIN_PATH ${GCC32_TOOLCHAIN_PATH})
endif()

function(tee_append_compiler_flags target)
    set(flags ${ARGN})
    list(LENGTH flags num_flags)
    if (num_flags GREATER 0)
        foreach (f ${flags})
            target_compile_options(${target} PRIVATE ${f})
        endforeach()
    endif()
endfunction()

function(tee_remove_build_path_64 target)
STRING(REGEX REPLACE "hm-teeos" "" abs_path ${PROJECT_SOURCE_DIR})
add_custom_command(TARGET ${target}
                    PRE_BUILD
                    COMMAND bash -c "find . -name \"*.obj\"| grep -v \".S.obj\" | xargs -i ${CMAKE_DIS} {}"
                    COMMAND bash -c "find . -name \"*.ll\" | xargs -i sed -i '1,2s^${abs_path}^^g'  {} "
                    COMMAND bash -c "find . -name \"*.ll\" | xargs -i ${CMAKE_AS} {} "
                    COMMAND bash -c "find . -name \"*.bc\" | sed -e 'p;s/.bc//g' | xargs -n2 mv "
                    VERBATIM
                   )
endfunction()

function(tee_remove_build_path_32 target)
STRING(REGEX REPLACE "hm-teeos" "" abs_path ${PROJECT_SOURCE_DIR})
add_custom_command(TARGET ${target}
                    PRE_BUILD
                    COMMAND bash -c "find . -name \"*.o\"  | grep -v \".S.o\" | xargs -i ${CMAKE_DIS} {}"
                    COMMAND bash -c "find . -name \"*.ll\" | xargs -i sed -i '1,2s^${abs_path}^^g'  {} "
                    COMMAND bash -c "find . -name \"*.ll\" | xargs -i ${CMAKE_AS} {} "
                    COMMAND bash -c "find . -name \"*.bc\" | sed -e 'p;s/.bc//g' | xargs -n2 mv "
                    VERBATIM
                   )
endfunction()

function(tee_append_definitions target)
    set(flags ${ARGN})
    list(LENGTH flags num_flags)
    if (num_flags GREATER 0)
        foreach (f ${flags})
            target_compile_definitions(${target} PRIVATE ${f})
        endforeach()
    endif()
endfunction()

function(tee_include_directories target)
    set(flags ${ARGN})
    list(LENGTH flags num_flags)
    if (num_flags GREATER 0)
        foreach (f ${flags})
            target_include_directories(${target} PRIVATE ${f})
        endforeach()
    endif()
endfunction()

function(_tee_target_link_options target)
    set(flags ${ARGN})
    list(LENGTH flags num_flags)
    if (num_flags GREATER 0)
        get_target_property(old_link_flags ${target} LINK_FLAGS)
        if (old_link_flags)
            set_target_properties(${target} PROPERTIES LINK_FLAGS "${old_link_flags} ${flags}")
        else()
            set_target_properties(${target} PROPERTIES LINK_FLAGS "${flags}")
        endif()
    endif()
endfunction()

function(tee_append_linker_flags target)
    set(flags ${ARGN})
    list(LENGTH flags num_flags)
    if (num_flags GREATER 0)
        foreach (f ${flags})
            string(REPLACE " " "," wlf ${f})
            _tee_target_link_options(${target} -Wl,${wlf})
        endforeach()
    endif()
endfunction()

function(tee_target_linker_flags target)
    set(flags ${ARGN})
    list(LENGTH flags num_flags)
    if (num_flags GREATER 0)
        foreach (f ${flags})
            _tee_target_link_options(${target} ${f})
        endforeach()
    endif()
endfunction()

function(tee_include_dirs target)
    cmake_parse_arguments(
        ARG
        "PRIVATE;INTERNAL;PUBLIC"
        ""
        "DIRS"
        ${ARGN}
    )

    list(LENGTH ARG_DIRS num_flags)
    if (NOT num_flags GREATER 0)
        return()
    endif()

    if (ARG_PRIVATE)
        foreach (f ${ARG_DIRS})
            target_include_directories(${target} PRIVATE ${f})
        endforeach()
    elseif (ARG_INTERNAL)
        foreach (f ${ARG_DIRS})
            target_include_directories(${target} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/${f}>)
        endforeach()
    elseif (ARG_PUBLIC)
    endif()
endfunction()

function(tee_library_default_link target)
    cmake_parse_arguments(
        TEELIB
        ""
        ""
        "OBJECTS;WHOLEARCHIVE;LIBRARIES;LINKGROUP"
        ${ARGN}
    )

    target_link_libraries(${target} PRIVATE "${TEELIB_OBJECTS}")
    target_link_libraries(${target} PRIVATE -Wl,--whole-archive "${TEELIB_WHOLEARCHIVE}" -Wl,--no-whole-archive)
    target_link_libraries(${target} PRIVATE "${TEELIB_LIBRARIES}")
    target_link_libraries(${target} PRIVATE -Wl,--start-group "${TEELIB_LINKGROUP}" -Wl,--end-group)

    foreach (obj ${TEELIB_OBJECTS})
        target_link_libraries(${obj} PRIVATE ${TEELIB_LIBRARIES})
    endforeach()
endfunction()

function(tee_append_definitions_auto target prefix)
    get_cmake_property(_vars VARIABLES)
    string(REGEX MATCHALL "(^|;)${prefix}[A-Za-z0-9_]*" _matchedVars "${_vars}")
    list(SORT _vars)
    foreach (_v ${_matchedVars})
        tee_append_definitions(${target} "${_v}=${${_v}}")
    endforeach()
endfunction()

function(tee_set_lds target lds)
    _tee_target_link_options(${target} -Wl,-T,${lds})
    set_target_properties(${target} PROPERTIES LINK_DEPENDS ${lds})
endfunction()

function(tee_default_include target)
    if ("${TOP_IS_TEEOS}" STREQUAL "true")
        target_include_directories(${target} PRIVATE ${HMSDKINCLUDE})
    endif()
endfunction()

function(bins_default_link target)
    cmake_parse_arguments(
        TEEBINS
        "DYNAMIC"
        ""
        "LINKGROUP;OBJECTS;WHOLEARCHIVE;LIBRARIES"
        ${ARGN}
    )
    target_link_libraries(${target} PRIVATE "${TEEBINS_OBJECTS}")
    target_link_libraries(${target} PRIVATE -Wl,--whole-archive "${TEEBINS_WHOLEARCHIVE}" -Wl,--no-whole-archive)
    target_link_libraries(${target} PRIVATE "${TEEBINS_LIBRARIES}")
    target_link_libraries(${target} PRIVATE -Wl,--start-group "${TEEBINS_LINKGROUP}" -Wl,--end-group)
    foreach (obj ${TEEBINS_OBJECTS})
        target_link_libraries(${obj} PRIVATE ${TEEBINS_LIBRARIES})
    endforeach()
endfunction()

function(find_c_compiler_component comp_name comp_path)
    if (CMAKE_SYSROOT)
        set(search_sysroot "--sysroot=${TOOLCHAIN_ABS_PATH}")
    endif()
    if (comp_name STREQUAL "libgcc_eh")
        set(cmd_opt "-print-file-name=${comp_name}.a")
    else()
        set(cmd_opt "--print-prog-name=${comp_name}")
    endif()

    execute_process(
        COMMAND ${GCC_C_COMPILER} ${search_sysroot} ${cmd_opt}
        RESULT_VARIABLE ret
        OUTPUT_VARIABLE path
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(${comp_path} ${path} PARENT_SCOPE)
endfunction()

set(LIBCOMPILER_RT_BUILTINS_PATH)
set(LIBGCC_RET)
set(LIBGCC_EH_PATH)
set(LIBGCC_EH_RET)
set(LIBATOMIC_PATH)
set(LIBATOMIC_RET)
set(RUNTIMELIB_LINK_PATH)

if (NOT "${GCC_TOOLCHAIN_PATH}" STREQUAL "")
    if("${ARCH}" STREQUAL "aarch64")
        set(LIBCOMPILER_RT_BUILTINS_PATH "${TOP_TEEOS_DIR}/hm-teeos/libs/teelib/libcompiler-rt/aarch64-build/lib/linux/libclang_rt.builtins-aarch64.a")
    else()
        set(LIBCOMPILER_RT_BUILTINS_PATH "${TOP_TEEOS_DIR}/hm-teeos/libs/teelib/libcompiler-rt/arm-build/lib/linux/libclang_rt.builtins-arm.a")
    endif()
else()
    if("${ARCH}" STREQUAL "aarch64")
        set(LIBCOMPILER_RT_BUILTINS_PATH "${TOP_TEEOS_DIR}/hm-apps/trustedcore_hm/prebuild/hm-teeos-release/libs/aarch64/libclang_rt.builtins-aarch64.a")
    else()
        set(LIBCOMPILER_RT_BUILTINS_PATH "${TOP_TEEOS_DIR}/hm-apps/trustedcore_hm/prebuild/hm-teeos-release/libs/arm/libclang_rt.builtins-arm.a")
    endif()
endif()

find_c_compiler_component(libgcc_eh LIBGCC_EH_PATH)
find_c_compiler_component(libatomic.a LIBATOMIC_PATH)

if (LIBCOMPILER_RT_BUILTINS_PATH)
    get_filename_component(LIBCOMPILER_RT_DIR "${LIBCOMPILER_RT_BUILTINS_PATH}" DIRECTORY)
    set(COMMON_LDFLAGS
        ${COMMON_LDFLAGS}
        -L${LIBCOMPILER_RT_DIR}
    )
    if("${ARCH}" STREQUAL "aarch64")
        set(COMMON_LIBGCC_COMPS
            ${COMMON_LIBGCC_COMPS}
            clang_rt.builtins-aarch64
        )
    else()
        set(COMMON_LIBGCC_COMPS
            ${COMMON_LIBGCC_COMPS}
            clang_rt.builtins-arm
        )
    endif()
    set(RUNTIMELIB_LINK_PATH
        ${RUNTIMELIB_LINK_PATH}
        -L${LIBCOMPILER_RT_DIR}
    )
endif()

if (LIBGCC_EH_PATH)
    get_filename_component(LIBGCC_EH_DIR "${LIBGCC_EH_PATH}" DIRECTORY)
    set(COMMON_LDFLAGS
        ${COMMON_LDFLAGS}
        -L${LIBGCC_EH_DIR}
        )
    set(COMMON_LIBGCC_COMPS
        ${COMMON_LIBGCC_COMPS}
        gcc_eh
    )
    set(RUNTIMELIB_LINK_PATH
        ${RUNTIMELIB_LINK_PATH}
        -L${LIBGCC_EH_DIR}
    )
endif()

if (LIBATOMIC_PATH)
    get_filename_component(LIBATOMIC_DIR "${LIBATOMIC_PATH}" DIRECTORY)
    link_directories(${LIBATOMIC_DIR})
    set(CXX_COMPS
        ${CXX_COMPS}
        :libatomic.a
    )
endif()

list(APPEND CFI_VISIBILITY_HIDDEN ssagent rpmbagent permsrv teesmcmgr.elf)
if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND CFI_NO_ICALL ccmgr_hm vfs ac swcrypto_engine hongmeng ta_mt zlib_64 crypto taentry taloader.elf gtask teeos ssa decouple swcrypto_engine tarunner.elf timer crypto_hal)
else()
    list(APPEND CFI_NO_ICALL ccmgr_hm vfs ac hongmeng ta_mt zlib crypto taentry taloader.elf gtask teeos ssa decouple swcrypto_engine tarunner.elf timer crypto_hal)
    if ("${PLATFORM_NAME}" STREQUAL "mtk")
        list(APPEND CFI_NO_ICALL platdrv.elf drv_frame)
    endif()
endif()

list(APPEND XOM32_BLACK_LIST taloader.elf ta_mt mmgr_sysmgr asan_sysmgr tui_internal tui.elf thp_afe_990)
###################################################
# Interfaces to create executatbles and libraries #
###################################################
function(tee_add_executable target)
    cmake_parse_arguments(
        TEEBINS
        "DYNAMIC;DO_INSTALL;NO_CFI;NO_XOM"
        "RPATH;COMPILE_TOOL"
        "SOURCES;C_SOURCES;CPP_SOURCES;ASM_SOURCES;COMPILER_FLAGS;C_COMPILER_FLAGS;CPP_COMPILER_FLAGS;ASM_COMPILER_FLAGS;PRIVATE_INCLUDES;C_PRIVATE_INCLUDES;CPP_PRIVATE_INCLUDES;ASM_PRIVATE_INCLUDES;LINKGROUP;OBJECTS;WHOLEARCHIVE;LIBRARY_PATHS;LIBRARIES;LINKER_SCRIPT;COMPILER_DEFINITIONS;C_COMPILER_DEFINITIONS;CPP_COMPILER_DEFINITIONS;ASM_COMPILER_DEFINITIONS;LD_FLAGS;INSTALL_DIR"
        ${ARGN}
    )
    if (NOT TEEBINS_COMPILE_TOOL STREQUAL BUILD_TOOL)
        return()
    endif()

    set(TEEBINS_CFI_FLAGS)
    set(TEEBINS_XOM_FLAGS)
    if ("${TEEBINS_COMPILE_TOOL}" STREQUAL "clang")
        if (NOT TEEBINS_NO_CFI)
            if ("${CONFIG_LLVM_CFI}" STREQUAL "y")
                #list(APPEND TEEBINS_CFI_FLAGS -fsanitize=cfi -fno-sanitize-cfi-cross-dso)
                if (NOT ${target} IN_LIST CFI_VISIBILITY_HIDDEN)
                    #list(APPEND TEEBINS_CFI_FLAGS -fvisibility=default)
                endif()
                if (${target} IN_LIST CFI_NO_ICALL)
                    #list(APPEND TEEBINS_CFI_FLAGS -fno-sanitize=cfi-icall)
                endif()
            endif()
        endif()

        if (NOT TEEBINS_NO_XOM)
            if ("${CONFIG_ENABLE_XOM32}" STREQUAL "y" AND "${ARCH}" STREQUAL "arm")
                if (NOT "${BUILD_TA}" STREQUAL "y")
                    if (NOT "${TARGET_IS_TA}" STREQUAL "y")
                        if (NOT ${target} IN_LIST XOM32_BLACK_LIST)
                            set(TEEBINS_XOM_FLAGS ${TEEBINS_XOM_FLAGS} -mexecute-only -fno-jump-tables)
                        endif()
                    else()
                        if ("${TARGET_IS_EXT_LIB}" STREQUAL "y")
                            if (NOT ${target} IN_LIST XOM32_BLACK_LIST)
                                set(TEEBINS_XOM_FLAGS ${TEEBINS_XOM_FLAGS} -fno-jump-tables)
                            endif()
                        else()
                            if (NOT ${target} IN_LIST XOM32_BLACK_LIST)
                                set(TEEBINS_XOM_FLAGS ${TEEBINS_XOM_FLAGS} -mexecute-only -fno-jump-tables)
                            endif()
                        endif()
                    endif()
                endif()
            endif()
        endif()
    endif()

    add_executable(${target} ${TEEBINS_SOURCES} ${TEEBINS_C_SOURCES} ${TEEBINS_CPP_SOURCES} ${TEEBINS_ASM_SOURCES})
    list(REMOVE_DUPLICATES TEEBINS_COMPILER_FLAGS)
    list(REMOVE_DUPLICATES TEEBINS_CFI_FLAGS)
    list(REMOVE_DUPLICATES TEEBINS_XOM_FLAGS)
    list(REMOVE_DUPLICATES TEEBINS_PRIVATE_INCLUDES)
    list(REMOVE_DUPLICATES TEEBINS_COMPILER_DEFINITIONS)
    list(REMOVE_DUPLICATES TEEBINS_LD_FLAGS)
    tee_append_compiler_flags(${target} ${TEEBINS_COMPILER_FLAGS})
    foreach(f IN LISTS TEEBINS_CFI_FLAGS)
        target_compile_options(${target} PRIVATE ${f})
    endforeach()
    foreach(f IN LISTS TEEBINS_XOM_FLAGS)
        target_compile_options(${target} PRIVATE ${f})
    endforeach()
    #tee_append_definitions_auto(${target} "CONFIG")
    tee_default_include(${target})

    if (TEEBINS_C_PRIVATE_INCLUDES)
        set(c_includes)
        foreach (i ${TEEBINS_C_PRIVATE_INCLUDES})
            if (NOT c_includes)
                set(c_includes "-I${i}")
            else()
                set(c_includes "${c_includes} -I${i}")
            endif()
        endforeach()
        if ("${TOP_IS_TEEOS}" STREQUAL "true")
            set(c_includes "${c_includes} -I${HMSDKINCLUDE}")
        endif()
    endif()

    if (TEEBINS_CPP_PRIVATE_INCLUDES)
        set(cpp_includes)
        foreach (i ${TEEBINS_CPP_PRIVATE_INCLUDES})
            if (NOT cpp_includes)
                set(cpp_includes "-I${i}")
            else()
                set(cpp_includes "${cpp_includes} -I${i}")
            endif()
        endforeach()
        if ("${TOP_IS_TEEOS}" STREQUAL "true")
            set(cpp_includes "${cpp_includes} -I${HMSDKINCLUDE}")
        endif()
    endif()

    if (TEEBINS_ASM_PRIVATE_INCLUDES)
        set(asm_includes)
        foreach (i ${TEEBINS_ASM_PRIVATE_INCLUDES})
            if (NOT asm_includes)
                set(asm_includes "-I${i}")
            else()
                set(asm_includes "${asm_includes} -I${i}")
            endif()
        endforeach()
        if ("${TOP_IS_TEEOS}" STREQUAL "true")
            set(asm_includes "${asm_includes} -I${HMSDKINCLUDE}")
        endif()
    endif()

    if (TEEBINS_C_COMPILER_FLAGS)
        set(c_flags)
        set(c_flags_no_warn)
        foreach (f ${TEEBINS_C_COMPILER_FLAGS})
            if(NOT c_flags)
                set(c_flags "${f}")
            else()
                set(c_flags "${c_flags} ${f}")
            endif()
            if(NOT c_flags_no_warn)
                set(c_flags_no_warn "${f}")
            else()
                if (NOT "${f}" STREQUAL "-Werror")
                    set(c_flags_no_warn "${c_flags_no_warn} ${f}")
                endif()
            endif()
        endforeach()
    endif()

    foreach (f IN LISTS TEEBINS_CFI_FLAGS)
        if(NOT c_flags)
            set(c_flags "${f}")
        else()
            set(c_flags "${c_flags} ${f}")
        endif()
    endforeach()

    foreach (f IN LISTS TEEBINS_XOM_FLAGS)
        if(NOT c_flags)
            set(c_flags "${f}")
        else()
            set(c_flags "${c_flags} ${f}")
        endif()
    endforeach()

    if (TEEBINS_CPP_COMPILER_FLAGS)
        set(cpp_flags)
        foreach (f ${TEEBINS_CPP_COMPILER_FLAGS})
            if(NOT cpp_flags)
                set(cpp_flags "${f}")
            else()
                set(cpp_flags "${cpp_flags} ${f}")
            endif()
        endforeach()
    endif()

    foreach (f IN LISTS TEEBINS_CFI_FLAGS)
        if(NOT cpp_flags)
            set(cpp_flags "${f}")
        else()
            set(cpp_flags "${cpp_flags} ${f}")
        endif()
    endforeach()

    foreach (f IN LISTS TEEBINS_XOM_FLAGS)
        if(NOT cpp_flags)
            set(cpp_flags "${f}")
        else()
            set(cpp_flags "${cpp_flags} ${f}")
        endif()
    endforeach()

    if (TEEBINS_C_COMPILER_DEFINITIONS)
        set(c_defs)
        foreach (d ${TEEBINS_C_COMPILER_DEFINITIONS})
            if(NOT c_defs)
                set(c_defs "-D${d}")
            else()
                set(c_defs "${c_defs} -D${d}")
            endif()
        endforeach()
    endif()

    if (TEEBINS_ASM_COMPILER_DEFINITIONS)
        set(asm_defs)
        foreach (d ${TEEBINS_ASM_COMPILER_DEFINITIONS})
            if (NOT asm_defs)
                set(asm_defs "-D${d}")
            else()
                set(asm_defs "${asm_defs} -D${d}")
            endif()
        endforeach()
    endif()

    if (TEEBINS_CPP_COMPILER_DEFINITIONS)
        set(cpp_defs)
        foreach (d ${TEEBINS_CPP_COMPILER_DEFINITIONS})
            if(NOT cpp_defs)
                set(cpp_defs "-D${d}")
            else()
                set(cpp_defs "${cpp_defs} -D${d}")
            endif()
        endforeach()
    endif()

    if (TEEBINS_ASM_COMPILER_FLAGS)
        set(asm_flags)
        foreach (f ${TEEBINS_ASM_COMPILER_FLAGS})
            if(NOT asm_flags)
                set(asm_flags "${f}")
            else()
                set(asm_flags "${asm_flags} ${f}")
            endif()
        endforeach()
    endif()
    foreach (f IN LISTS TEEBINS_CFI_FLAGS)
        if(NOT asm_flags)
            set(asm_flags "${f}")
        else()
            set(asm_flags "${asm_flags} ${f}")
        endif()
    endforeach()
    foreach (f IN LISTS TEEBINS_XOM_FLAGS)
        if(NOT asm_flags)
            set(asm_flags "${f}")
        else()
            set(asm_flags "${asm_flags} ${f}")
        endif()
    endforeach()

    list(REMOVE_DUPLICATES c_includes)
    list(REMOVE_DUPLICATES c_defs)
    list(REMOVE_DUPLICATES c_flags)
    list(REMOVE_DUPLICATES cpp_includes)
    list(REMOVE_DUPLICATES cpp_defs)
    list(REMOVE_DUPLICATES cpp_flags)
    list(REMOVE_DUPLICATES asm_includes)
    list(REMOVE_DUPLICATES asm_flags)
    list(REMOVE_DUPLICATES asm_defs)

    set(TEEBINS_C_SOURCES_NO_WARN )
    set(BLACK_LIST_WARN antiroot)
    set(BLACK_LIST_WARN "${BLACK_LIST_WARN}|libfdt")
    set(BLACK_LIST_WARN "${BLACK_LIST_WARN}|kirin/isp")
    set(BLACK_LIST_WARN "${BLACK_LIST_WARN}|touchscreen/panel/tui_fts")
    set(BLACK_LIST_WARN "${BLACK_LIST_WARN}|fingerprint")
    set(BLACK_LIST_WARN "${BLACK_LIST_WARN}|npu_v100")
    set(BLACK_LIST_WARN "${BLACK_LIST_WARN}|secureboot")
    set(BLACK_LIST_WARN "${BLACK_LIST_WARN}|hieps")

    set(TEEBINS_C_SOURCES_NO_WARN )
    foreach (f IN LISTS TEEBINS_C_SOURCES)
        if (${f} MATCHES "${BLACK_LIST_WARN}")
            list(REMOVE_ITEM TEEBINS_C_SOURCES ${f})
            list(APPEND TEEBINS_C_SOURCES_NO_WARN ${f})
        endif()
    endforeach()

    set_source_files_properties(${TEEBINS_C_SOURCES_NO_WARN} PROPERTIES COMPILE_FLAGS "${c_includes} ${c_defs} ${c_flags_no_warn}")
    set_source_files_properties(${TEEBINS_C_SOURCES} PROPERTIES COMPILE_FLAGS "${c_includes} ${c_defs} ${c_flags}")
    set_source_files_properties(${TEEBINS_CPP_SOURCES} PROPERTIES COMPILE_FLAGS "${cpp_includes} ${cpp_defs} ${cpp_flags}")
    set_source_files_properties(${TEEBINS_ASM_SOURCES} PROPERTIES COMPILE_FLAGS "${asm_includes} ${asm_defs} ${asm_flags}")


    if (TEEBINS_DYNAMIC)
        set(bins_link_arg "DYNAMIC")
    endif()

    if (TEEBINS_PRIVATE_INCLUDES)
        tee_include_directories(${target} ${TEEBINS_PRIVATE_INCLUDES})
    endif()

    if (TEEBINS_LIBRARY_PATHS)
        foreach (p ${TEEBINS_LIBRARY_PATHS})
            tee_target_linker_flags(${target} -L${p})
        endforeach()
    endif()

    if (TEEBINS_LINKER_SCRIPT)
        tee_set_lds(${target} ${TEEBINS_LINKER_SCRIPT})
    endif()

    if (TEEBINS_LD_FLAGS)
        foreach (f ${TEEBINS_LD_FLAGS})
            tee_target_linker_flags(${target} ${f})
        endforeach()
    endif()

    if (TEEBINS_COMPILER_DEFINITIONS)
        foreach (d ${TEEBINS_COMPILER_DEFINITIONS})
            tee_append_definitions(${target} ${d})
        endforeach()
    endif()

    bins_default_link(${target}
        ${bins_link_arg}
        OBJECTS ${TEEBINS_OBJECTS}
        WHOLEARCHIVE ${TEEBINS_WHOLEARCHIVE}
        LINKGROUP ${TEEBINS_LINKGROUP}
        LIBRARIES ${TEEBINS_LIBRARIES}
    )

    add_custom_command(TARGET ${target}
        POST_BUILD
        COMMAND ${CMAKE_OBJCOPY} $<TARGET_FILE:${target}>
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${target}> $<TARGET_FILE_DIR:${target}>/${target}
    )

    if (TEEBINS_DO_INSTALL)
        install(TARGETS ${target}
            COMPONENT bins_install
            RUNTIME DESTINATION ${TEEBINS_INSTALL_DIR}
            PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                        GROUP_READ GROUP_EXECUTE
                        WORLD_READ WORLD_EXECUTE
        )
        install(FILES $<TARGET_FILE:${target}>
            COMPONENT bins_install
            DESTINATION ${TEEBINS_INSTALL_DIR}
            PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                        GROUP_READ GROUP_EXECUTE
                        WORLD_READ WORLD_EXECUTE
        )
    endif()
endfunction()

function(tee_add_library target)
    cmake_parse_arguments(
        TEELIB
        "STATIC;SHARED;OBJECT;NO_INSTALL;DO_INSTALL;NO_CFI;NO_XOM"
        "OUTPUT_NAME;LIBS_INSTALL_PATH;HEADERS_INSTALL_PATH;COMPILE_TOOL"
        "SOURCES;C_SOURCES;CPP_SOURCES;ASM_SOURCES;COMPILER_FLAGS;C_COMPILER_FLAGS;CPP_COMPILER_FLAGS;ASM_COMPILER_FLAGS;PRIVATE_INCLUDES;C_PRIVATE_INCLUDES;CPP_PRIVATE_INCLUDES;ASM_PRIVATE_INCLUDES;PUBLIC_INCLUDES;INTERNAL_INCLUDES;LIBRARIES;LIBRARY_PATHS;OBJECTS;WHOLEARCHIVE;LINKER_SCRIPT;RPATH;LINKER_FLAGS;C_LINKER_FLAGS;ASM_LINKER_FLAGS;COMPILER_DEFINITIONS;C_COMPILER_DEFINITIONS;CPP_COMPILER_DEFINITIONS;ASM_COMPILER_DEFINITIONS;LINKGROUP"
        ${ARGN}
    )

    if (NOT TEELIB_COMPILE_TOOL STREQUAL BUILD_TOOL)
        return()
    endif()

    set(TEELIB_CFI_FLAGS)
    set(TEELIB_XOM_FLAGS)
    if ("${TEELIB_COMPILE_TOOL}" STREQUAL "clang")
        if (NOT TEELIB_NO_CFI)
            if ("${CONFIG_LLVM_CFI}" STREQUAL "y")
                #list(APPEND TEELIB_CFI_FLAGS -fsanitize=cfi -fno-sanitize-cfi-cross-dso)
                if (NOT ${target} IN_LIST CFI_VISIBILITY_HIDDEN)
                    #list(APPEND TEELIB_CFI_FLAGS -fvisibility=default)
                endif()
                if (${target} IN_LIST CFI_NO_ICALL)
                    #list(APPEND TEELIB_CFI_FLAGS -fno-sanitize=cfi-icall)
                endif()
            endif()
        endif()

        if (NOT TEELIB_NO_XOM)
            if ("${CONFIG_ENABLE_XOM32}" STREQUAL "y" AND "${ARCH}" STREQUAL "arm")
                if (NOT "${BUILD_TA}" STREQUAL "y")
                    if (NOT "${TARGET_IS_TA}" STREQUAL "y")
                        if (NOT ${target} IN_LIST XOM32_BLACK_LIST)
                            list(APPEND TEELIB_XOM_FLAGS -mexecute-only -fno-jump-tables)
                        endif()
                    else()
                        if ("${TARGET_IS_EXT_LIB}" STREQUAL "y")
                            if (NOT ${target} IN_LIST XOM32_BLACK_LIST)
                                list(APPEND TEELIB_XOM_FLAGS -fno-jump-tables)
                            endif()
                        else()
                            if (NOT ${target} IN_LIST XOM32_BLACK_LIST)
                                list(APPEND TEELIB_XOM_FLAGS -mexecute-only -fno-jump-tables)
                            endif()
                        endif()
                    endif()
                endif()
            endif()
        endif()
    endif()

    if (TEELIB_STATIC)
        add_library(${target} STATIC ${TEELIB_SOURCES} ${TEELIB_C_SOURCES} ${TEELIB_CPP_SOURCES} ${TEELIB_ASM_SOURCES})
    elseif (TEELIB_SHARED)
        add_library(${target} SHARED ${TEELIB_SOURCES} ${TEELIB_C_SOURCES} ${TEELIB_CPP_SOURCES} ${TEELIB_ASM_SOURCES})
    elseif (TEELIB_OBJECT)
        add_library(${target} OBJECT ${TEELIB_SOURCES} ${TEELIB_C_SOURCES} ${TEELIB_CPP_SOURCES} ${TEELIB_ASM_SOURCES})
    endif()

    if (TEELIB_C_PRIVATE_INCLUDES)
        set(c_includes)
        foreach (i ${TEELIB_C_PRIVATE_INCLUDES})
            if (NOT c_includes)
                set(c_includes "-I${i}")
            else()
                set(c_includes "${c_includes} -I${i}")
            endif()
        endforeach()
        if ("${TOP_IS_TEEOS}" STREQUAL "true")
            set(c_includes "${c_includes} -I${HMSDKINCLUDE}")
        endif()
    endif()

    if (TEELIB_CPP_PRIVATE_INCLUDES)
        set(cpp_includes)
        foreach (i ${TEELIB_CPP_PRIVATE_INCLUDES})
            if (NOT cpp_includes)
                set(cpp_includes "-I${i}")
            else()
                set(cpp_includes "${cpp_includes} -I${i}")
            endif()
        endforeach()
        if ("${TOP_IS_TEEOS}" STREQUAL "true")
            set(cpp_includes "${cpp_includes} -I${HMSDKINCLUDE}")
        endif()
    endif()

    if (TEELIB_ASM_PRIVATE_INCLUDES)
        set(asm_includes)
        foreach (i ${TEELIB_ASM_PRIVATE_INCLUDES})
            if (NOT asm_includes)
                set(asm_includes "-I${i}")
            else()
                set(asm_includes "${asm_includes} -I${i}")
            endif()
        endforeach()
        if ("${TOP_IS_TEEOS}" STREQUAL "true")
            set(asm_includes "${asm_includes} -I${HMSDKINCLUDE}")
        endif()
    endif()

    if (TEELIB_C_COMPILER_FLAGS)
        set(c_flags)
        foreach (f ${TEELIB_C_COMPILER_FLAGS})
            if(NOT c_flags)
                set(c_flags "${f}")
            else()
                set(c_flags "${c_flags} ${f}")
            endif()
        endforeach()
    endif()

    foreach (f IN LISTS TEELIB_CFI_FLAGS)
        if(NOT c_flags)
            set(c_flags "${f}")
        else()
            set(c_flags "${c_flags} ${f}")
        endif()
    endforeach()

    foreach (f IN LISTS TEELIB_XOM_FLAGS)
        if(NOT c_flags)
            set(c_flags "${f}")
        else()
            set(c_flags "${c_flags} ${f}")
        endif()
    endforeach()

    if (TEELIB_CPP_COMPILER_FLAGS)
        set(cpp_flags)
        foreach (f ${TEELIB_CPP_COMPILER_FLAGS})
            if(NOT cpp_flags)
                set(cpp_flags "${f}")
            else()
                set(cpp_flags "${c_flags} ${f}")
            endif()
        endforeach()
    endif()

    foreach (f IN LISTS TEELIB_CFI_FLAGS)
        if(NOT cpp_flags)
            set(cpp_flags "${f}")
        else()
            set(cpp_flags "${cpp_flags} ${f}")
        endif()
    endforeach()

    foreach (f IN LISTS TEELIB_XOM_FLAGS)
        if(NOT cpp_flags)
            set(cpp_flags "${f}")
        else()
            set(cpp_flags "${cpp_flags} ${f}")
        endif()
    endforeach()

    if (TEELIB_C_COMPILER_DEFINITIONS)
        set(c_defs)
        foreach (d ${TEELIB_C_COMPILER_DEFINITIONS})
            if(NOT c_defs)
                set(c_defs "-D${d}")
            else()
                set(c_defs "${c_defs} -D${d}")
            endif()
        endforeach()
    endif()

    if (TEELIB_CPP_COMPILER_DEFINITIONS)
        set(cpp_defs)
        foreach (d ${TEELIB_CPP_COMPILER_DEFINITIONS})
            if(NOT cpp_defs)
                set(cpp_defs "-D${d}")
            else()
                set(cpp_defs "${c_defs} -D${d}")
            endif()
        endforeach()
    endif()

    if (TEELIB_ASM_COMPILER_FLAGS)
        set(asm_flags)
        foreach (f ${TEELIB_ASM_COMPILER_FLAGS})
            if(NOT asm_flags)
                set(asm_flags "${f}")
            else()
                set(asm_flags "${asm_flags} ${f}")
            endif()
        endforeach()
    endif()

    foreach (f IN LISTS TEELIB_CFI_FLAGS)
        if(NOT asm_flags)
            set(asm_flags "${f}")
        else()
            set(asm_flags "${asm_flags} ${f}")
        endif()
    endforeach()

    foreach (f IN LISTS TEELIB_XOM_FLAGS)
        if(NOT asm_flags)
            set(asm_flags "${f}")
        else()
            set(asm_flags "${asm_flags} ${f}")
        endif()
    endforeach()

    list(REMOVE_DUPLICATES c_includes)
    list(REMOVE_DUPLICATES c_flags)
    list(REMOVE_DUPLICATES c_defs)
    list(REMOVE_DUPLICATES cpp_includes)
    list(REMOVE_DUPLICATES cpp_flags)
    list(REMOVE_DUPLICATES cpp_defs)
    list(REMOVE_DUPLICATES asm_includes)
    list(REMOVE_DUPLICATES asm_flags)
    list(REMOVE_DUPLICATES TEELIB_CFI_FLAGS)
    list(REMOVE_DUPLICATES TEELIB_XOM_FLAGS)
    list(REMOVE_DUPLICATES TEELIB_COMPILER_FLAGS)
    list(REMOVE_DUPLICATES TEELIB_COMPILER_DEFINITIONS)
    list(REMOVE_DUPLICATES TEELIB_PRIVATE_INCLUDES)
    list(REMOVE_DUPLICATES TEELIB_LINKER_FLAGS)
    set_source_files_properties(${TEELIB_C_SOURCES} PROPERTIES COMPILE_FLAGS "${c_includes} ${c_flags} ${c_defs}")
    set_source_files_properties(${TEELIB_CPP_SOURCES} PROPERTIES COMPILE_FLAGS "${cpp_includes} ${cpp_flags} ${cpp_defs}")
    set_source_files_properties(${TEELIB_ASM_SOURCES} PROPERTIES COMPILE_FLAGS "${asm_includes} ${asm_flags}")

    list(REMOVE_ITEM asm_flags "-flto")
    list(REMOVE_ITEM asm_flags "-fsplit-lto-unit")

    tee_append_compiler_flags(${target} ${TEELIB_COMPILER_FLAGS})
    if ("${TEELIB_COMPILER_FLAGS}" MATCHES "flto" OR "${c_flags}" MATCHES "flto" )
    if("${ARCH}" STREQUAL "aarch64")
        tee_remove_build_path_64(${target})
    else()
        tee_remove_build_path_32(${target})
    endif()
    endif()
    foreach(f IN LISTS TEELIB_CFI_FLAGS)
        target_compile_options(${target} PRIVATE ${f})
    endforeach()
    foreach(f IN LISTS TEELIB_XOM_FLAGS)
        target_compile_options(${target} PRIVATE ${f})
    endforeach()
    #tee_append_definitions_auto(${target} "CONFIG")

    foreach (d ${TEELIB_COMPILER_DEFINITIONS})
        tee_append_definitions(${target} ${d})
    endforeach()

    tee_include_directories(${target} ${TEELIB_PRIVATE_INCLUDES})
    if (TEELIB_SOURCES)
        tee_default_include(${target})
    endif()

    if (TEELIB_INTERNAL_INCLUDES)
        tee_include_dirs(${target} INTERNAL DIRS ${TEELIB_INTERNAL_INCLUDES})
    endif()

    if (TEELIB_LIBRARY_PATHS)
        foreach (p ${TEELIB_LIBRARY_PATHS})
            tee_target_linker_flags(${target} -L${p})
        endforeach()
    endif()

    if (TEELIB_LINKER_SCRIPT)
        tee_set_lds(${target} ${TEELIB_LINKER_SCRIPT})
    endif()

    tee_library_default_link(${target}
        OBJECTS ${TEELIB_OBJECTS}
        WHOLEARCHIVE ${TEELIB_WHOLEARCHIVE}
        LINKGROUP ${TEELIB_LINKGROUP}
        LIBRARIES ${TEELIB_LIBRARIES}
    )

    if (TEELIB_LINKER_FLAGS)
        foreach (f ${TEELIB_LINKER_FLAGS})
            tee_target_linker_flags(${target} ${f})
        endforeach()
    endif()

    if (NOT TEELIB_LIBS_INSTALL_PATH)
        set(TEELIB_LIBS_INSTALL_PATH ${TEELIB_LIBS_INSTALL_PATH})
    endif()

    if (NOT TEE_HEADERS_INSTALL_PATH)
        set(TEE_HEADERS_INSTALL_PATH ${TEELIB_HEADERS_INSTALL_PATH})
    endif()

    if (TEELIB_SHARED)
        add_custom_command(TARGET ${target}
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${target}> $<TARGET_FILE_DIR:${target}>
        )
    endif()

    if (TEELIB_DO_INSTALL)
        install(TARGETS ${target}
            COMPONENT libs_install
            EXPORT export_${target}
            ARCHIVE DESTINATION ${TEELIB_LIBS_INSTALL_PATH}
            LIBRARY DESTINATION ${TEELIB_LIBS_INSTALL_PATH}
        )

        install(EXPORT export_${target}
            NAMESPACE ${CMAKE_PROJECT_NAME}_
            DESTINATION ${CMAKE_PROJECT_NAME}/cmake/${target}
            EXCLUDE_FROM_ALL)

        foreach (inc ${TEELIB_PUBLIC_INCLUDES})
            get_filename_component(abs_inc ${inc} ABSOLUTE)
            if (IS_DIRECTORY "${abs_inc}")
                install(DIRECTORY ${inc}
                    DESTINATION ${HEADERS_INSTALL_PATH}
                    COMPONENT headers_install
                    EXCLUDE_FROM_ALL
                )
            else()
                install(FILES ${inc}
                    DESTINATION ${HEADERS_INSTALL_PATH}
                    COMPONENT headers_install
                    EXCLUDE_FROM_ALL
                    PERMISSIONS OWNER_READ OWNER_WRITE
                                GROUP_READ
                                WORLD_READ
                )
            endif()
        endforeach()
    endif()
endfunction()

###########################
# preprocess source files #
###########################
function(preprocess_files target)
    cmake_parse_arguments(
        TEEPREPROCESS
        ""
        "OUTPUT_PATH;COMPILE_TOOL"
        "SOURCES;COMPILER_FLAGS;GENERAL_FLAGS;PRIVATE_INCLUDES;COMPILER_DEFINITIONS"
        ${ARGN}
    )

    if (NOT TEEPREPROCESS_COMPILE_TOOL STREQUAL BUILD_TOOL)
        return()
    endif()

    set(include_flags)
    set(include_definitions)
    foreach (v ${TEEPREPROCESS_PRIVATE_INCLUDES})
        list(APPEND include_flags -I${CMAKE_CURRENT_SOURCE_DIR}/${v})
    endforeach()
    foreach(d ${TEEPREPROCESS_COMPILER_DEFINITIONS})
        list(APPEND include_definitions -D${d})
    endforeach()

    if ("${TOP_IS_TEEOS}" STREQUAL "true")
        list(APPEND include_flags -I${HMSDKINCLUDE})
    endif()

    foreach (f ${TEEPREPROCESS_SOURCES})
        get_filename_component(file_dir_only ${f} DIRECTORY)
        get_filename_component(file_name_only ${f} NAME_WE)
        add_custom_command(
            PRE_BUILD
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${file_name_only}.s
            COMMAND ${CMAKE_C_COMPILER} ${include_definitions} ${include_flags} ${TEEPREPROCESS_COMPILER_FLAGS} ${TEEPREPROCESS_GENERAL_FLAGS} -E -P ${CMAKE_CURRENT_SOURCE_DIR}/${f} -o ${CMAKE_CURRENT_BINARY_DIR}/${file_name_only}.s
            DEPENDS ${f}
        )
    endforeach()
endfunction()

function(preprocess_lds target)
    cmake_parse_arguments(
        TEELDS
        ""
        "LDS_FILE;OUTPUT_PATH;COMPILE_TOOL"
        "COMPILER_DEFINITIONS;PRIVATE_INCLUDES;COMPILER_FLAGS"
        ${ARGN}
    )
    if (NOT TEELDS_COMPILE_TOOL STREQUAL BUILD_TOOL)
        return()
    endif()
    set(compiler_defs)
    set(include_flags)
    set(compiler_flags)
    foreach (v ${TEELDS_PRIVATE_INCLUDES})
        list(APPEND include_flags -I${v})
    endforeach()
    if ("${TOP_IS_TEEOS}" STREQUAL "true")
        list(APPEND include_flags -I${HMSDKINCLUDE})
    else()
        list(APPEND include_flags -I${PREBUILD_HEADER})
    endif()
    foreach (d ${TEELDS_COMPILER_DEFINITIONS})
        list(APPEND -D${d})
    endforeach()
    foreach (f ${TEETXT_COMPILER_FLAGS})
        list(APPEND compiler_flags ${f})
    endforeach()
    get_filename_component(file_name_only ${TEELDS_LDS_FILE} NAME_WE)
    get_filename_component(file_dir_only ${TEELDS_LDS_FILE} DIRECTORY)
    add_custom_target(${target})
    add_custom_command(
        TARGET ${target}
        COMMAND ${CMAKE_C_COMPILER} ${include_flags} ${compiler_defs} ${compiler_flags} -x assembler-with-cpp -E --no-line-commands ${TEELDS_LDS_FILE} -o ${CMAKE_CURRENT_BINARY_DIR}/${file_name_only}.lds
    )
endfunction()

function(preprocess_txt target)
    cmake_parse_arguments(
        TEETXT
        ""
        "TXT_FILE;OUTPUT_PATH;COMPILE_TOOL"
        "COMPILER_DEFINITIONS;PRIVATE_INCLUDES;COMPILER_FLAGS"
        ${ARGN}
    )
    if (NOT TEELDS_COMPILE_TOOL STREQUAL BUILD_TOOL)
        return()
    endif()
    set(compiler_defs)
    set(include_flags)
    set(compiler_flags)
    foreach (v ${TEETXT_PRIVATE_INCLUDES})
        list(APPEND include_flags -I${CMAKE_CURRENT_SOURCE_DIR}/${v})
    endforeach()
    foreach (d ${TEETXT_COMPILER_DEFINITIONS})
        list(APPEND compiler_defs -D${d})
    endforeach()
    foreach (f ${TEETXT_COMPILER_FLAGS})
        list(APPEND compiler_flags ${f})
    endforeach()
    get_filename_component(file_name_only ${TEETXT_TXT_FILE} NAME_WE)
    get_filename_component(file_dir_only ${TEETXT_TXT_FILE} DIRECTORY)
    add_custom_target(${target})
    add_custom_command(
        TARGET ${target}
        COMMAND ${CMAKE_C_COMPILER} ${include_flags} ${compiler_defs} ${compiler_flags} -x assembler-with-cpp -E --no-line-commands ${TEETXT_TXT_FILE} -o ${CMAKE_CURRENT_BINARY_DIR}/${file_name_only}.txt
    )
endfunction()
