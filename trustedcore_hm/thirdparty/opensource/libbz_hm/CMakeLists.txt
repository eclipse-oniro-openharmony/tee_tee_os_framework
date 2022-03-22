add_custom_target(libbz_hm_headers
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/src/bzlib.h ${HDR_L_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/src/bzlib_private.h ${HDR_L_DIR}
)
include(apps_ext_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_FLAGS
    -Wall
    -Wextra
    -Wno-unused-parameter
    -Wno-implicit-fallthrough
    -Wno-sign-compare
    -fno-builtin-fwrite
    -fno-builtin-malloc
    -fno-builtin-calloc
)

tee_add_library(bz_hm STATIC
    SOURCES
    src/bzlib.c
    src/huffman.c
    src/compress.c
    src/crctable.c
    src/blocksort.c
    src/randtable.c
    src/decompress.c

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
