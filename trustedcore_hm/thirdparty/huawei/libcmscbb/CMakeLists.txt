include(apps_ext_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/cmscbb/include
)
tee_add_library(cmscbb STATIC
    SOURCES
    cmscbb/src/cms_verify.c
    cmscbb/src/cmscbb_buf.c
    cmscbb/src/cmscbb_pki.c
    cmscbb/src/cmscbb_list.c
    cmscbb/src/cmscbb_x509.c
    cmscbb/src/cmscbb_base64.c
    cmscbb/src/cmscbb_asn1_def.c
    cmscbb/src/cmscbb_cms_parse.c
    cmscbb/src/cmscbb_cms_templ.c
    cmscbb/src/cmscbb_plt_proxy.c
    cmscbb/src/cmscbb_asn1_templ.c
    cmscbb/src/cmscbb_asn1_utils.c
    cmscbb/src/cmscbb_x509_templ.c
    cmscbb/src/cmscbb_asn1_decode.c

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
