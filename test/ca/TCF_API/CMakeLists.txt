#
# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
#

MESSAGE( STATUS "__ANDROID_API__ = ${__ANDROID_API__}.")

set(ca_sources)
list(APPEND ca_sources
    common/common_test.cpp
    get_prop_as_string_test.cpp
    get_prop_as_bool_test.cpp
    get_prop_as_u32_test.cpp
    get_prop_as_u64_test.cpp
    get_prop_as_binaryblock_test.cpp
    get_prop_as_uuid_test.cpp
    get_prop_as_identity_test.cpp
    get_prop_with_enumerator_test.cpp
    tee_malloc_test.cpp
    tee_realloc_test.cpp
    tee_memmove_test.cpp
    tee_memfill_test.cpp
    tee_free_test.cpp
    tee_memcompare_test.cpp
    tee_checkmemaccessrights_test.cpp
    tee_instance_test.cpp
    internal_client_api_test.cpp
    tee_panic_test.cpp
)


ca_compile_pub(
    TEST_NAME
    tcf_api_ca

    SRC_LIST
    ${ca_sources}

    INCLUDE_DIRS
    common

    COMPILE_OPTS
    COMPILE_DEFS
)

