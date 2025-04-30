#!/usr/bin/env bash
# Copyright (c) 2025-2025 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

CURRENT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_PATH="$(cd "${CURRENT_DIR}/../../../../../../.." && pwd)"
BASE_PATH="${ROOT_PATH}/base/security/certificate_framework"
TEST_PATH="${BASE_PATH}/frameworks/js/ani/test"
OUT_PATH="${ROOT_PATH}/out/rk3568"
ABC_NAME="cert_framework_test.abc"

ES2PANDA="${OUT_PATH}/clang_x64/arkcompiler/ets_frontend/es2panda"
ARK_LINK="${OUT_PATH}/clang_x64/arkcompiler/runtime_core/ark_link"

cd "${OUT_PATH}/security/certificate_framework"
"${ES2PANDA}" --arktsconfig "${TEST_PATH}/arktsconfig.json" --ets-module
"${ARK_LINK}" --output="${ABC_NAME}" -- "${TEST_PATH}/dist/"*
rm -rf "${TEST_PATH}/dist"

echo -e "output abc file: \033[1;32m${OUT_PATH}/security/certificate_framework/${ABC_NAME}\033[0m"
