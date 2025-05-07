/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ani_common.h"
#include <unordered_map>

namespace {
enum ResultCode {
    SUCCESS = 0,
    INVALID_PARAMS = 401,
    NOT_SUPPORT = 801,
    ERR_OUT_OF_MEMORY = 19020001,
    ERR_RUNTIME_ERROR = 19020002,
    ERR_CRYPTO_OPERATION = 19030001,
    ERR_CERT_SIGNATURE_FAILURE = 19030002,
    ERR_CERT_NOT_YET_VALID = 19030003,
    ERR_CERT_HAS_EXPIRED = 19030004,
    ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 19030005,
    ERR_KEYUSAGE_NO_CERTSIGN = 19030006,
    ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE = 19030007,
    ERR_MAYBE_WRONG_PASSWORD = 19030008,
};
} // namespace

namespace ANI::CertFramework {
int ConvertResultCode(CfResult res)
{
    static std::unordered_map<CfResult, int> resCodeMap = {
        { CF_SUCCESS, SUCCESS },
        { CF_INVALID_PARAMS, INVALID_PARAMS },
        { CF_NOT_SUPPORT, NOT_SUPPORT },
        { CF_ERR_MALLOC, ERR_OUT_OF_MEMORY },
        { CF_ERR_CRYPTO_OPERATION, ERR_CRYPTO_OPERATION },
        { CF_ERR_CERT_SIGNATURE_FAILURE, ERR_CERT_SIGNATURE_FAILURE },
        { CF_ERR_CERT_NOT_YET_VALID, ERR_CERT_NOT_YET_VALID },
        { CF_ERR_CERT_HAS_EXPIRED, ERR_CERT_HAS_EXPIRED },
        { CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY },
        { CF_ERR_KEYUSAGE_NO_CERTSIGN, ERR_KEYUSAGE_NO_CERTSIGN },
        { CF_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE, ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE },
        { CF_ERR_CERT_INVALID_PRIVATE_KEY, ERR_MAYBE_WRONG_PASSWORD },
    };
    if (resCodeMap.count(res) > 0) {
        return resCodeMap[res];
    }
    return ERR_RUNTIME_ERROR;
}
} // namespace ANI::CertFramework
