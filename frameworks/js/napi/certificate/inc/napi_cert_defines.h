/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef NAPI_CERT_DEFINES_H
#define NAPI_CERT_DEFINES_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace CertFramework {
constexpr size_t ARGS_SIZE_ONE = 1;
constexpr size_t ARGS_SIZE_TWO = 2;
constexpr size_t ARGS_SIZE_THREE = 3;
constexpr size_t ARGS_SIZE_FOUR = 4;
constexpr int32_t PARAM0 = 0;
constexpr int32_t PARAM1 = 1;
constexpr int32_t PARAM2 = 2;
constexpr uint32_t MAX_SN_BYTE_CNT = 100;
constexpr uint32_t QUAD_WORD_ALIGN_UP = 3;

const std::string CERT_TAG_DATA = "data";
const std::string CERT_TAG_ERR_CODE = "code";
const std::string CERT_TAG_COUNT = "count";
const std::string CERT_TAG_ENCODING_FORMAT = "encodingFormat";
const std::string CERT_TAG_ALGORITHM = "algorithm";
const std::string CRYPTO_TAG_ALG_NAME = "algName";
const std::string CRYPTO_TAG_FORMAT = "format";

enum ResultCode {
    JS_SUCCESS = 0,
    JS_ERR_CERT_INVALID_PARAMS = 401,
    JS_ERR_CERT_NOT_SUPPORT = 801,
    JS_ERR_CERT_OUT_OF_MEMORY = 19020001,
    JS_ERR_CERT_RUNTIME_ERROR = 19020002,
    JS_ERR_CERT_CRYPTO_OPERATION = 19030001,
    JS_ERR_CERT_SIGNATURE_FAILURE = 19030002,
    JS_ERR_CERT_NOT_YET_VALID = 19030003,
    JS_ERR_CERT_HAS_EXPIRED = 19030004,
    JS_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 19030005,
    JS_ERR_KEYUSAGE_NO_CERTSIGN = 19030006,
    JS_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE = 19030007
};

enum CertAsyncType {
    CERT_ASYNC_TYPE_CALLBACK = 1,
    CERT_ASYNC_TYPE_PROMISE = 2
};
} // namespace CertFramework
} // namespace OHOS

#endif // NAPI_CERT_DEFINES_H
