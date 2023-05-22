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

#ifndef NAPI_CERT_CHAIN_VALIDATOR_H
#define NAPI_CERT_CHAIN_VALIDATOR_H

#include <string>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "cert_chain_validator.h"

namespace OHOS {
namespace CertFramework {
class NapiCertChainValidator {
public:
    explicit NapiCertChainValidator(HcfCertChainValidator *certChainValidator);
    ~NapiCertChainValidator();

    static void DefineCertChainValidatorJSClass(napi_env env, napi_value exports);
    static napi_value CreateCertChainValidator(napi_env env, napi_callback_info info);

    napi_value Validate(napi_env env, napi_callback_info info);

    HcfCertChainValidator *GetCertChainValidator()
    {
        return certChainValidator_;
    }

    static thread_local napi_ref classRef_;

private:
    HcfCertChainValidator *certChainValidator_ = nullptr;
};
} // namespace CertFramework
} // namespace OHOS

#endif // NAPI_CERT_CHAIN_VALIDATOR_H
