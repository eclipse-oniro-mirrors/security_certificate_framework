/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef NAPI_CERT_CMS_GENERATOR_H
#define NAPI_CERT_CMS_GENERATOR_H

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "cert_cms_generator.h"

namespace OHOS {
namespace CertFramework {
class NapiCertCmsGenerator {
public:
    explicit NapiCertCmsGenerator(HcfCmsGenerator *certCmsGenerator);
    ~NapiCertCmsGenerator();

    static void DefineCertCmsGeneratorJSClass(napi_env env, napi_value exports);
    static napi_value CreateCmsGenerator(napi_env env, napi_callback_info info);

    napi_value AddSigner(napi_env env, napi_callback_info info);
    napi_value AddCert(napi_env env, napi_callback_info info);
    napi_value DoFinal(napi_env env, napi_callback_info info);
    napi_value DoFinalSync(napi_env env, napi_callback_info info);
    napi_value SetRecipientEncryptionAlgorithm(napi_env env, napi_callback_info info);
    napi_value AddRecipientInfo(napi_env env, napi_callback_info info);
    napi_value GetEncryptedContentData(napi_env env, napi_callback_info info);

    HcfCmsGenerator *GetCertCmsGenerator()
    {
        return cmsGenerator_;
    }

    static thread_local napi_ref classRef_;

private:
    HcfCmsGenerator *cmsGenerator_ = nullptr;
};

class NapiCertCmsParser {
public:
    explicit NapiCertCmsParser(HcfCmsParser *cmsParser);
    ~NapiCertCmsParser();

    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void DefineCertCmsParserJsClass(napi_env env, napi_value exports);
    static napi_value CreateCertCmsParser(napi_env env, napi_callback_info info);
    napi_value SetRawData(napi_env env, napi_callback_info info);
    napi_value GetContentType(napi_env env, napi_callback_info info);
    napi_value VerifySignedData(napi_env env, napi_callback_info info);
    napi_value GetContentData(napi_env env, napi_callback_info info);
    napi_value GetCerts(napi_env env, napi_callback_info info);
    napi_value DecryptEnvelopedData(napi_env env, napi_callback_info info);

    HcfCmsParser *GetCertCmsParser()
    {
        return cmsParser_;
    }

    static thread_local napi_ref classRef_;

private:
    HcfCmsParser *cmsParser_ = nullptr;
};
} // namespace CertFramework
} // namespace OHOS

#endif // NAPI_CERT_CMS_GENERATOR_H
