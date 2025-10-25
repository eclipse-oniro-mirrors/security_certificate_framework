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

#ifndef ANI_CERT_CMS_GENERATOR_H
#define ANI_CERT_CMS_GENERATOR_H

#include "ani_common.h"
#include "cert_cms_generator.h"

namespace ANI::CertFramework {
class CmsGeneratorImpl {
public:
    CmsGeneratorImpl();
    explicit CmsGeneratorImpl(HcfCmsGenerator *cmsGenerator);
    ~CmsGeneratorImpl();

    void AddSigner(weak::X509Cert cert, ThPrivateKeyInfo const& keyInfo, CmsSignerConfig const& config);
    void AddCert(weak::X509Cert cert);
    void SetRecipientEncryptionAlgorithm(CmsRecipientEncryptionAlgorithm algorithm);
    void AddRecipientInfoSync(ThCmsRecipientInfo const& recipientInfo);
    OptStrUint8Arr DoFinalSync(array_view<uint8_t> data, optional_view<CmsGeneratorOptions> options);
    array<uint8_t> GetEncryptedContentDataSync();

private:
    HcfCmsGenerator *cmsGenerator_ = nullptr;
};

class CmsParserImpl {
public:
    CmsParserImpl();
    explicit CmsParserImpl(HcfCmsParser *cmsParser);
    ~CmsParserImpl();

    void SetRawDataSync(OptStrUint8Arr const& data, CmsFormat cmsFormat);
    CmsContentType GetContentType();
    void VerifySignedDataSync(CmsVerificationConfig const& config);
    array<uint8_t> GetContentDataSync();
    array<X509Cert> GetCertsSync(CmsCertType type);
    array<uint8_t> DecryptEnvelopedDataSync(CmsEnvelopedDecryptionConfig const& config);

private:
    HcfCmsParser *cmsParser_ = nullptr;
};
} // namespace ANI::CertFramework

#endif // ANI_CERT_CMS_GENERATOR_H
