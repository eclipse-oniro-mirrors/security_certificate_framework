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

namespace ANI::CertFramework {
class CmsGeneratorImpl {
public:
    CmsGeneratorImpl();
    ~CmsGeneratorImpl();

    void AddSigner(weak::X509Cert cert, PrivateKeyInfo const& keyInfo, CmsSignerConfig const& config);
    void AddCert(weak::X509Cert cert);
    OptStrUint8Arr DoFinalSync(array_view<uint8_t> data, optional_view<CmsGeneratorOptions> options);
};
} // namespace ANI::CertFramework

#endif // ANI_CERT_CMS_GENERATOR_H
