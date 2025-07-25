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

#ifndef ANI_CERT_CHAIN_BUILD_RESULT_H
#define ANI_CERT_CHAIN_BUILD_RESULT_H

#include "ani_common.h"
#include "x509_cert_chain.h"

namespace ANI::CertFramework {
class CertChainBuildResultImpl {
public:
    CertChainBuildResultImpl();
    explicit CertChainBuildResultImpl(HcfX509CertChainBuildResult *buildResult);
    ~CertChainBuildResultImpl();

    X509CertChain GetCertChain();
    CertChainValidationResult GetValidationResult();

private:
    HcfX509CertChainBuildResult *buildResult_ = nullptr;
};
} // namespace ANI::CertFramework

#endif // ANI_CERT_CHAIN_BUILD_RESULT_H
