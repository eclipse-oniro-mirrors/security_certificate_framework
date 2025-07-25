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

#ifndef ANI_PARAMETERS_H
#define ANI_PARAMETERS_H

#include "ani_common.h"
#include "x509_cert_match_parameters.h"
#include "x509_cert_chain_validate_params.h"

namespace ANI::CertFramework {
bool BuildX509CertMatchParams(X509CertMatchParameters const& param, HcfX509CertMatchParams &hcfParam);
void FreeX509CertMatchParams(HcfX509CertMatchParams &hcfParam);

bool BuildX509CertChainValidateParams(CertChainValidationParameters const& param,
    HcfX509CertChainValidateParams &hcfParam);
void FreeX509CertChainValidateParams(HcfX509CertChainValidateParams &hcfParam);
void FreeTrustAnchorArray(HcfX509TrustAnchorArray *&trustAnchors);
} // namespace ANI::CertFramework

#endif // ANI_PARAMETERS_H
