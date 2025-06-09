/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ATTESTATION_CERT_VERIFY_H
#define ATTESTATION_CERT_VERIFY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "cf_result.h"
#include "cf_blob.h"
#include "hm_attestation_cert_ext_type.h"

typedef struct HmAttestationInfo HmAttestationInfo;

typedef struct HcfAttestCertVerifyParam HcfAttestCertVerifyParam;

#ifdef __cplusplus
extern "C" {
#endif

CfResult AttestCreateVerifyParam(HcfAttestCertVerifyParam **param);

CfResult AttestSetVerifyParamCheckTime(HcfAttestCertVerifyParam *param, bool checkTime);

CfResult AttestSetVerifyParamRootCa(HcfAttestCertVerifyParam *param, const CfEncodingBlob *rootCa);

CfResult AttestSetVerifyParamSnInfos(HcfAttestCertVerifyParam *param, const HmAttestationSnInfo *snInfos);

void AttestFreeVerifyParam(HcfAttestCertVerifyParam *param);

CfResult AttestCertVerify(const CfEncodingBlob *encodingBlob, const HcfAttestCertVerifyParam *param,
    HmAttestationInfo **info);

CfResult AttestCertParseExtension(HmAttestationInfo *info);

CfResult AttestCheckBoundedWithUdId(HmAttestationInfo *info);

CfResult AttestCheckBoundedWithSocid(HmAttestationInfo *info);

CfResult AttestGetCertExtension(HmAttestationInfo *info, HmAttestationCertExtType type, HmAttestationCertExt *ext);

void AttestInfoFree(HmAttestationInfo *info);

#ifdef __cplusplus
}
#endif

#endif // ATTESTATION_CERT_VERIFY_H
