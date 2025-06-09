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

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "cf_blob.h"
#include "cf_result.h"
#include "hm_attestation_cert_ext_type.h"
#include "hm_attestation_cert_verify.h"
#include "attestation_cert_verify.h"

CfResult HcfAttestCreateVerifyParam(HcfAttestCertVerifyParam **param)
{
    return AttestCreateVerifyParam(param);
}

CfResult HcfAttestSetVerifyParamCheckTime(HcfAttestCertVerifyParam *param, bool checkTime)
{
    return AttestSetVerifyParamCheckTime(param, checkTime);
}

CfResult HcfAttestSetVerifyParamRootCa(HcfAttestCertVerifyParam *param, const CfEncodingBlob *rootCa)
{
    return AttestSetVerifyParamRootCa(param, rootCa);
}

CfResult HcfAttestSetVerifyParamSnInfos(HcfAttestCertVerifyParam *param, const HmAttestationSnInfo *snInfo)
{
    return AttestSetVerifyParamSnInfos(param, snInfo);
}

void HcfAttestFreeVerifyParam(HcfAttestCertVerifyParam *param)
{
    AttestFreeVerifyParam(param);
}

CfResult HcfAttestCertVerify(const CfEncodingBlob *encodingBlob, const HcfAttestCertVerifyParam *param,
    HmAttestationInfo **info)
{
    return AttestCertVerify(encodingBlob, param, info);
}

CfResult HcfAttestCertParseExtension(HmAttestationInfo *info)
{
    return AttestCertParseExtension(info);
}

CfResult HcfAttestCheckBoundedWithUdId(HmAttestationInfo *info)
{
    return AttestCheckBoundedWithUdId(info);
}

CfResult HcfAttestCheckBoundedWithSocid(HmAttestationInfo *info)
{
    return AttestCheckBoundedWithSocid(info);
}

CfResult HcfAttestGetCertExtension(HmAttestationInfo *info, HmAttestationCertExtType type, HmAttestationCertExt *ext)
{
    return AttestGetCertExtension(info, type, ext);
}

void HcfAttestInfoFree(HmAttestationInfo *info)
{
    AttestInfoFree(info);
}
