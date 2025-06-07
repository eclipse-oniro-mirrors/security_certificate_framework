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

#ifndef HM_ATTESTATION_CERT_VERIFY_H
#define HM_ATTESTATION_CERT_VERIFY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "cf_result.h"
#include "hm_attestation_cert_ext_type.h"

typedef struct HmAttestationInfo HmAttestationInfo;

typedef struct HcfAttestCertVerifyParam HcfAttestCertVerifyParam;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Create the certificate verify param.
 *
 * @param [out] param The certificate verify param.
 * @return The result code.
 */
CfResult HcfAttestCreateVerifyParam(HcfAttestCertVerifyParam **param);

/*
 * Set the certificate verify param.
 *
 * @param [in] param The certificate verify param.
 * @param [in] checkTime Whether to check the certificate validity.
 * @return The result code.
 */
CfResult HcfAttestSetVerifyParamCheckTime(HcfAttestCertVerifyParam *param, bool checkTime);

/*
 * Set the root ca certificate.
 *
 * @param [in] param The certificate verify param.
 * @param [in] rootCa The trusted CA certificate.
 * @return The result code.
 */
CfResult HcfAttestSetVerifyParamRootCa(HcfAttestCertVerifyParam *param, const CfEncodingBlob *rootCa);

/*
 * Set the trusted SN infos to check sub ca.
 *
 * @param [in] param The certificate verify param.
 * @param [in] snInfo The trusted SN infos.
 * @return The result code.
 */
CfResult HcfAttestSetVerifyParamSnInfos(HcfAttestCertVerifyParam *param, const HmAttestationSnInfo *snInfos);

/*
 * Free the certificate verify param.
 *
 * @param [in] param The certificate verify param.
 */
void HcfAttestFreeVerifyParam(HcfAttestCertVerifyParam *param);

/*
 * Verify the certificate and return the attestation info.
 *
 * @param [in] encodingBlob The certificate encoding blob. Currently only PEM is supported
 * @param [in] param The certificate verify param, can be NULL. If NULL, the default param will be used.
 * (1) Use system time to check certificate validity.
 * (2) Verify the certificate using the built-in CA certificate.
 * @param [out] info The attestation info.
 * @return The result code.
 */
CfResult HcfAttestCertVerify(const CfEncodingBlob *encodingBlob, const HcfAttestCertVerifyParam *param,
    HmAttestationInfo **info);

/*
 * Parse the certificate extension.
 *
 * @param [in] info The attestation info.
 * @return The result code.
 */
CfResult HcfAttestCertParseExtension(HmAttestationInfo *info);

/*
 * Check the certificate is bounded with the UDID.
 *
 * @param [in] info The attestation info.
 * @return The result code.
 */
CfResult HcfAttestCheckBoundedWithUdId(HmAttestationInfo *info);

/*
 * Check the certificate is bounded with the SOCID.
 *
 * @param [in] info The attestation info.
 * @return The result code.
 */
CfResult HcfAttestCheckBoundedWithSocid(HmAttestationInfo *info);

/*
 * Get the certificate extension.
 *
 * @param [in] info The attestation info.
 * @param [in] type The certificate extension type.
 * @param [out] ext The certificate extension.
 * @return The result code. If the extension is not found, the result code is CF_ERR_EXTENSION_NOT_EXIST.
 */
CfResult HcfAttestGetCertExtension(HmAttestationInfo *info, HmAttestationCertExtType type, HmAttestationCertExt *ext);

/*
 * Free the attestation info.
 *
 * @param [in] info The attestation info.
 */
void HcfAttestInfoFree(HmAttestationInfo *info);

#ifdef __cplusplus
}
#endif

#endif // HM_ATTESTATION_CERT_VERIFY_H