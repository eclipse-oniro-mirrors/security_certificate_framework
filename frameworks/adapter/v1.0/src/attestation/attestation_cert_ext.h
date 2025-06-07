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

#ifndef ATTESTATION_CERT_EXT_H
#define ATTESTATION_CERT_EXT_H
#include <stdbool.h>

#include "openssl/x509.h"
#include "openssl/asn1t.h"
#include "cf_result.h"
#include "attestation_common.h"
#include "hm_attestation_cert_ext_type.h"

typedef struct AttestationRecord AttestationRecord;

typedef struct DeviceCertSecureLevel DeviceCertSecureLevel;

typedef struct AttestationRecord DeviceActivationCertExt;

#ifdef __cplusplus
extern "C" {
#endif

CfResult GetHmAttestationRecord(const X509 *cert, AttestationRecord **record);

CfResult GetDeviceCertSecureLevel(const X509 *cert, DeviceCertSecureLevel **devSecLevel);

CfResult GetDeviceActivationCertExt(const X509 *cert, DeviceActivationCertExt **record);

CfResult GetDeviceSecureLevel(DeviceCertSecureLevel *record, int *version, int *level);

void FreeHmAttestationRecord(AttestationRecord *record);

void FreeAttestationDevSecLevel(DeviceCertSecureLevel *record);

void FreeDeviveActiveCertExt(DeviceActivationCertExt *record);

CfResult GetAttestCertExt(AttestationRecord *record, HmAttestationCertExtType type, HmAttestationCertExt *ext);

#ifdef __cplusplus
}
#endif

#endif // ATTESTATION_CERT_EXT_H
