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

#ifndef HM_ATTESTATION_CERT_EXT_TYPE_H
#define HM_ATTESTATION_CERT_EXT_TYPE_H

#include <stdbool.h>
#include <stdint.h>
#include "cf_blob.h"

typedef enum {
    SECURITY_LEVEL_SOFTWARE = 0,
    SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1,
    SECURITY_LEVEL_STRONGBOX = 2
} LegacySecurityLevel;

typedef enum {
    // standard
    DEVICE_ACTIVATION_DEVICE_ID1 = 0, // CfBlob
    DEVICE_ACTIVATION_DEVICE_ID2 = 1, // CfBlob
    ATTESTATION_KEY_PURPOSE = 2, // CfBlob
    ATTESTATION_APP_ID_HAP_ID, // CfBlob
    ATTESTATION_APP_ID_SA_ID, // CfBlob
    ATTESTATION_APP_ID_UNIFIED_ID, // CfBlob
    ATTESTATION_CHALLENGE, // CfBlob
    ATTESTATION_KEY_FLAG, // CfBlob
    ATTESTATION_DIGEST, // CfBlob
    ATTESTATION_SIGN_PADDING, // CfBlob
    ATTESTATION_ENC_PADDING, // CfBlob
    ATTESTATION_SIGN_TYPE, // CfBlob
    ATTESTATION_VERSION_INFO, // CfBlob
    ATTESTATION_KEY_MANAGER_TA_ID, // CfBlob
    ATTESTATION_PURPOSE, // int64_t
    ATTESTATION_ID_PADDING_FLAG, // bool
    ATTESTATION_NONCE, // CfBlob
    ATTESTATION_IMEI, // CfBlob
    ATTESTATION_MEID, // CfBlob
    ATTESTATION_SERIAL, // CfBlob
    ATTESTATION_MODEL, // CfBlob
    ATTESTATION_SOCID, // CfBlob
    ATTESTATION_UDID, // CfBlob
    ATTESTATION_VERSION, // int64_t
    ATTESTATION_CERT_EXT_TYPE_MAX,

    // legacy
    LEGACY_VERSION = 1000, // int64_t
    LEGACY_SECURITY_LEVEL = 1001, // int64_t, enum LegacySecurityLevel
    LEGACY_KM_VERSION = 1002, // int64_t
    LEGACY_KM_SECURITY_LEVEL = 1003, // int64_t, enum LegacySecurityLevel
    LEGACY_CHALLENGE = 1004, // CfBlob
    LEGACY_UNIQUE_ID = 1005, // CfBlob
    KM_TAG_PURPOSE, // CfInt64Array, set of int64_t
    KM_TAG_ALGORITHM, // int64_t
    KM_TAG_KEY_SIZE, // int64_t
    KM_TAG_KEY_DIGEST, // CfInt64Array, set of int64_t
    KM_TAG_KEY_PADDING, // CfInt64Array, set of int64_t
    KM_TAG_EC_CURVE, // int64_t
    KM_TAG_RSA_PUBLIC_EXPONENT, // int64_t
    KM_TAG_NO_AUTH_REQUIRED, // NULL
    KM_TAG_USER_AUTH_TYPE, // int64_t
    KM_TAG_CREATION_DATETIME, // int64_t
    KM_TAG_ORIGIN, // int64_t
    KM_TAG_OS_VERSION, // int64_t
    KM_TAG_OS_PATCH_LEVEL, // int64_t
    KM_TAG_ATTESTATION_ID_BRAND, // CfBlob
    KM_TAG_ATTESTATION_ID_DEVICE, // CfBlob
    KM_TAG_ATTESTATION_ID_PRODUCT, // CfBlob
    KM_TAG_ATTESTATION_ID_SERIAL, // CfBlob
    KM_TAG_ATTESTATION_ID_IMEI, // CfBlob
    KM_TAG_ATTESTATION_ID_MEID, // CfBlob
    KM_TAG_ATTESTATION_ID_MANUFACTURER, // CfBlob
    KM_TAG_ATTESTATION_ID_MODEL, // CfBlob
    KM_TAG_ATTESTATION_ID_SOCID, // CfBlob
    KM_TAG_ATTESTATION_ID_UDID, // CfBlob
    KM_TAG_TYPE_MAX,
} HmAttestationCertExtType;

typedef struct {
    union {
        bool boolValue;
        int64_t int64Value;
        CfBlob blob;
        CfInt64Array int64Array;
    };
} HmAttestationCertExt;

typedef struct {
    char *cn;
    char *ou;
    char *o;
    char *c;
} CertSnInfo;

typedef struct {
    uint32_t num;
    CertSnInfo *certSnInfos;
} HmAttestationSnInfo;

#endif