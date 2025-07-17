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

#include <stdio.h>
#include <string.h>
#include "openssl/x509.h"
#include "openssl/asn1t.h"
#include "openssl/types.h"
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "cf_log.h"
#include "cf_memory.h"
#include "cf_result.h"
#include "attestation_common.h"
#include "attestation_cert_ext_legacy.h"

static const uint8_t KEY_DESCRIPTION_OID[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x11};

typedef enum {
    VERIFIED_BOOT_STATE_VERIFIED = 0,
    VERIFIED_BOOT_STATE_SELF_SIGNED = 1,
    VERIFIED_BOOT_STATE_UNVERIFIED = 2,
    VERIFIED_BOOT_STATE_FAILED = 3
} VerifiedBootState;

typedef struct {
    ASN1_OCTET_STRING *verifiedBootKey;
    ASN1_BOOLEAN *deviceLocked;
    ASN1_ENUMERATED *verifiedBootState;
    ASN1_OCTET_STRING *verifiedBootHash;
} RootOfTrust;

typedef struct {
    STACK_OF(ASN1_INTEGER) *purpose;
    ASN1_INTEGER *algorithm;
    ASN1_INTEGER *keySize;
    STACK_OF(ASN1_INTEGER) *digest;
    STACK_OF(ASN1_INTEGER) *padding;
    ASN1_INTEGER *ecCurve;
    ASN1_INTEGER *rsaPublicExponent;
    STACK_OF(ASN1_INTEGER) *mgfDigest;

    ASN1_NULL *rollbackResistance;
    ASN1_NULL *earlyBootOnly;
    ASN1_NULL *noAuthRequired;
    ASN1_NULL *allowWhileOnBody;
    ASN1_NULL *trustedUserPresenceRequired;
    ASN1_NULL *trustedConfirmationRequired;
    ASN1_NULL *unlockedDeviceRequired;
    ASN1_NULL *deviceUniqueAttestation;

    ASN1_INTEGER *activeDateTime;
    ASN1_INTEGER *originationExpireDateTime;
    ASN1_INTEGER *usageExpireDateTime;
    ASN1_INTEGER *usageCountLimit;
    ASN1_INTEGER *userAuthType;
    ASN1_INTEGER *authTimeout;
    ASN1_INTEGER *creationDateTime;
    ASN1_INTEGER *origin;
    ASN1_INTEGER *osVersion;
    ASN1_INTEGER *osPatchLevel;
    ASN1_INTEGER *bootPatchLevel;

    RootOfTrust *rootOfTrust;

    ASN1_OCTET_STRING *attestationApplicationId;
    ASN1_TYPE *attestationIdBrand; // compatible OCTET_STRING and UTF8STRING
    ASN1_TYPE *attestationIdDevice;
    ASN1_TYPE *attestationIdProduct;
    ASN1_TYPE *attestationIdSerial;
    ASN1_TYPE *attestationIdImei;
    ASN1_TYPE *attestationIdMeid;
    ASN1_TYPE *attestationIdManufacturer;
    ASN1_TYPE *attestationIdModel;
    ASN1_TYPE *attestationIdSecondImei;
    ASN1_TYPE *moduleHash;
    ASN1_TYPE *attestationIdSocid;
    ASN1_TYPE *attestationIdUdid;
} AuthorizationList;

typedef struct {
    ASN1_INTEGER *attestationVersion;
    ASN1_ENUMERATED *attestationSecurityLevel;
    ASN1_INTEGER *keyMintVersion;
    ASN1_ENUMERATED *keyMintSecurityLevel;
    ASN1_OCTET_STRING *attestationChallenge;
    ASN1_OCTET_STRING *uniqueId;
    AuthorizationList *softwareEnforced;
    AuthorizationList *hardwareEnforced;
} KeyDescription;

DECLARE_ASN1_FUNCTIONS(RootOfTrust)
DECLARE_ASN1_FUNCTIONS(AuthorizationList)
DECLARE_ASN1_FUNCTIONS(KeyDescription)

IMPLEMENT_ASN1_FUNCTIONS(RootOfTrust)
IMPLEMENT_ASN1_FUNCTIONS(AuthorizationList)
IMPLEMENT_ASN1_FUNCTIONS(KeyDescription)

ASN1_SEQUENCE(RootOfTrust) = {
    ASN1_SIMPLE(RootOfTrust, verifiedBootKey, ASN1_OCTET_STRING),
    ASN1_SIMPLE(RootOfTrust, deviceLocked, ASN1_BOOLEAN),
    ASN1_SIMPLE(RootOfTrust, verifiedBootState, ASN1_ENUMERATED),
    ASN1_SIMPLE(RootOfTrust, verifiedBootHash, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(RootOfTrust)

#define TAG_PURPOSE 1
#define TAG_ALGORITHM 2
#define TAG_KEY_SIZE 3
#define TAG_DIGEST 5
#define TAG_PADDING 6
#define TAG_EC_CURVE 10
#define TAG_RSA_PUBLIC_EXPONENT 200
#define TAG_MGF_DIGEST 203
#define TAG_ROLLBACK_RESISTANCE 303
#define TAG_EARLY_BOOT_ONLY 305
#define TAG_ACTIVE_DATETIME 400
#define TAG_ORIGINATION_EXPIRE_DATETIME 401
#define TAG_USAGE_EXPIRE_DATETIME 402
#define TAG_USAGE_COUNT_LIMIT 405
#define TAG_NO_AUTH_REQUIRED 503
#define TAG_USER_AUTH_TYPE 504
#define TAG_AUTH_TIMEOUT 505
#define TAG_ALLOW_WHILE_ON_BODY 506
#define TAG_TRUSTED_USER_PRESENCE_REQUIRED 507
#define TAG_TRUSTED_CONFIRMATION_REQUIRED 508
#define TAG_UNLOCKED_DEVICE_REQUIRED 509
#define TAG_CREATION_DATETIME 701
#define TAG_ORIGIN 702
#define TAG_ROOT_OF_TRUST 704
#define TAG_OS_VERSION 705
#define TAG_OS_PATCH_LEVEL 706
#define TAG_ATTESTATION_APPLICATION_ID 709
#define TAG_ATTESTATION_ID_BRAND 710
#define TAG_ATTESTATION_ID_DEVICE 711
#define TAG_ATTESTATION_ID_PRODUCT 712
#define TAG_ATTESTATION_ID_SERIAL 713
#define TAG_ATTESTATION_ID_IMEI 714
#define TAG_ATTESTATION_ID_MEID 715
#define TAG_ATTESTATION_ID_MANUFACTURER 716
#define TAG_ATTESTATION_ID_MODEL 717
#define TAG_ATTESTATION_ID_SOCID 718 // self defined
#define TAG_BOOT_PATCH_LEVEL 719
#define TAG_DEVICE_UNIQUE_ATTESTATION 720
#define TAG_ATTESTATION_ID_SECOND_IMEI 723
#define TAG_MODULE_HASH 724
#define TAG_ATTESTATION_ID_UDID 10006

ASN1_SEQUENCE(AuthorizationList) = {
    ASN1_EXP_SET_OF_OPT(AuthorizationList, purpose, ASN1_INTEGER, TAG_PURPOSE),
    ASN1_EXP_OPT(AuthorizationList, algorithm, ASN1_INTEGER, TAG_ALGORITHM),
    ASN1_EXP_OPT(AuthorizationList, keySize, ASN1_INTEGER, TAG_KEY_SIZE),
    ASN1_EXP_SET_OF_OPT(AuthorizationList, digest, ASN1_INTEGER, TAG_DIGEST),
    ASN1_EXP_SET_OF_OPT(AuthorizationList, padding, ASN1_INTEGER, TAG_PADDING),
    ASN1_EXP_OPT(AuthorizationList, ecCurve, ASN1_INTEGER, TAG_EC_CURVE),
    ASN1_EXP_OPT(AuthorizationList, rsaPublicExponent, ASN1_INTEGER, TAG_RSA_PUBLIC_EXPONENT),
    ASN1_EXP_SET_OF_OPT(AuthorizationList, mgfDigest, ASN1_INTEGER, TAG_MGF_DIGEST),
    ASN1_EXP_OPT(AuthorizationList, rollbackResistance, ASN1_NULL, TAG_ROLLBACK_RESISTANCE),
    ASN1_EXP_OPT(AuthorizationList, earlyBootOnly, ASN1_NULL, TAG_EARLY_BOOT_ONLY),
    ASN1_EXP_OPT(AuthorizationList, activeDateTime, ASN1_INTEGER, TAG_ACTIVE_DATETIME),
    ASN1_EXP_OPT(AuthorizationList, originationExpireDateTime, ASN1_INTEGER, TAG_ORIGINATION_EXPIRE_DATETIME),
    ASN1_EXP_OPT(AuthorizationList, usageExpireDateTime, ASN1_INTEGER, TAG_USAGE_EXPIRE_DATETIME),
    ASN1_EXP_OPT(AuthorizationList, usageCountLimit, ASN1_INTEGER, TAG_USAGE_COUNT_LIMIT),
    ASN1_EXP_OPT(AuthorizationList, noAuthRequired, ASN1_NULL, TAG_NO_AUTH_REQUIRED),
    ASN1_EXP_OPT(AuthorizationList, userAuthType, ASN1_INTEGER, TAG_USER_AUTH_TYPE),
    ASN1_EXP_OPT(AuthorizationList, authTimeout, ASN1_INTEGER, TAG_AUTH_TIMEOUT),
    ASN1_EXP_OPT(AuthorizationList, allowWhileOnBody, ASN1_NULL, TAG_ALLOW_WHILE_ON_BODY),
    ASN1_EXP_OPT(AuthorizationList, trustedUserPresenceRequired, ASN1_NULL, TAG_TRUSTED_USER_PRESENCE_REQUIRED),
    ASN1_EXP_OPT(AuthorizationList, trustedConfirmationRequired, ASN1_NULL, TAG_TRUSTED_CONFIRMATION_REQUIRED),
    ASN1_EXP_OPT(AuthorizationList, unlockedDeviceRequired, ASN1_NULL, TAG_UNLOCKED_DEVICE_REQUIRED),
    ASN1_EXP_OPT(AuthorizationList, creationDateTime, ASN1_INTEGER, TAG_CREATION_DATETIME),
    ASN1_EXP_OPT(AuthorizationList, origin, ASN1_INTEGER, TAG_ORIGIN),
    ASN1_EXP_OPT(AuthorizationList, rootOfTrust, RootOfTrust, TAG_ROOT_OF_TRUST),
    ASN1_EXP_OPT(AuthorizationList, osVersion, ASN1_INTEGER, TAG_OS_VERSION),
    ASN1_EXP_OPT(AuthorizationList, osPatchLevel, ASN1_INTEGER, TAG_OS_PATCH_LEVEL),
    ASN1_EXP_OPT(AuthorizationList, attestationApplicationId, ASN1_OCTET_STRING, TAG_ATTESTATION_APPLICATION_ID),
    ASN1_EXP_OPT(AuthorizationList, attestationIdBrand, ASN1_ANY, TAG_ATTESTATION_ID_BRAND),
    ASN1_EXP_OPT(AuthorizationList, attestationIdDevice, ASN1_ANY, TAG_ATTESTATION_ID_DEVICE),
    ASN1_EXP_OPT(AuthorizationList, attestationIdProduct, ASN1_ANY, TAG_ATTESTATION_ID_PRODUCT),
    ASN1_EXP_OPT(AuthorizationList, attestationIdSerial, ASN1_ANY, TAG_ATTESTATION_ID_SERIAL),
    ASN1_EXP_OPT(AuthorizationList, attestationIdImei, ASN1_ANY, TAG_ATTESTATION_ID_IMEI),
    ASN1_EXP_OPT(AuthorizationList, attestationIdMeid, ASN1_ANY, TAG_ATTESTATION_ID_MEID),
    ASN1_EXP_OPT(AuthorizationList, attestationIdManufacturer, ASN1_ANY, TAG_ATTESTATION_ID_MANUFACTURER),
    ASN1_EXP_OPT(AuthorizationList, attestationIdModel, ASN1_ANY, TAG_ATTESTATION_ID_MODEL),
    ASN1_EXP_OPT(AuthorizationList, attestationIdSocid, ASN1_ANY, TAG_ATTESTATION_ID_SOCID),
    ASN1_EXP_OPT(AuthorizationList, bootPatchLevel, ASN1_INTEGER, TAG_BOOT_PATCH_LEVEL),
    ASN1_EXP_OPT(AuthorizationList, deviceUniqueAttestation, ASN1_NULL, TAG_DEVICE_UNIQUE_ATTESTATION),
    ASN1_EXP_OPT(AuthorizationList, attestationIdSecondImei, ASN1_ANY, TAG_ATTESTATION_ID_SECOND_IMEI),
    ASN1_EXP_OPT(AuthorizationList, moduleHash, ASN1_ANY, TAG_MODULE_HASH),
    ASN1_EXP_OPT(AuthorizationList, attestationIdUdid, ASN1_ANY, TAG_ATTESTATION_ID_UDID)
} ASN1_SEQUENCE_END(AuthorizationList)

ASN1_SEQUENCE(KeyDescription) = {
    ASN1_SIMPLE(KeyDescription, attestationVersion, ASN1_INTEGER),
    ASN1_SIMPLE(KeyDescription, attestationSecurityLevel, ASN1_ENUMERATED),
    ASN1_SIMPLE(KeyDescription, keyMintVersion, ASN1_INTEGER),
    ASN1_SIMPLE(KeyDescription, keyMintSecurityLevel, ASN1_ENUMERATED),
    ASN1_SIMPLE(KeyDescription, attestationChallenge, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KeyDescription, uniqueId, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KeyDescription, softwareEnforced, AuthorizationList),
    ASN1_SIMPLE(KeyDescription, hardwareEnforced, AuthorizationList)
} ASN1_SEQUENCE_END(KeyDescription)

struct LegacyKeyDescription {
    KeyDescription *keyDescription;
    CfInt64Array *purpose;
    CfInt64Array *digest;
    CfInt64Array *padding;
};

CfResult ParseKeyDescription(X509_EXTENSION *extension, KeyDescription **keyDescription)
{
    ASN1_OCTET_STRING *extValue = X509_EXTENSION_get_data(extension);
    if (extValue == NULL) {
        LOGE("X509_EXTENSION_get_data failed\n");
        return CF_ERR_CRYPTO_OPERATION;
    }

    int extValueLen = ASN1_STRING_length(extValue);
    const unsigned char *data = ASN1_STRING_get0_data(extValue);
    KeyDescription *keyDesc = d2i_KeyDescription(NULL, &data, extValueLen);
    if (keyDesc == NULL) {
        LOGE("d2i_KeyDescription failed\n");
        return CF_ERR_CRYPTO_OPERATION;
    }
    *keyDescription = keyDesc;
    return CF_SUCCESS;
}

static CfResult ParseInt64Array(STACK_OF(ASN1_INTEGER) *data, CfInt64Array **out)
{
    if (data == NULL) {
        return CF_SUCCESS;
    }

    int count = sk_ASN1_INTEGER_num(data);
    if (count == 0) {
        return CF_SUCCESS;
    }

    CfInt64Array *array = (CfInt64Array *)CfMalloc(sizeof(CfInt64Array), 0);
    if (array == NULL) {
        LOGE("Malloc failed\n");
        return CF_ERR_MALLOC;
    }

    array->data = (int64_t *)CfMalloc(sizeof(int64_t) * count, 0);
    if (array->data == NULL) {
        LOGE("Malloc failed\n");
        CfFree(array);
        array = NULL;
        return CF_ERR_MALLOC;
    }

    int i;
    for (i = 0; i < count; i++) {
        ASN1_INTEGER *asn1Integer = sk_ASN1_INTEGER_value(data, i);
        if (ASN1_INTEGER_get_int64(&array->data[i], asn1Integer) != 1) {
            LOGE("ASN1_INTEGER_get_int64 failed\n");
            CfFree(array->data);
            array->data = NULL;
            CfFree(array);
            array = NULL;
            return CF_ERR_CRYPTO_OPERATION;
        }
    }
    array->size = (uint32_t)count;
    *out = array;
    return CF_SUCCESS;
}

static CfResult ParseSetOfItems(LegacyKeyDescription *legacyKeyDescription)
{
    if (legacyKeyDescription == NULL || legacyKeyDescription->keyDescription == NULL) {
        return CF_ERR_EXTENSION_NOT_EXIST;
    }
    AuthorizationList *hardwareEnforced = legacyKeyDescription->keyDescription->hardwareEnforced;
    if (hardwareEnforced == NULL) {
        return CF_ERR_EXTENSION_NOT_EXIST;
    }

    CfResult ret = ParseInt64Array(hardwareEnforced->purpose, &legacyKeyDescription->purpose);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    ret = ParseInt64Array(hardwareEnforced->digest, &legacyKeyDescription->digest);
    if (ret != CF_SUCCESS) {
        return ret;
    }
    return ParseInt64Array(hardwareEnforced->padding, &legacyKeyDescription->padding);
}

void FreeHmKeyDescription(LegacyKeyDescription *legacy)
{
    if (legacy == NULL) {
        return;
    }

    if (legacy->purpose != NULL) {
        CfFree(legacy->purpose->data);
        legacy->purpose->data = NULL;
        CfFree(legacy->purpose);
        legacy->purpose = NULL;
    }
    if (legacy->digest != NULL) {
        CfFree(legacy->digest->data);
        legacy->digest->data = NULL;
        CfFree(legacy->digest);
        legacy->digest = NULL;
    }
    if (legacy->padding != NULL) {
        CfFree(legacy->padding->data);
        legacy->padding->data = NULL;
        CfFree(legacy->padding);
        legacy->padding = NULL;
    }
    KeyDescription_free(legacy->keyDescription);
    legacy->keyDescription = NULL;
    CfFree(legacy);
}

CfResult GetHmKeyDescription(const X509 *cert, LegacyKeyDescription **legacy)
{
    if (cert == NULL || legacy == NULL) {
        return CF_NULL_POINTER;
    }

    X509_EXTENSION *extension = NULL;
    CfResult ret = FindCertExt(cert, KEY_DESCRIPTION_OID, sizeof(KEY_DESCRIPTION_OID), &extension);
    if (ret != CF_SUCCESS) {
        LOGE("keyDescription is not exist\n");
        return ret;
    }

    LegacyKeyDescription *out = (LegacyKeyDescription *)CfMalloc(sizeof(LegacyKeyDescription), 0);
    if (out == NULL) {
        LOGE("Malloc failed\n");
        return CF_ERR_MALLOC;
    }

    ret = ParseKeyDescription(extension, &out->keyDescription);
    if (ret != CF_SUCCESS) {
        LOGE("ParseKeyDescription failed, ret = %{public}d\n", ret);
        CfFree(out);
        out = NULL;
        return ret;
    }

    ret = ParseSetOfItems(out);
    if (ret != CF_SUCCESS) {
        LOGE("ParseSetOfItems failed, ret = %{public}d\n", ret);
        FreeHmKeyDescription(out);
        out = NULL;
        return ret;
    }
    *legacy = out;
    return CF_SUCCESS;
}

static CfResult GetOctetString(ASN1_OCTET_STRING *octetString, CfBlob *out)
{
    if (octetString == NULL) {
        return CF_ERR_EXTENSION_NOT_EXIST;
    }
    out->size = (uint32_t)ASN1_STRING_length(octetString);
    out->data = (uint8_t *)ASN1_STRING_get0_data(octetString);
    return CF_SUCCESS;
}

static CfResult GetInt64(ASN1_INTEGER *in, int64_t *v)
{
    if (in == NULL) {
        return CF_ERR_EXTENSION_NOT_EXIST;
    }
    CfResult ret = ASN1_INTEGER_get_int64(v, in);
    if (ret != 1) {
        return CF_ERR_CRYPTO_OPERATION;
    }
    return CF_SUCCESS;
}

static CfResult GetNull(ASN1_NULL *in)
{
    if (in == NULL) {
        return CF_ERR_EXTENSION_NOT_EXIST;
    }

    return CF_SUCCESS;
}

static CfResult GetEnum(ASN1_INTEGER *in, int64_t *v)
{
    if (in == NULL) {
        return CF_ERR_EXTENSION_NOT_EXIST;
    }
    CfResult ret = ASN1_ENUMERATED_get_int64(v, in);
    if (ret != 1) {
        return CF_ERR_CRYPTO_OPERATION;
    }
    return CF_SUCCESS;
}

static CfResult GetInt64Array(CfInt64Array *src, CfInt64Array *dst)
{
    if (src == NULL) {
        return CF_ERR_EXTENSION_NOT_EXIST;
    }
    dst->size = src->size;
    dst->data = src->data;
    return CF_SUCCESS;
}

static CfResult GetKeyDescriptionInfo(LegacyKeyDescription *legacy, HmAttestationCertExtType type,
    HmAttestationCertExt *ext)
{
    KeyDescription *keyDescription = legacy->keyDescription;
    switch (type) {
        case LEGACY_VERSION:
            return GetInt64(keyDescription->attestationVersion, &ext->int64Value);
        case LEGACY_SECURITY_LEVEL:
            return GetEnum(keyDescription->attestationSecurityLevel, &ext->int64Value);
        case LEGACY_KM_VERSION:
            return GetInt64(keyDescription->keyMintVersion, &ext->int64Value);
        case LEGACY_KM_SECURITY_LEVEL:
            return GetEnum(keyDescription->keyMintSecurityLevel, &ext->int64Value);
        case LEGACY_CHALLENGE:
            return GetOctetString(keyDescription->attestationChallenge, &ext->blob);
        case LEGACY_UNIQUE_ID:
            return GetOctetString(keyDescription->uniqueId, &ext->blob);
        default:
            return CF_ERR_PARAMETER_CHECK;
    }
}

static CfResult GetAuthorizationInfoBase(LegacyKeyDescription *legacy, HmAttestationCertExtType type,
    HmAttestationCertExt *ext)
{
    AuthorizationList *hardwareEnforced = legacy->keyDescription->hardwareEnforced;
    if (hardwareEnforced == NULL) {
        return CF_ERR_EXTENSION_NOT_EXIST;
    }
    switch (type) {
        case KM_TAG_PURPOSE:
            return GetInt64Array(legacy->purpose, &ext->int64Array);
        case KM_TAG_ALGORITHM:
            return GetInt64(hardwareEnforced->algorithm, &ext->int64Value);
        case KM_TAG_KEY_SIZE:
            return GetInt64(hardwareEnforced->keySize, &ext->int64Value);
        case KM_TAG_KEY_DIGEST:
            return GetInt64Array(legacy->digest, &ext->int64Array);
        case KM_TAG_KEY_PADDING:
            return GetInt64Array(legacy->padding, &ext->int64Array);
        case KM_TAG_EC_CURVE:
            return GetInt64(hardwareEnforced->ecCurve, &ext->int64Value);
        case KM_TAG_RSA_PUBLIC_EXPONENT:
            return GetInt64(hardwareEnforced->rsaPublicExponent, &ext->int64Value);
        case KM_TAG_NO_AUTH_REQUIRED:
            return GetNull(hardwareEnforced->noAuthRequired);
        case KM_TAG_USER_AUTH_TYPE:
            return GetInt64(hardwareEnforced->userAuthType, &ext->int64Value);
        case KM_TAG_CREATION_DATETIME:
            return GetInt64(hardwareEnforced->creationDateTime, &ext->int64Value);
        case KM_TAG_ORIGIN:
            return GetInt64(hardwareEnforced->origin, &ext->int64Value);
        case KM_TAG_OS_VERSION:
            return GetInt64(hardwareEnforced->osVersion, &ext->int64Value);
        case KM_TAG_OS_PATCH_LEVEL:
            return GetInt64(hardwareEnforced->osPatchLevel, &ext->int64Value);
        default:
            return CF_ERR_PARAMETER_CHECK;
    }
}

static CfResult GetAuthorizationInfoEx(LegacyKeyDescription *legacy, HmAttestationCertExtType type,
    HmAttestationCertExt *ext)
{
    AuthorizationList *hardwareEnforced = legacy->keyDescription->hardwareEnforced;
    if (hardwareEnforced == NULL) {
        return CF_ERR_EXTENSION_NOT_EXIST;
    }
    switch (type) {
        case KM_TAG_ATTESTATION_ID_BRAND:
            return GetOctectOrUtf8Data(hardwareEnforced->attestationIdBrand, &ext->blob);
        case KM_TAG_ATTESTATION_ID_DEVICE:
            return GetOctectOrUtf8Data(hardwareEnforced->attestationIdDevice, &ext->blob);
        case KM_TAG_ATTESTATION_ID_PRODUCT:
            return GetOctectOrUtf8Data(hardwareEnforced->attestationIdProduct, &ext->blob);
        case KM_TAG_ATTESTATION_ID_SERIAL:
            return GetOctectOrUtf8Data(hardwareEnforced->attestationIdSerial, &ext->blob);
        case KM_TAG_ATTESTATION_ID_IMEI:
            return GetOctectOrUtf8Data(hardwareEnforced->attestationIdImei, &ext->blob);
        case KM_TAG_ATTESTATION_ID_MEID:
            return GetOctectOrUtf8Data(hardwareEnforced->attestationIdMeid, &ext->blob);
        case KM_TAG_ATTESTATION_ID_MANUFACTURER:
            return GetOctectOrUtf8Data(hardwareEnforced->attestationIdManufacturer, &ext->blob);
        case KM_TAG_ATTESTATION_ID_MODEL:
            return GetOctectOrUtf8Data(hardwareEnforced->attestationIdModel, &ext->blob);
        case KM_TAG_ATTESTATION_ID_SOCID:
            return GetOctectOrUtf8Data(hardwareEnforced->attestationIdSocid, &ext->blob);
        case KM_TAG_ATTESTATION_ID_UDID:
            return GetOctectOrUtf8Data(hardwareEnforced->attestationIdUdid, &ext->blob);
        default:
            return CF_ERR_PARAMETER_CHECK;
    }
}

CfResult GetKeyDescriptionExt(LegacyKeyDescription *legacy, HmAttestationCertExtType type, HmAttestationCertExt *ext)
{
    if (legacy == NULL || legacy->keyDescription == NULL) {
        return CF_ERR_EXTENSION_NOT_EXIST;
    }
    if (type >= LEGACY_VERSION && type <= LEGACY_UNIQUE_ID) {
        return GetKeyDescriptionInfo(legacy, type, ext);
    }
    if (type >= KM_TAG_PURPOSE && type <= KM_TAG_OS_PATCH_LEVEL) {
        return GetAuthorizationInfoBase(legacy, type, ext);
    }
    if (type >= KM_TAG_ATTESTATION_ID_BRAND && type <= KM_TAG_ATTESTATION_ID_UDID) {
        return GetAuthorizationInfoEx(legacy, type, ext);
    }
    return CF_ERR_PARAMETER_CHECK;
}
