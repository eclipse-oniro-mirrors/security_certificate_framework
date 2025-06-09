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

#include "openssl/x509.h"
#include "openssl/asn1t.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "cf_result.h"
#include "attestation_common.h"
#include "attestation_cert_ext.h"
#include "hm_attestation_cert_ext_type.h"

#define ID_HM_PKI 0x2B, 0x06, 0x01, 0x04, 0x1, 0x8F, 0x5B, 0x02, 0x82, 0x78

#define ID_HM_PKI_CERT_EXT ID_HM_PKI, 0x01
#define ID_HM_DEVICE_SECURITY_LEVEL_EXTENSION ID_HM_PKI_CERT_EXT, 0x01
#define ID_HM_ATTESTATION_EXTENSION ID_HM_PKI_CERT_EXT, 0x03
#define ID_HM_DEVICE_ACTIVATION_EXTENSION ID_HM_PKI_CERT_EXT, 0x05
#define ID_HM_DEVICE_ACTIVATION_DEVICE_ID1 ID_HM_DEVICE_ACTIVATION_EXTENSION, 0x01
#define ID_HM_DEVICE_ACTIVATION_DEVICE_ID2 ID_HM_DEVICE_ACTIVATION_EXTENSION, 0x02
#define ID_HM_ATTESTATION_BASE      ID_HM_PKI, 0x02
#define ID_KEY_PROPERTIES               ID_HM_ATTESTATION_BASE, 0x01
#define ID_SYSTEM_PROPERTIES            ID_HM_ATTESTATION_BASE, 0x02

// ID_KEY_PROPERTIES
#define ID_KEY_PROPERTY_KEY_PURPOSE  ID_KEY_PROPERTIES, 0x01
#define ID_KEY_PROPERTY_KEY_ID ID_KEY_PROPERTIES, 0x02
#define ID_KEY_PROPERTY_APP_ID ID_KEY_PROPERTIES, 0x03

#define ID_KEY_PROPERTY_APP_ID_HAP_ID ID_KEY_PROPERTY_APP_ID, 0x01
#define ID_KEY_PROPERTY_APP_ID_SA_ID ID_KEY_PROPERTY_APP_ID, 0x02

#define ID_KEY_PROPERTY_APP_ID_UNIFIED_ID ID_KEY_PROPERTY_APP_ID, 0x03

#define ID_KEY_PROPERTY_CHALLENGE ID_KEY_PROPERTIES, 0x04
#define ID_KEY_PROPERTY_KEY_FLAG ID_KEY_PROPERTIES, 0x05
#define ID_KEY_PROPERTY_DIGEST ID_KEY_PROPERTIES, 0x08
#define ID_KEY_PROPERTY_SIGN_PADDING ID_KEY_PROPERTIES, 0x09
#define ID_KEY_PROPERTY_ENC_PADDING ID_KEY_PROPERTIES, 0x0A
#define ID_KEY_PROPERTY_SIGN_TYPE ID_KEY_PROPERTIES, 0x0B

// ID_SYSTEM_PROPERTIES
#define ID_SYSTEM_PROPERTIES_OS ID_SYSTEM_PROPERTIES, 0x02
#define ID_SYSTEM_PROPERTIES_OS_VERSION_INFO ID_SYSTEM_PROPERTIES_OS, 0x04
#define ID_SYSTEM_PROPERTIES_OS_SEC_LEVEL_INFO ID_SYSTEM_PROPERTIES_OS, 0x05
#define ID_SYSTEM_PROPERTIES_OS_KEY_MANAGER_TA_ID ID_SYSTEM_PROPERTIES_OS, 0x06
#define ID_SYSTEM_PROPERTIES_OS_PURPOSE ID_SYSTEM_PROPERTIES_OS, 0x07
#define ID_SYSTEM_PROPERTIES_OS_ID_PADDING_FLAG ID_SYSTEM_PROPERTIES_OS, 0x08
#define ID_SYSTEM_PROPERTIES_OS_NONCE ID_SYSTEM_PROPERTIES_OS, 0x09

#define ID_PRIVACY_PROPERTIES ID_SYSTEM_PROPERTIES, 0x04
#define ID_PRIVACY_PROPERTIES_IMEI ID_PRIVACY_PROPERTIES, 0x01
#define ID_PRIVACY_PROPERTIES_MEID ID_PRIVACY_PROPERTIES, 0x02
#define ID_PRIVACY_PROPERTIES_SERIAL ID_PRIVACY_PROPERTIES, 0x03
#define ID_PRIVACY_PROPERTIES_BRAND ID_PRIVACY_PROPERTIES, 0x04
#define ID_PRIVACY_PROPERTIES_DEVICE ID_PRIVACY_PROPERTIES, 0x05
#define ID_PRIVACY_PROPERTIES_PRODUCT ID_PRIVACY_PROPERTIES, 0x06
#define ID_PRIVACY_PROPERTIES_MANUFACTURER ID_PRIVACY_PROPERTIES, 0x07
#define ID_PRIVACY_PROPERTIES_MODEL ID_PRIVACY_PROPERTIES, 0x08
#define ID_PRIVACY_PROPERTIES_SOCID ID_PRIVACY_PROPERTIES, 0x09
#define ID_PRIVACY_PROPERTIES_UDID ID_PRIVACY_PROPERTIES, 0x0A

#define DECLARE_OID(name, id) \
    static const uint8_t name##_OID[] = {id}

DECLARE_OID(DEVICE_SECURITY_LEVEL, ID_HM_DEVICE_SECURITY_LEVEL_EXTENSION);
DECLARE_OID(DEVICE_ACTIVATION_EXT, ID_HM_DEVICE_ACTIVATION_EXTENSION);
DECLARE_OID(DEVICE_ACTIVATION_DEVICE_ID1, ID_HM_DEVICE_ACTIVATION_DEVICE_ID1);
DECLARE_OID(DEVICE_ACTIVATION_DEVICE_ID2, ID_HM_DEVICE_ACTIVATION_DEVICE_ID2);
DECLARE_OID(ATTESTATION_EXT, ID_HM_ATTESTATION_EXTENSION);
DECLARE_OID(ATTESTATION_NONCE, ID_SYSTEM_PROPERTIES_OS_NONCE);
DECLARE_OID(ATTESTATION_IMEI, ID_PRIVACY_PROPERTIES_IMEI);
DECLARE_OID(ATTESTATION_MEID, ID_PRIVACY_PROPERTIES_MEID);
DECLARE_OID(ATTESTATION_SERIAL, ID_PRIVACY_PROPERTIES_SERIAL);
DECLARE_OID(ATTESTATION_MODEL, ID_PRIVACY_PROPERTIES_MODEL);
DECLARE_OID(ATTESTATION_SOCID, ID_PRIVACY_PROPERTIES_SOCID);
DECLARE_OID(ATTESTATION_UDID, ID_PRIVACY_PROPERTIES_UDID);
DECLARE_OID(ATTESTATION_KEY_PURPOSE, ID_KEY_PROPERTY_KEY_PURPOSE);
DECLARE_OID(ATTESTATION_APP_ID, ID_KEY_PROPERTY_APP_ID);
DECLARE_OID(ATTESTATION_APP_ID_HAP_ID, ID_KEY_PROPERTY_APP_ID_HAP_ID);
DECLARE_OID(ATTESTATION_APP_ID_SA_ID, ID_KEY_PROPERTY_APP_ID_SA_ID);
DECLARE_OID(ATTESTATION_APP_ID_UNIFIED_ID, ID_KEY_PROPERTY_APP_ID_UNIFIED_ID);
DECLARE_OID(ATTESTATION_CHALLENGE, ID_KEY_PROPERTY_CHALLENGE);
DECLARE_OID(ATTESTATION_KEY_FLAG, ID_KEY_PROPERTY_KEY_FLAG);
DECLARE_OID(ATTESTATION_DIGEST, ID_KEY_PROPERTY_DIGEST);
DECLARE_OID(ATTESTATION_SIGN_PADDING, ID_KEY_PROPERTY_SIGN_PADDING);
DECLARE_OID(ATTESTATION_ENC_PADDING, ID_KEY_PROPERTY_ENC_PADDING);
DECLARE_OID(ATTESTATION_SIGN_TYPE, ID_KEY_PROPERTY_SIGN_TYPE);
DECLARE_OID(ATTESTATION_VERSION_INFO, ID_SYSTEM_PROPERTIES_OS_VERSION_INFO);
DECLARE_OID(ATTESTATION_KEY_MANAGER_TA_ID, ID_SYSTEM_PROPERTIES_OS_KEY_MANAGER_TA_ID);
DECLARE_OID(ATTESTATION_PURPOSE, ID_SYSTEM_PROPERTIES_OS_PURPOSE);
DECLARE_OID(ATTESTATION_ID_PADDING_FLAG, ID_SYSTEM_PROPERTIES_OS_ID_PADDING_FLAG);

typedef struct {
    const uint8_t *oid;
    uint32_t oidLen;
} AttestationExtOid;

static const AttestationExtOid ATTESTATION_EXT_OIDS[] = {
    {DEVICE_ACTIVATION_DEVICE_ID1_OID, sizeof(DEVICE_ACTIVATION_DEVICE_ID1_OID)}, // DEVICE_ACTIVATION_DEVICE_ID1 0
    {DEVICE_ACTIVATION_DEVICE_ID2_OID, sizeof(DEVICE_ACTIVATION_DEVICE_ID2_OID)}, // DEVICE_ACTIVATION_DEVICE_ID2 1
    {ATTESTATION_KEY_PURPOSE_OID, sizeof(ATTESTATION_KEY_PURPOSE_OID)}, // ATTESTATION_KEY_PURPOSE 2
    {ATTESTATION_APP_ID_HAP_ID_OID, sizeof(ATTESTATION_APP_ID_HAP_ID_OID)}, // ATTESTATION_APP_ID_HAP_ID 3
    {ATTESTATION_APP_ID_SA_ID_OID, sizeof(ATTESTATION_APP_ID_SA_ID_OID)}, // ATTESTATION_APP_ID_SA_ID 4
    {ATTESTATION_APP_ID_UNIFIED_ID_OID, sizeof(ATTESTATION_APP_ID_UNIFIED_ID_OID)}, // ATTESTATION_APP_ID_UNIFIED_ID 5
    {ATTESTATION_CHALLENGE_OID, sizeof(ATTESTATION_CHALLENGE_OID)}, // ATTESTATION_CHALLENGE 6
    {ATTESTATION_KEY_FLAG_OID, sizeof(ATTESTATION_KEY_FLAG_OID)}, // ATTESTATION_KEY_FLAG 7
    {ATTESTATION_DIGEST_OID, sizeof(ATTESTATION_DIGEST_OID)}, // ATTESTATION_DIGEST 8
    {ATTESTATION_SIGN_PADDING_OID, sizeof(ATTESTATION_SIGN_PADDING_OID)}, // ATTESTATION_SIGN_PADDING 9
    {ATTESTATION_ENC_PADDING_OID, sizeof(ATTESTATION_ENC_PADDING_OID)}, // ATTESTATION_ENC_PADDING 10
    {ATTESTATION_SIGN_TYPE_OID, sizeof(ATTESTATION_SIGN_TYPE_OID)}, // ATTESTATION_SIGN_TYPE 11
    {ATTESTATION_VERSION_INFO_OID, sizeof(ATTESTATION_VERSION_INFO_OID)}, // ATTESTATION_VERSION_INFO 12
    {ATTESTATION_KEY_MANAGER_TA_ID_OID, sizeof(ATTESTATION_KEY_MANAGER_TA_ID_OID)}, // ATTESTATION_KEY_MANAGER_TA_ID 13
    {ATTESTATION_PURPOSE_OID, sizeof(ATTESTATION_PURPOSE_OID)}, // ATTESTATION_PURPOSE 14
    {ATTESTATION_ID_PADDING_FLAG_OID, sizeof(ATTESTATION_ID_PADDING_FLAG_OID)}, // ATTESTATION_ID_PADDING_FLAG 15
    {ATTESTATION_NONCE_OID, sizeof(ATTESTATION_NONCE_OID)}, // ATTESTATION_NONCE 16
    {ATTESTATION_IMEI_OID, sizeof(ATTESTATION_IMEI_OID)}, // ATTESTATION_IMEI 17
    {ATTESTATION_MEID_OID, sizeof(ATTESTATION_MEID_OID)}, // ATTESTATION_MEID 18
    {ATTESTATION_SERIAL_OID, sizeof(ATTESTATION_SERIAL_OID)}, // ATTESTATION_SERIAL 19
    {ATTESTATION_MODEL_OID, sizeof(ATTESTATION_MODEL_OID)}, // ATTESTATION_MODEL 20
    {ATTESTATION_SOCID_OID, sizeof(ATTESTATION_SOCID_OID)}, // ATTESTATION_SOCID 21
    {ATTESTATION_UDID_OID, sizeof(ATTESTATION_UDID_OID)}, // ATTESTATION_UDID 22
};

typedef struct {
    ASN1_INTEGER *securityLevel;
    ASN1_OBJECT *attestType;
    ASN1_TYPE *value;
} HmAttestationClaim;

typedef struct {
    ASN1_OBJECT *type;
    ASN1_OCTET_STRING *value;
} HmApplicationIdType;

ASN1_SEQUENCE(HmApplicationIdType) = {
    ASN1_SIMPLE(HmApplicationIdType, type, ASN1_OBJECT),
    ASN1_SIMPLE(HmApplicationIdType, value, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(HmApplicationIdType)
IMPLEMENT_ASN1_FUNCTIONS(HmApplicationIdType)

ASN1_SEQUENCE(HmAttestationClaim) = {
    ASN1_SIMPLE(HmAttestationClaim, securityLevel, ASN1_INTEGER),
    ASN1_SIMPLE(HmAttestationClaim, attestType, ASN1_OBJECT),
    ASN1_SIMPLE(HmAttestationClaim, value, ASN1_ANY),
} ASN1_SEQUENCE_END(HmAttestationClaim)

IMPLEMENT_ASN1_FUNCTIONS(HmAttestationClaim)

struct AttestationRecord {
    int64_t version;
    uint32_t claimNum;
    HmAttestationClaim **claims;
    HmApplicationIdType *appId;
};

static void HmAttestationClaimfree(HmAttestationClaim **claims, uint32_t count)
{
    if (claims == NULL) {
        return;
    }

    uint32_t i;
    for (i = 0; i < count; i++) {
        HmAttestationClaim *claim = claims[i];
        if (claim != NULL) {
            HmAttestationClaim_free(claim);
        }
    }
    CfFree(claims);
}

void FreeHmAttestationRecord(AttestationRecord *record)
{
    if (record == NULL) {
        return;
    }

    HmAttestationClaimfree(record->claims, record->claimNum);
    HmApplicationIdType_free(record->appId);
    CfFree(record);
}

static CfResult Asn1typeGetInteger(ASN1_TYPE *asn1Type, int64_t *value)
{
    if (asn1Type == NULL || asn1Type->type != V_ASN1_INTEGER || asn1Type->value.integer == NULL) {
        return CF_ERR_INVALID_EXTENSION;
    }

    int64_t v = 0;
    CfResult ret = ASN1_INTEGER_get_int64(&v, asn1Type->value.integer);
    if (ret != 1) {
        return CF_ERR_CRYPTO_OPERATION;
    }

    *value = v;
    return CF_SUCCESS;
}

struct DeviceCertSecureLevel {
    int64_t version;
    int64_t secLevel;
};

typedef struct {
    ASN1_INTEGER *version;
    ASN1_ENUMERATED *level;
} HmDeviceSecurityLevel;

ASN1_SEQUENCE(HmDeviceSecurityLevel) = {
    ASN1_SIMPLE(HmDeviceSecurityLevel, version, ASN1_INTEGER),
    ASN1_SIMPLE(HmDeviceSecurityLevel, level, ASN1_ENUMERATED),
} ASN1_SEQUENCE_END(HmDeviceSecurityLevel)

IMPLEMENT_ASN1_FUNCTIONS(HmDeviceSecurityLevel)

CfResult GetDeviceCertSecureLevel(const X509 *cert, DeviceCertSecureLevel **devSecLevel)
{
    if (cert == NULL || devSecLevel == NULL) {
        return CF_NULL_POINTER;
    }
    X509_EXTENSION *extension = NULL;
    CfResult ret = FindCertExt(cert, DEVICE_SECURITY_LEVEL_OID, sizeof(DEVICE_SECURITY_LEVEL_OID), &extension);
    if (ret != CF_SUCCESS) {
        LOGE("device security level extention is not exist, ret = %{public}d\n", ret);
        return ret;
    }

    ASN1_OCTET_STRING *extValue = X509_EXTENSION_get_data(extension);
    if (extValue == NULL) {
        LOGE("X509_EXTENSION_get_data failed\n");
        return CF_ERR_CRYPTO_OPERATION;
    }

    int dataLen = ASN1_STRING_length(extValue);
    const unsigned char *data = ASN1_STRING_get0_data(extValue);
    HmDeviceSecurityLevel *tmp = NULL;
    tmp = d2i_HmDeviceSecurityLevel(NULL, &data, dataLen);
    if (tmp == NULL) {
        LOGE("d2i_HmDeviceSecurityLevel failed\n");
        return CF_ERR_INVALID_EXTENSION;
    }

    int64_t v = 0;
    int64_t s = 0;
    if (ASN1_INTEGER_get_int64(&v, tmp->version) != 1) {
        LOGE("ASN1_INTEGER_get_int64 version failed\n");
        HmDeviceSecurityLevel_free(tmp);
        return CF_ERR_CRYPTO_OPERATION;
    }
    if (ASN1_ENUMERATED_get_int64(&s, tmp->level) != 1) {
        LOGE("ASN1_INTEGER_get_int64 level failed\n");
        HmDeviceSecurityLevel_free(tmp);
        return CF_ERR_CRYPTO_OPERATION;
    }
    HmDeviceSecurityLevel_free(tmp);
    *devSecLevel = (DeviceCertSecureLevel *)CfMalloc(sizeof(DeviceCertSecureLevel), 0);
    if (*devSecLevel == NULL) {
        LOGE("malloc failed\n");
        return CF_ERR_MALLOC;
    }
    (*devSecLevel)->version = v;
    (*devSecLevel)->secLevel = s;
    return CF_SUCCESS;
}

static CfResult FindClaim(AttestationRecord *record, const uint8_t *oid, uint32_t oidLen, HmAttestationClaim **claim)
{
    if (record == NULL || record->claimNum == 0) {
        return CF_ERR_EXTENSION_NOT_EXIST;
    }
    uint32_t i;
    HmAttestationClaim *tmp = NULL;
    for (i = 0; i < record->claimNum; i++) {
        tmp = record->claims[i];
        if (CmpObjOid(tmp->attestType, oid, oidLen) == true) {
            *claim = tmp;
            return CF_SUCCESS;
        }
    }
    return CF_ERR_EXTENSION_NOT_EXIST;
}

static CfResult GetOctetStringItem(AttestationRecord *record, const uint8_t *oid, uint32_t oidLen, CfBlob *out)
{
    HmAttestationClaim *claim = NULL;
    CfResult ret = FindClaim(record, oid, oidLen, &claim);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    if (ASN1_TYPE_get(claim->value) != V_ASN1_OCTET_STRING) {
        return CF_ERR_INVALID_EXTENSION;
    }

    ASN1_OCTET_STRING *octetString = claim->value->value.octet_string;
    if (octetString == NULL) {
        return CF_ERR_INVALID_EXTENSION;
    }

    out->size = ASN1_STRING_length(octetString);
    out->data = (uint8_t *)ASN1_STRING_get0_data(octetString);
    return CF_SUCCESS;
}

static CfResult GetOctetOrUtf8Item(AttestationRecord *record, const uint8_t *oid, uint32_t oidLen, CfBlob *out)
{
    HmAttestationClaim *claim = NULL;
    CfResult ret = FindClaim(record, oid, oidLen, &claim);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    return GetOctectOrUtf8Data(claim->value, out);
}

static CfResult GetInt64Item(AttestationRecord *record, const uint8_t *oid, uint32_t oidLen, int64_t *out)
{
    HmAttestationClaim *claim = NULL;
    CfResult ret = FindClaim(record, oid, oidLen, &claim);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    if (ASN1_TYPE_get(claim->value) != V_ASN1_INTEGER) {
        return CF_ERR_INVALID_EXTENSION;
    }

    ret = ASN1_INTEGER_get_int64(out, claim->value->value.integer);
    if (ret != 1) {
        return CF_ERR_INVALID_EXTENSION;
    }
    return CF_SUCCESS;
}

static CfResult GetBooleanItem(AttestationRecord *record, const uint8_t *oid, uint32_t oidLen, bool *out)
{
    HmAttestationClaim *claim = NULL;
    CfResult ret = FindClaim(record, oid, oidLen, &claim);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    if (ASN1_TYPE_get(claim->value) != V_ASN1_BOOLEAN) {
        return CF_ERR_INVALID_EXTENSION;
    }

    if (claim->value->value.boolean == 0) {
        *out = false;
    } else {
        *out = true;
    }
    return CF_SUCCESS;
}

static CfResult Asn1typeParseHmAttestationClaim(ASN1_TYPE *asn1Type, HmAttestationClaim **claim)
{
    if (asn1Type == NULL || asn1Type->type != V_ASN1_SEQUENCE || asn1Type->value.sequence == NULL) {
        return CF_ERR_INVALID_EXTENSION;
    }

    const unsigned char *p = asn1Type->value.sequence->data;
    long len = asn1Type->value.sequence->length;

    *claim = d2i_HmAttestationClaim(NULL, &p, len);
    if (*claim == NULL) {
        LOGE("d2i_HmAttestationClaim failed\n");
        return CF_ERR_INVALID_EXTENSION;
    }

    return CF_SUCCESS;
}

static CfResult ParseAttestationClaim(STACK_OF(ASN1_TYPE) *exts, int extCount, AttestationRecord *record)
{
    ASN1_TYPE *asn1Type = NULL;
    uint32_t count = 0;
    int i;
    CfResult ret;
    HmAttestationClaim **claims = NULL;

    if (extCount == 1) {
        record->claimNum = 0;
        record->claims = NULL;
        return CF_SUCCESS;
    }

    claims = (HmAttestationClaim **)CfMalloc(sizeof(HmAttestationClaim *) * (extCount - 1), 0);
    if (claims == NULL) {
        LOGE("Malloc failed\n");
        return CF_ERR_MALLOC;
    }

    for (i = 1; i < extCount; i++) {
        asn1Type = sk_ASN1_TYPE_value(exts, i);
        HmAttestationClaim *t = NULL;
        ret = Asn1typeParseHmAttestationClaim(asn1Type, &t);
        if (ret != CF_SUCCESS) {
            LOGE("Asn1typeParseHmAttestationClaim failed, ret = %{public}d\n", ret);
            HmAttestationClaimfree(claims, count);
            return ret;
        }
        claims[i - 1] = t;
        count++;
    }

    record->claimNum = count;
    record->claims = claims;
    return CF_SUCCESS;
}

static CfResult ParseAttestationExt(X509_EXTENSION *extension, AttestationRecord *record)
{
    ASN1_OCTET_STRING *extValue = X509_EXTENSION_get_data(extension);
    if (extValue == NULL) {
        LOGE("X509_EXTENSION_get_data failed\n");
        return CF_ERR_CRYPTO_OPERATION;
    }

    int extValueLen = ASN1_STRING_length(extValue);
    const unsigned char *data = ASN1_STRING_get0_data(extValue);
    if (extValueLen == 0 || data == NULL) {
        LOGE("extValueLen = %{public}d, data = %{public}p\n", extValueLen, data);
        return CF_ERR_EXTENSION_NOT_EXIST;
    }
    STACK_OF(ASN1_TYPE) *exts = d2i_ASN1_SEQUENCE_ANY(NULL, &data, extValueLen);
    if (exts == NULL) {
        LOGE("d2i_ASN1_SEQUENCE_ANY failed\n");
        return CF_ERR_INVALID_EXTENSION;
    }

    CfResult ret;
    int extCount = sk_ASN1_TYPE_num(exts);
    if (extCount <= 0) {
        LOGE("exts has no element\n");
        ret = CF_ERR_EXTENSION_NOT_EXIST;
        goto exit;
    }

    ret = Asn1typeGetInteger(sk_ASN1_TYPE_value(exts, 0), &record->version);
    if (ret != CF_SUCCESS) {
        LOGE("Asn1typeGetInteger record version failed, ret = %{public}d\n", ret);
        goto exit;
    }

    ret = ParseAttestationClaim(exts, extCount, record);
    if (ret != CF_SUCCESS) {
        LOGE("ParseAttestationClaim failed, ret = %{public}d\n", ret);
        goto exit;
    }

exit:
    sk_ASN1_TYPE_pop_free(exts, ASN1_TYPE_free);
    return ret;
}

static CfResult ParseAppId(AttestationRecord *record)
{
    CfBlob blob = {0};
    CfResult ret = GetOctetStringItem(record, ATTESTATION_APP_ID_OID, sizeof(ATTESTATION_APP_ID_OID), &blob);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    HmApplicationIdType *appId = NULL;
    const unsigned char *p = blob.data;
    appId = d2i_HmApplicationIdType(NULL, &p, blob.size);
    if (appId == NULL) {
        LOGE("d2i_HmApplicationIdType failed\n");
        return CF_ERR_INVALID_EXTENSION;
    }

    record->appId = appId;
    return CF_SUCCESS;
}

CfResult GetHmAttestationRecord(const X509 *cert, AttestationRecord **record)
{
    if (cert == NULL || record == NULL) {
        return CF_NULL_POINTER;
    }
    X509_EXTENSION *extension = NULL;
    CfResult ret = FindCertExt(cert, ATTESTATION_EXT_OID, sizeof(ATTESTATION_EXT_OID), &extension);
    if (ret != CF_SUCCESS) {
        LOGE("attestation extention is not exist, ret = %{public}d\n", ret);
        return ret;
    }

    AttestationRecord *tmp = (AttestationRecord *)CfMalloc(sizeof(AttestationRecord), 0);
    if (tmp == NULL) {
        LOGE("Malloc failed\n");
        return CF_ERR_MALLOC;
    }
    ret = ParseAttestationExt(extension, tmp);
    if (ret != CF_SUCCESS) {
        CfFree(tmp);
        return ret;
    }

    ret = ParseAppId(tmp);
    if (ret != CF_SUCCESS && ret != CF_ERR_EXTENSION_NOT_EXIST) {
        FreeHmAttestationRecord(tmp);
        return ret;
    }

    *record = tmp;
    return CF_SUCCESS;
}

CfResult GetDeviceActivationCertExt(const X509 *cert, DeviceActivationCertExt **record)
{
    if (cert == NULL || record == NULL) {
        return CF_NULL_POINTER;
    }
    X509_EXTENSION *extension = NULL;
    CfResult ret = FindCertExt(cert, DEVICE_ACTIVATION_EXT_OID, sizeof(DEVICE_ACTIVATION_EXT_OID), &extension);
    if (ret != CF_SUCCESS) {
        LOGE("Device activation cert extention is not exist, ret = %{public}d\n", ret);
        return ret;
    }

    DeviceActivationCertExt *tmp = (DeviceActivationCertExt *)CfMalloc(sizeof(DeviceActivationCertExt), 0);
    if (tmp == NULL) {
        LOGE("Malloc failed\n");
        return CF_ERR_MALLOC;
    }
    ret = ParseAttestationExt(extension, tmp);
    if (ret != CF_SUCCESS) {
        CfFree(tmp);
        return ret;
    }
    *record = tmp;
    return CF_SUCCESS;
}

CfResult GetDeviceSecureLevel(DeviceCertSecureLevel *record, int *version, int *level)
{
    if (record == NULL) {
        return CF_ERR_EXTENSION_NOT_EXIST;
    }
    if (version != NULL) {
        *version = record->version;
    }
    if (level != NULL) {
        *level = record->secLevel;
    }
    return CF_SUCCESS;
}

void FreeAttestationDevSecLevel(DeviceCertSecureLevel *record)
{
    if (record == NULL) {
        return;
    }

    CfFree(record);
}

void FreeDeviveActiveCertExt(DeviceActivationCertExt *record)
{
    if (record == NULL) {
        return;
    }

    HmAttestationClaimfree(record->claims, record->claimNum);
    CfFree(record);
}

static CfResult GetAppIdType(AttestationRecord *record, const uint8_t *oid, uint32_t oidLen, CfBlob *out)
{
    if (record == NULL || record->appId == NULL) {
        return CF_ERR_EXTENSION_NOT_EXIST;
    }

    if (CmpObjOid(record->appId->type, oid, oidLen) != true) {
        return CF_ERR_EXTENSION_NOT_EXIST;
    }

    out->size = ASN1_STRING_length(record->appId->value);
    out->data = (uint8_t *)ASN1_STRING_get0_data(record->appId->value);
    return CF_SUCCESS;
}

CfResult GetAttestCertExt(AttestationRecord *record, HmAttestationCertExtType type, HmAttestationCertExt *ext)
{
    if (record == NULL) {
        return CF_ERR_EXTENSION_NOT_EXIST;
    }
    if (type == ATTESTATION_VERSION) {
        ext->int64Value = record->version;
        return CF_SUCCESS;
    }
    const uint8_t *oid = ATTESTATION_EXT_OIDS[type].oid;
    uint32_t oidLen = ATTESTATION_EXT_OIDS[type].oidLen;
    switch (type) {
        case ATTESTATION_ID_PADDING_FLAG:
            return GetBooleanItem(record, oid, oidLen, &ext->boolValue);
        case ATTESTATION_APP_ID_HAP_ID:
        case ATTESTATION_APP_ID_SA_ID:
        case ATTESTATION_APP_ID_UNIFIED_ID:
            return GetAppIdType(record, oid, oidLen, &ext->blob);
        case ATTESTATION_PURPOSE:
            return GetInt64Item(record, oid, oidLen, &ext->int64Value);
        case ATTESTATION_NONCE:
        case ATTESTATION_IMEI:
        case ATTESTATION_SERIAL:
        case ATTESTATION_MEID:
        case ATTESTATION_MODEL:
        case ATTESTATION_SOCID:
        case ATTESTATION_UDID:
            return GetOctetOrUtf8Item(record, oid, oidLen, &ext->blob);
        default:
            return GetOctetStringItem(record, oid, oidLen, &ext->blob);
    }
}
