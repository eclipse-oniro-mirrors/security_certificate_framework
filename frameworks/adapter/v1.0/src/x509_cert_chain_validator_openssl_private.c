/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "x509_cert_chain_validator_openssl_private.h"
#include "cert_manager_api.h"

/* KeyUsage type to OpenSSL KU_* bit mapping table */
const uint32_t KEYUSAGE_TO_OPENSSL_MAP[] = {
    KU_DIGITAL_SIGNATURE,   /* KEYUSAGE_DIGITAL_SIGNATURE = 0 */
    KU_NON_REPUDIATION,     /* KEYUSAGE_NON_REPUDIATION = 1 */
    KU_KEY_ENCIPHERMENT,    /* KEYUSAGE_KEY_ENCIPHERMENT = 2 */
    KU_DATA_ENCIPHERMENT,   /* KEYUSAGE_DATA_ENCIPHERMENT = 3 */
    KU_KEY_AGREEMENT,       /* KEYUSAGE_KEY_AGREEMENT = 4 */
    KU_KEY_CERT_SIGN,       /* KEYUSAGE_KEY_CERT_SIGN = 5 */
    KU_CRL_SIGN,            /* KEYUSAGE_CRL_SIGN = 6 */
    KU_ENCIPHER_ONLY,       /* KEYUSAGE_ENCIPHER_ONLY = 7 */
    KU_DECIPHER_ONLY,       /* KEYUSAGE_DECIPHER_ONLY = 8 */
};

/* ExtendedKeyUsage type (HcfEkuType) to OpenSSL NID mapping table */
static const int EXTENDED_KEY_USAGE_TO_OPENSSL_MAP[] = {
    NID_anyExtendedKeyUsage,  /* EKU_ANY = 0 */
    NID_server_auth,          /* EKU_TLS_SERVER_AUTH = 1 */
    NID_client_auth,          /* EKU_TLS_CLIENT_AUTH = 2 */
    NID_code_sign,            /* EKU_CODE_SIGNING = 3 */
    NID_email_protect,        /* EKU_EMAIL_PROTECTION = 4 */
    NID_time_stamp,           /* EKU_TIME_STAMPING = 5 */
    NID_OCSP_sign,            /* EKU_OCSP_SIGNING = 6 */
};

const OpensslErrorToResult ERROR_TO_RESULT_MAP[] = {
    { X509_V_OK, CF_SUCCESS },
    { X509_V_ERR_CERT_SIGNATURE_FAILURE, CF_ERR_CERT_SIGNATURE_FAILURE },
    { X509_V_ERR_CERT_NOT_YET_VALID, CF_ERR_CERT_NOT_YET_VALID },
    { X509_V_ERR_CERT_HAS_EXPIRED, CF_ERR_CERT_HAS_EXPIRED },
    { X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY },
    { X509_V_ERR_KEYUSAGE_NO_CERTSIGN, CF_ERR_KEYUSAGE_NO_CERTSIGN },
    { X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE, CF_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE },
    { X509_V_ERR_INVALID_CA, CF_ERR_KEYUSAGE_NO_CERTSIGN },
};

const OpensslErrorToResult ERROR_TO_RESULT_MAP_EX[] = {
    { X509_V_ERR_CERT_REVOKED, CF_ERR_CERT_REVOKED },
    { X509_V_ERR_CERT_UNTRUSTED, CF_ERR_CERT_UNTRUSTED },
    { X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, CF_ERR_CERT_UNTRUSTED },
    { X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN, CF_ERR_CERT_UNTRUSTED },
    { X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION, CF_ERR_CERT_UNKNOWN_CRITICAL_EXTENSION },
    { X509_V_ERR_UNABLE_TO_GET_CRL, CF_ERR_CRL_NOT_FOUND },
    { X509_V_ERR_CRL_NOT_YET_VALID, CF_ERR_CRL_NOT_YET_VALID },
    { X509_V_ERR_CRL_HAS_EXPIRED, CF_ERR_CRL_HAS_EXPIRED },
    { X509_V_ERR_CRL_SIGNATURE_FAILURE, CF_ERR_CRL_SIGNATURE_FAILURE },
    { X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER, CF_ERR_UNABLE_TO_GET_CRL_ISSUER },
    { X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY},
};

const OpensslErrorToResult X509_VERIFY_IGNORE_ERR_MAP[] = {
    { X509_V_ERR_CERT_NOT_YET_VALID, CERT_NOT_YET_VALID },
    { X509_V_ERR_CERT_HAS_EXPIRED, CERT_HAS_EXPIRED },
    { X509_V_ERR_CRL_NOT_YET_VALID, CRL_NOT_YET_VALID },
    { X509_V_ERR_CRL_HAS_EXPIRED, CRL_HAS_EXPIRED },
    { X509_V_ERR_UNABLE_TO_GET_CRL, CRL_NOT_FOUND },
    { X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION, CERT_UNKNOWN_CRITICAL_EXTENSION },
};

CfResult CheckIpAddresses(X509 *x509, const HcfX509CertValidatorParams *params, CertVerifyResultInner *result)
{
    if (params->ipAddresses.count == 0) {
        return CF_SUCCESS;
    }
    for (uint32_t i = 0; i < params->ipAddresses.count; i++) {
        if (X509_check_ip_asc(x509, params->ipAddresses.data[i], 0) == 1) {
            return CF_SUCCESS;
        }
    }
    RETURN_VERIFY_ERROR(CF_ERR_CERT_IP_ADDRESS_MISMATCH,
        "The certificate ip address is not matched.", result);
}

CfResult CheckExtendedKeyUsage(X509 *x509, const HcfX509CertValidatorParams *params,
    CertVerifyResultInner *result)
{
    if (params->extendedKeyUsage.count == 0) {
        return CF_SUCCESS;
    }
    STACK_OF(ASN1_OBJECT) *extUsage = X509_get_ext_d2i(x509, NID_ext_key_usage, NULL, NULL);
    if (extUsage == NULL) {
        RETURN_VERIFY_ERROR(CF_ERR_CERT_EXTENDED_KEY_USAGE_MISMATCH,
            "The certificate extended key usage is not matched.", result);
    }
    for (uint32_t i = 0; i < params->extendedKeyUsage.count; i++) {
        int32_t ekuType = params->extendedKeyUsage.data[i];
        if (ekuType < 0 ||
            (uint32_t)ekuType >=
            (sizeof(EXTENDED_KEY_USAGE_TO_OPENSSL_MAP) / sizeof(EXTENDED_KEY_USAGE_TO_OPENSSL_MAP[0]))) {
            sk_ASN1_OBJECT_pop_free(extUsage, ASN1_OBJECT_free);
            RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK, "Invalid extended key usage type.", result);
        }
        int nid = EXTENDED_KEY_USAGE_TO_OPENSSL_MAP[ekuType];
        bool found = false;
        int32_t num = sk_ASN1_OBJECT_num(extUsage);
        for (int32_t j = 0; j < num; j++) {
            ASN1_OBJECT *obj = sk_ASN1_OBJECT_value(extUsage, j);
            if (obj != NULL && OBJ_obj2nid(obj) == nid) {
                found = true;
                break;
            }
        }
        if (!found) {
            sk_ASN1_OBJECT_pop_free(extUsage, ASN1_OBJECT_free);
            RETURN_VERIFY_ERROR(CF_ERR_CERT_EXTENDED_KEY_USAGE_MISMATCH,
                "The certificate extended key usage is not matched.", result);
        }
    }
    sk_ASN1_OBJECT_pop_free(extUsage, ASN1_OBJECT_free);
    return CF_SUCCESS;
}

void FormatRevocationTime(const ASN1_TIME *time, char *buf, size_t bufLen)
{
    if (time == NULL || buf == NULL || bufLen == 0) {
        return;
    }
    struct tm tm;
    if (ASN1_TIME_to_tm(time, &tm) != 1) {
        return;
    }
    (void)snprintf_s(buf, bufLen, bufLen - 1, "%04d%02d%02d%02d%02d%02dZ",
        tm.tm_year + TM_YEAR_BASE, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static int32_t GetCrlRevocationReason(X509_REVOKED *rev)
{
    ASN1_ENUMERATED *reasonObj = X509_REVOKED_get_ext_d2i(rev, NID_crl_reason, NULL, NULL);
    if (reasonObj == NULL) {
        return REVOCATION_REASON_UNSPECIFIED;
    }
    long reason = ASN1_ENUMERATED_get(reasonObj);
    ASN1_ENUMERATED_free(reasonObj);
    return (int32_t)reason;
}

void FillCrlRevocationInfo(X509 *cert, const HcfX509CertValidatorOpenSSLParams *opensslParams,
    CertVerifyResultInner *result)
{
    if (cert == NULL || opensslParams == NULL || opensslParams->store == NULL || result == NULL) {
        return;
    }
    STACK_OF(X509_OBJECT) *objs = X509_STORE_get0_objects(opensslParams->store);
    if (objs == NULL) {
        return;
    }
    const ASN1_INTEGER *certSerial = X509_get0_serialNumber(cert);
    if (certSerial == NULL) {
        return;
    }
    int objNum = sk_X509_OBJECT_num(objs);
    for (int i = 0; i < objNum; i++) {
        X509_OBJECT *obj = sk_X509_OBJECT_value(objs, i);
        if (obj == NULL || X509_OBJECT_get_type(obj) != X509_LU_CRL) {
            continue;
        }
        X509_CRL *crl = X509_OBJECT_get0_X509_CRL(obj);
        if (crl == NULL) {
            continue;
        }
        STACK_OF(X509_REVOKED) *revokedList = X509_CRL_get_REVOKED(crl);
        int revokeNum = sk_X509_REVOKED_num(revokedList);
        for (int j = 0; j < revokeNum; j++) {
            X509_REVOKED *rev = sk_X509_REVOKED_value(revokedList, j);
            if (rev == NULL) {
                continue;
            }
            const ASN1_INTEGER *revSerial = X509_REVOKED_get0_serialNumber(rev);
            if (revSerial == NULL || ASN1_INTEGER_cmp(revSerial, certSerial) != 0) {
                continue;
            }
            result->revocationReason = GetCrlRevocationReason(rev);
            FormatRevocationTime(X509_REVOKED_get0_revocationDate(rev),
                result->revocationTime, sizeof(result->revocationTime));
            return;
        }
    }
}

uint64_t Asn1TimeToTimestamp(const ASN1_TIME *time)
{
    if (time == NULL) {
        return 0;
    }
    struct tm tm;
    if (ASN1_TIME_to_tm(time, &tm) != 1) {
        return 0;
    }
    time_t t = timegm(&tm);
    return (t == (time_t)-1) ? 0 : (uint64_t)t;
}

uint64_t GetCrlExpirationTime(X509_CRL *crl)
{
    uint64_t t = Asn1TimeToTimestamp(X509_CRL_get0_nextUpdate(crl));
    return (t != 0) ? t : (uint64_t)(time(NULL) + CRL_CACHE_FALLBACK_EXPIRE_SECONDS);
}

#define SHA256_HEX_LEN (SHA256_DIGEST_LENGTH * 2)

static enum CmRevocationType ToCmRevocationType(HcfRevocationType type)
{
    return (type == REVOCATION_TYPE_CRL) ? CM_REVOCATION_TYPE_CRL : CM_REVOCATION_TYPE_OCSP;
}

/* Output an uppercase hex string after SHA256 on DER data (32 bytes -> 64 characters + null) */
static CfResult HashDerToHex(const unsigned char *der, uint32_t derLen, char *hexBuf, uint32_t hexBufLen)
{
    if (der == NULL || hexBuf == NULL || hexBufLen < SHA256_HEX_LEN + 1) {
        return CF_ERR_PARAMETER_CHECK;
    }
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(der, derLen, digest);
    static const char kHexUpper[] = "0123456789ABCDEF";
    for (uint32_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        hexBuf[i * 2] = kHexUpper[digest[i] >> 4];
        hexBuf[i * 2 + 1] = kHexUpper[digest[i] & 0x0F];
    }
    hexBuf[SHA256_HEX_LEN] = '\0';
    return CF_SUCCESS;
}

/* Output the DER data directly as an uppercase hex string (for short data such as serial numbers, no hashing) */
static CfResult DerToHex(const unsigned char *der, uint32_t derLen, char *hexBuf, uint32_t hexBufLen)
{
    if (der == NULL || hexBuf == NULL || hexBufLen < derLen * 2 + 1) {
        return CF_ERR_PARAMETER_CHECK;
    }
    static const char kHexUpper[] = "0123456789ABCDEF";
    for (uint32_t i = 0; i < derLen; i++) {
        hexBuf[i * 2] = kHexUpper[der[i] >> 4];
        hexBuf[i * 2 + 1] = kHexUpper[der[i] & 0x0F];
    }
    hexBuf[derLen * 2] = '\0';
    return CF_SUCCESS;
}

/* Build the SHA256 hex of the issuer name and key DER, output to nameHex/keyHex. */
static CfResult BuildIssuerHashHex(X509 *issuer, char *nameHex, uint32_t nameHexLen,
    char *keyHex, uint32_t keyHexLen)
{
    unsigned char *nameDer = NULL;
    int nameDerLen = i2d_X509_NAME(X509_get_issuer_name(issuer), &nameDer);
    if (nameDerLen <= 0 || nameDer == NULL) {
        return CF_ERR_CRYPTO_OPERATION;
    }

    EVP_PKEY *issuerKey = X509_get_pubkey(issuer);
    if (issuerKey == NULL) {
        OPENSSL_free(nameDer);
        return CF_ERR_CRYPTO_OPERATION;
    }
    unsigned char *keyDer = NULL;
    int keyDerLen = i2d_PUBKEY(issuerKey, &keyDer);
    EVP_PKEY_free(issuerKey);
    if (keyDerLen <= 0 || keyDer == NULL) {
        OPENSSL_free(nameDer);
        return CF_ERR_CRYPTO_OPERATION;
    }

    CfResult ret = HashDerToHex(nameDer, (uint32_t)nameDerLen, nameHex, nameHexLen);
    OPENSSL_free(nameDer);
    if (ret != CF_SUCCESS) {
        OPENSSL_free(keyDer);
        return ret;
    }
    ret = HashDerToHex(keyDer, (uint32_t)keyDerLen, keyHex, keyHexLen);
    OPENSSL_free(keyDer);
    return ret;
}

/* Assemble the identifier material: CRL has no serial number, OCSP appends the serial number (raw hex). */
static CfResult BuildIdentifierMaterial(X509 *cert, HcfRevocationType type,
    const char *nameHex, const char *keyHex, char *combined, uint32_t combinedLen)
{
    if (type == REVOCATION_TYPE_CRL) {
        if (snprintf_s(combined, combinedLen, combinedLen - 1, "CRL:%s:%s", nameHex, keyHex) < 0) {
            return CF_ERR_CRYPTO_OPERATION;
        }
        return CF_SUCCESS;
    }

    unsigned char *serialDer = NULL;
    int serialDerLen = i2d_ASN1_INTEGER((ASN1_INTEGER *)X509_get0_serialNumber(cert), &serialDer);
    if (serialDerLen <= 0 || serialDer == NULL) {
        return CF_ERR_CRYPTO_OPERATION;
    }
    char serialHex[129] = { 0 };
    CfResult ret = DerToHex(serialDer, (uint32_t)serialDerLen, serialHex, sizeof(serialHex));
    OPENSSL_free(serialDer);
    if (ret != CF_SUCCESS) {
        return ret;
    }
    if (snprintf_s(combined, combinedLen, combinedLen - 1, "OCSP:%s:%s:%s",
        nameHex, keyHex, serialHex) < 0) {
        return CF_ERR_CRYPTO_OPERATION;
    }
    return CF_SUCCESS;
}

CfResult BuildRevocationCacheIdentifier(X509 *cert, X509 *issuer,
    HcfRevocationType type, char *bufOut, uint32_t bufLen)
{
    if (cert == NULL || issuer == NULL || bufOut == NULL ||
        (type != REVOCATION_TYPE_CRL && type != REVOCATION_TYPE_OCSP)) {
        return CF_ERR_PARAMETER_CHECK;
    }
    if (bufLen < MAX_REVOCATION_CACHE_ID_LEN) {
        return CF_ERR_PARAMETER_CHECK;
    }

    char nameHex[SHA256_HEX_LEN + 1] = { 0 };
    char keyHex[SHA256_HEX_LEN + 1] = { 0 };
    CfResult ret = BuildIssuerHashHex(issuer, nameHex, sizeof(nameHex), keyHex, sizeof(keyHex));
    if (ret != CF_SUCCESS) {
        return ret;
    }

    char combined[256] = { 0 };
    ret = BuildIdentifierMaterial(cert, type, nameHex, keyHex, combined, sizeof(combined));
    if (ret != CF_SUCCESS) {
        return ret;
    }

    return HashDerToHex((const unsigned char *)combined, (uint32_t)strlen(combined), bufOut, bufLen);
}

CfResult RevocationCacheStore(const char *identifier, HcfRevocationType type,
    const CfBlob *data, uint64_t expirationTime)
{
    if (identifier == NULL || data == NULL || data->data == NULL) {
        return CF_ERR_PARAMETER_CHECK;
    }
    struct CmBlob key = { (uint32_t)strlen(identifier), (uint8_t *)identifier };
    struct CmBlob cmData = { data->size, data->data };
    int32_t cmRet = CmSaveRevocationCache(key, ToCmRevocationType(type), cmData, (int64_t)expirationTime);
    if (cmRet == CM_SUCCESS) {
        return CF_SUCCESS;
    }
    LOGW("CmSaveRevocationCache failed, ret = %{public}d.", cmRet);
    return CF_ERR_CRYPTO_OPERATION;
}

CfResult RevocationCacheQuery(const char *identifier, HcfRevocationType type, CfBlob *dataOut)
{
    if (identifier == NULL || dataOut == NULL) {
        return CF_ERR_PARAMETER_CHECK;
    }
    struct CmBlob key = { (uint32_t)strlen(identifier), (uint8_t *)identifier };
    struct CmBlob cmData = { 0, NULL };
    int32_t cmRet = CmGetRevocationCache(key, ToCmRevocationType(type), &cmData);
    if (cmRet == CM_SUCCESS) {
        dataOut->data = cmData.data;
        dataOut->size = cmData.size;
        return CF_SUCCESS;
    }
    if (cmRet != CMR_ERROR_NOT_EXIST && cmRet != CMR_ERROR_NOT_FOUND) {
        LOGW("CmGetRevocationCache failed, ret = %{public}d.", cmRet);
    }
    return CF_NOT_EXIST;
}