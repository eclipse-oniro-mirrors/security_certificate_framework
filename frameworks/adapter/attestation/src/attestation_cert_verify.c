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

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "cf_log.h"
#include "cf_memory.h"
#include "attestation_common.h"
#include "attestation_cert_ext.h"
#include "attestation_cert_verify.h"
#include "attestation_cert_ext_legacy.h"

static const char *ROOT_CA = "-----BEGIN CERTIFICATE-----\n"
"MIIFZDCCA0ygAwIBAgIIYsLLTehAXpYwDQYJKoZIhvcNAQELBQAwUDELMAkGA1UE\n"
"BhMCQ04xDzANBgNVBAoMBkh1YXdlaTETMBEGA1UECwwKSHVhd2VpIENCRzEbMBkG\n"
"A1UEAwwSSHVhd2VpIENCRyBSb290IENBMB4XDTE3MDgyMTEwNTYyN1oXDTQyMDgx\n"
"NTEwNTYyN1owUDELMAkGA1UEBhMCQ04xDzANBgNVBAoMBkh1YXdlaTETMBEGA1UE\n"
"CwwKSHVhd2VpIENCRzEbMBkGA1UEAwwSSHVhd2VpIENCRyBSb290IENBMIICIjAN\n"
"BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1OyKm3Ig/6eibB7Uz2o93UqGk2M7\n"
"84WdfF8mvffvu218d61G5M3Px54E3kefUTk5Ky1ywHvw7Rp9KDuYv7ktaHkk+yr5\n"
"9Ihseu3a7iM/C6SnMSGt+LfB/Bcob9Abw95EigXQ4yQddX9hbNrin3AwZw8wMjEI\n"
"SYYDo5GuYDL0NbAiYg2Y5GpfYIqRzoi6GqDz+evLrsl20kJeCEPgJZN4Jg00Iq9k\n"
"++EKOZ5Jc/Zx22ZUgKpdwKABkvzshEgG6WWUPB+gosOiLv++inu/9blDpEzQZhjZ\n"
"9WVHpURHDK1YlCvubVAMhDpnbqNHZ0AxlPletdoyugrH/OLKl5inhMXNj3Re7Hl8\n"
"WsBWLUKp6sXFf0dvSFzqnr2jkhicS+K2IYZnjghC9cOBRO8fnkonh0EBt0evjUIK\n"
"r5ClbCKioBX8JU+d4ldtWOpp2FlxeFTLreDJ5ZBU4//bQpTwYMt7gwMK+MO5Wtok\n"
"Ux3UF98Z6GdUgbl6nBjBe82c7oIQXhHGHPnURQO7DDPgyVnNOnTPIkmiHJh/e3vk\n"
"VhiZNHFCCLTip6GoJVrLxwb9i4q+d0thw4doxVJ5NB9OfDMV64/ybJgpf7m3Ld2y\n"
"E0gsf1prrRlDFDXjlYyqqpf1l9Y0u3ctXo7UpXMgbyDEpUQhq3a7txZQO/17luTD\n"
"oA6Tz1ADavvBwHkCAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQF\n"
"MAMBAf8wHQYDVR0OBBYEFKrE03lH6G4ja+/wqWwicz16GWmhMA0GCSqGSIb3DQEB\n"
"CwUAA4ICAQC1d3TMB+VHZdGrWJbfaBShFNiCTN/MceSHOpzBn6JumQP4N7mxCOwd\n"
"RSsGKQxV2NPH7LTXWNhUvUw5Sek96FWx/+Oa7jsj3WNAVtmS3zKpCQ5iGb08WIRO\n"
"cFnx3oUQ5rcO8r/lUk7Q2cN0E+rF4xsdQrH9k2cd3kAXZXBjfxfKPJTdPy1XnZR/\n"
"h8H5EwEK5DWjSzK1wKd3G/Fxdm3E23pcr4FZgdYdOlFSiqW2TJ3Qe6lF4GOKOOyd\n"
"WHkpu54ieTsqoYcuMKnKMjT2SLNNgv9Gu5ipaG8Olz6g9C7Htp943lmK/1Vtnhgg\n"
"pL3rDTsFX/+ehk7OtxuNzRMD9lXUtEfok7f8XB0dcL4ZjnEhDmp5QZqC1kMubHQt\n"
"QnTauEiv0YkSGOwJAUZpK1PIff5GgxXYfaHfBC6Op4q02ppl5Q3URl7XIjYLjvs9\n"
"t4S9xPe8tb6416V2fe1dZ62vOXMMKHkZjVihh+IceYpJYHuyfKoYJyahLOQXZykG\n"
"K5iPAEEtq3HPfMVF43RKHOwfhrAH5KwelUA/0EkcR4Gzth1MKEqojdnYNemkkSy7\n"
"aNPPT4LEm5R7sV6vG1CjwbgvQrWCgc4nMb8ngdfnVF7Ydqjqi9SAqUzIk4+Uf0ZY\n"
"+6RY5IcHdCaiPaWIE1xURQ8B0DRUURsQwXdjZhgLN/DKJpCl5aCCxg==\n"
"-----END CERTIFICATE-----";

static const char *ROOT_G2_CA = "-----BEGIN CERTIFICATE-----\n"
"MIICGjCCAaGgAwIBAgIIShhpn519jNAwCgYIKoZIzj0EAwMwUzELMAkGA1UEBhMC\n"
"Q04xDzANBgNVBAoMBkh1YXdlaTETMBEGA1UECwwKSHVhd2VpIENCRzEeMBwGA1UE\n"
"AwwVSHVhd2VpIENCRyBSb290IENBIEcyMB4XDTIwMDMxNjAzMDQzOVoXDTQ5MDMx\n"
"NjAzMDQzOVowUzELMAkGA1UEBhMCQ04xDzANBgNVBAoMBkh1YXdlaTETMBEGA1UE\n"
"CwwKSHVhd2VpIENCRzEeMBwGA1UEAwwVSHVhd2VpIENCRyBSb290IENBIEcyMHYw\n"
"EAYHKoZIzj0CAQYFK4EEACIDYgAEWidkGnDSOw3/HE2y2GHl+fpWBIa5S+IlnNrs\n"
"GUvwC1I2QWvtqCHWmwFlFK95zKXiM8s9yV3VVXh7ivN8ZJO3SC5N1TCrvB2lpHMB\n"
"wcz4DA0kgHCMm/wDec6kOHx1xvCRo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T\n"
"AQH/BAUwAwEB/zAdBgNVHQ4EFgQUo45a9Vq8cYwqaiVyfkiS4pLcIAAwCgYIKoZI\n"
"zj0EAwMDZwAwZAIwMypeB7P0IbY7c6gpWcClhRznOJFj8uavrNu2PIoz9KIqr3jn\n"
"BlBHJs0myI7ntYpEAjBbm8eDMZY5zq5iMZUC6H7UzYSix4Uy1YlsLVV738PtKP9h\n"
"FTjgDHctXJlC5L7+ZDY=\n"
"-----END CERTIFICATE-----";

static const char *EQUIPMENT_ROOT_CA = "-----BEGIN CERTIFICATE-----\n"
"MIICEDCCAZagAwIBAgIDM4vWMAoGCCqGSM49BAMDME8xCzAJBgNVBAYTAkNOMRMw\n"
"EQYDVQQKEwpIdWF3ZWkgQ0JHMSswKQYDVQQDEyJIdWF3ZWkgQ0JHIEVDQyBFcXVp\n"
"cG1lbnQgUm9vdCBDQSAzMCAXDTI0MDQxMzA0MjAwN1oYDzIwNzQwNDEzMDQyMDA3\n"
"WjBPMQswCQYDVQQGEwJDTjETMBEGA1UEChMKSHVhd2VpIENCRzErMCkGA1UEAxMi\n"
"SHVhd2VpIENCRyBFQ0MgRXF1aXBtZW50IFJvb3QgQ0EgMzB2MBAGByqGSM49AgEG\n"
"BSuBBAAiA2IABIqIk8IWZQaD80A5w8IxUN5HYs6coMCoA2uMffx8PQhoRE+OqsFM\n"
"g4AkdZmIqSjD0UMVNgN90gwTWYsjFRtztang3bujaQfABwb2PoLwd8bvdZaD8eq6\n"
"uYMBqgbEEeb23aNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8w\n"
"HQYDVR0OBBYEFCnkWR/rJwU1EGXzxZPD1X2pTWhFMAoGCCqGSM49BAMDA2gAMGUC\n"
"MH+QnarOVBE2RtbqVMMTKBlKMc/sas/CZuawZazpdEhNKZIfe/9cODWMpV0/NpKJ\n"
"/QIxAKNJ6Wb0ir3VGYpCfXLAGgCcJU5G/DHorT+7eF6T8Bg4t2Di1XGT9HIaZ2W+\n"
"OSPInA==\n"
"-----END CERTIFICATE-----";

struct HcfAttestCertVerifyParam {
    bool checkTime;
    STACK_OF(X509) *trustedCerts;
    const HmAttestationSnInfo *snInfos;
};
#define SUB_CA_SUBJECT_INFO_LEN 3

#define DEVICE_SECURITY_LEVEL_MIN 0
#define DEVICE_SECURITY_LEVEL_MAX 5

#define MAX_CERT_NUM 20

#define MAX_CERT_CHAIN_NUM 5
#define MIN_CERT_CHAIN_NUM 2

typedef enum {
    HM_ATTEST_TYPE_LEGACY = 0, // RSA cert
    HM_ATTEST_TYPE_STANDARD = 1, // EC cert
    HM_ATTEST_TYPE_UNKNOWN = 0xFF,
} HmAttestType;

struct HmAttestationInfo {
    HmAttestType type;
    union {
        void *data;
        AttestationRecord *attestationRecord;
        LegacyKeyDescription *legacyKeyDescription;
    };
    DeviceCertSecureLevel *attestationDevSecLevel;
    DeviceActivationCertExt *deviveActiveCertExt;
    STACK_OF(X509) *trustedChain;
    bool hasParseExtension;
};

static CfResult AddtrustedCertsToStore(STACK_OF(X509) *trustedCerts, X509_STORE *store)
{
    int i;
    for (i = 0; i < sk_X509_num(trustedCerts); i++) {
        X509 *ca = sk_X509_value(trustedCerts, i);
        if (ca == NULL) {
            LOGE("cert is NULL\n");
            return CF_ERR_CRYPTO_OPERATION;
        }

        if (X509_STORE_add_cert(store, ca) != 1) {
            LOGE("X509_STORE_add_cert failed\n");
            return CF_ERR_CRYPTO_OPERATION;
        }
    }
    return CF_SUCCESS;
}

typedef struct {
    int32_t errCode;
    CfResult ret;
} X509VerifyErrCodeMap;

static const X509VerifyErrCodeMap X509_VERIFY_ERR_MAP[] = {
    {X509_V_ERR_CERT_SIGNATURE_FAILURE, CF_ERR_CERT_SIGNATURE_FAILURE},
    {X509_V_ERR_CERT_NOT_YET_VALID, CF_ERR_CERT_NOT_YET_VALID},
    {X509_V_ERR_CERT_HAS_EXPIRED, CF_ERR_CERT_HAS_EXPIRED},
    {X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY},
    {X509_V_ERR_KEYUSAGE_NO_CERTSIGN, CF_ERR_KEYUSAGE_NO_CERTSIGN},
    {X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE, CF_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE},
};

static CfResult ParseX509VerifyErrCode(X509_STORE_CTX *ctx)
{
    int32_t errCode = X509_STORE_CTX_get_error(ctx);
    LOGE("X509_verify_cert failed: %{public}s\n", X509_verify_cert_error_string(errCode));
    int i;
    for (i = 0; i < sizeof(X509_VERIFY_ERR_MAP) / sizeof(X509_VERIFY_ERR_MAP[0]); i++) {
        if (X509_VERIFY_ERR_MAP[i].errCode == errCode) {
            return X509_VERIFY_ERR_MAP[i].ret;
        }
    }
    return CF_ERR_CRYPTO_OPERATION;
}

static CfResult VerifyCerts(STACK_OF(X509) *certs, STACK_OF(X509) *trustedCerts, const HcfAttestCertVerifyParam *param,
    STACK_OF(X509) **chain)
{
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    X509 *cert = NULL;
    CfResult ret = CF_ERR_CRYPTO_OPERATION;

    store = X509_STORE_new();
    if (store == NULL) {
        LOGE("X509_STORE_new failed\n");
        return CF_ERR_CRYPTO_OPERATION;
    }

    ret = AddtrustedCertsToStore(trustedCerts, store);
    if (ret != CF_SUCCESS) {
        LOGE("AddtrustedCertsToStore failed\n");
        goto exit;
    }

    ctx = X509_STORE_CTX_new();
    if (ctx == NULL) {
        LOGE("X509_STORE_CTX_new failed\n");
        goto exit;
    }

    cert = sk_X509_value(certs, 0);
    if (cert == NULL) {
        LOGE("cert is NULL\n");
        goto exit;
    }

    if (X509_STORE_CTX_init(ctx, store, cert, certs) != 1) {
        LOGE("X509_STORE_CTX_init failed\n");
        goto exit;
    }

    if (param != NULL && param->checkTime == false) {
        (void)X509_STORE_set_flags(store, X509_V_FLAG_NO_CHECK_TIME);
    }

    if (X509_verify_cert(ctx) != 1) {
        ret = ParseX509VerifyErrCode(ctx);
        goto exit;
    }

    *chain = X509_STORE_CTX_get1_chain(ctx);
    ret = CF_SUCCESS;
exit:
    X509_STORE_free(store);
    X509_STORE_CTX_free(ctx);
    return ret;
}

static CfResult GetX509NameByNid(X509_NAME *name, int nid, char **buf)
{
    CfResult ret = X509_NAME_get_text_by_NID(name, nid, NULL, 0);
    if (ret <= 0) {
        LOGE("X509 name not exist %{public}s\n", OBJ_nid2sn(nid));
        return CF_ERR_EXTENSION_NOT_EXIST;
    }

    int len = ret + 1;
    char *out = (char *)CfMalloc(len, 0);
    if (out == NULL) {
        LOGE("Malloc failed\n");
        return CF_ERR_MALLOC;
    }
    ret = X509_NAME_get_text_by_NID(name, nid, out, len);
    if (ret <= 0) {
        LOGE("X509_NAME_get_text_by_NID failed\n");
        CfFree(out);
        return CF_ERR_CRYPTO_OPERATION;
    }
    *buf = out;
    return CF_SUCCESS;
}

static CfResult CheckSnItem(char *snPatternItem, char *item)
{
    if (snPatternItem == NULL) {
        return CF_SUCCESS;
    }

    if (item == NULL) {
        return CF_ERR_PARAMETER_CHECK;
    }

    if (strcmp(snPatternItem, item) != 0) {
        return CF_ERR_PARAMETER_CHECK;
    }
    return CF_SUCCESS;
}

static CfResult CheckSn(const CertSnInfo *snPattern, const CertSnInfo *sn)
{
    if (snPattern->cn == NULL || sn->cn == NULL) {
        LOGE("snPattern->cn or sn->cn is NULL\n");
        return CF_ERR_PARAMETER_CHECK;
    }

    if (strncmp(snPattern->cn, sn->cn, strlen(snPattern->cn)) != 0) {
        LOGI("cn is not equal\n");
        return CF_ERR_PARAMETER_CHECK;
    }

    if (CheckSnItem(snPattern->o, sn->o) != CF_SUCCESS) {
        LOGI("o is not equal\n");
        return CF_ERR_PARAMETER_CHECK;
    }

    if (CheckSnItem(snPattern->c, sn->c) != CF_SUCCESS) {
        LOGI("c is not equal\n");
        return CF_ERR_PARAMETER_CHECK;
    }

    if (CheckSnItem(snPattern->ou, sn->ou) != CF_SUCCESS) {
        LOGI("ou is not equal\n");
        return CF_ERR_PARAMETER_CHECK;
    }

    return CF_SUCCESS;
}

static void FreeSnInfo(CertSnInfo *sn)
{
    CfFree(sn->cn);
    sn->cn = NULL;
    CfFree(sn->c);
    sn->c = NULL;
    CfFree(sn->ou);
    sn->ou = NULL;
    CfFree(sn->o);
    sn->o = NULL;
}

static CfResult GetCertSn(X509 *cert, CertSnInfo *sn)
{
    X509_NAME *name = X509_get_subject_name(cert);
    if (name == NULL) {
        LOGE("subject name is NULL\n");
        return CF_ERR_CRYPTO_OPERATION;
    }
    CfResult ret = GetX509NameByNid(name, NID_commonName, &sn->cn);
    if (ret != CF_SUCCESS) { // CN must exist
        LOGE("Get X509 name cn failed, ret = %{public}d\n", ret);
        goto exit;
    }

    ret = GetX509NameByNid(name, NID_countryName, &sn->c);
    if (ret != CF_SUCCESS && ret != CF_ERR_EXTENSION_NOT_EXIST) {
        LOGE("Get X509 name c failed, ret = %{public}d\n", ret);
        goto exit;
    }

    ret = GetX509NameByNid(name, NID_organizationalUnitName, &sn->ou);
    if (ret != CF_SUCCESS && ret != CF_ERR_EXTENSION_NOT_EXIST) {
        LOGE("Get X509 name ou failed, ret = %{public}d\n", ret);
        goto exit;
    }

    ret = GetX509NameByNid(name, NID_organizationName, &sn->o);
    if (ret != CF_SUCCESS && ret != CF_ERR_EXTENSION_NOT_EXIST) {
        LOGE("Get X509 name o failed, ret = %{public}d\n", ret);
        goto exit;
    }
    return CF_SUCCESS;
exit:
    FreeSnInfo(sn);
    return ret;
}

static CfResult VerifySubCa(X509 *subCa, const HcfAttestCertVerifyParam *param)
{
    if (param == NULL || param->snInfos == NULL || param->snInfos->num == 0) {
        LOGE("snInfos is NULL\n");
        return CF_SUCCESS;
    }

    CertSnInfo snInfo = {0};
    CfResult ret = GetCertSn(subCa, &snInfo);
    if (ret != CF_SUCCESS) {
        LOGE("GetCertSn failed, ret = %{public}d\n", ret);
        return ret;
    }

    uint32_t i;
    for (i = 0; i < param->snInfos->num; i++) {
        CertSnInfo *snPattern = &param->snInfos->certSnInfos[i];
        if (CheckSn(snPattern, &snInfo) == CF_SUCCESS) {
            FreeSnInfo(&snInfo);
            return CF_SUCCESS;
        }
    }
    FreeSnInfo(&snInfo);
    return CF_ERR_PARAMETER_CHECK;
}

static CfResult CreateTrustedCerts(const HcfAttestCertVerifyParam *param, STACK_OF(X509) **trustedCerts)
{
    if (param != NULL && param->trustedCerts != NULL) {
        *trustedCerts = X509_chain_up_ref(param->trustedCerts);
        if (*trustedCerts == NULL) {
            return CF_ERR_CRYPTO_OPERATION;
        }
        return CF_SUCCESS;
    }

    STACK_OF(X509) *certs = sk_X509_new_null();
    if (certs == NULL) {
        return CF_ERR_CRYPTO_OPERATION;
    }

    const char *rootCa[] = {ROOT_CA, ROOT_G2_CA, EQUIPMENT_ROOT_CA};
    uint32_t rootCaNum = sizeof(rootCa) / sizeof(rootCa[0]);
    uint32_t i;
    ERR_clear_error();
    for (i = 0; i < rootCaNum; i++) {
        BIO *bio = BIO_new_mem_buf(rootCa[i], -1);
        if (bio == NULL) {
            break;
        }
        X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (cert == NULL) {
            BIO_free(bio);
            break;
        }
        if (sk_X509_push(certs, cert) <= 0) {
            BIO_free(bio);
            X509_free(cert);
            break;
        }
        BIO_free(bio);
    }
    // Record the error
    ProcessOpensslError(CF_ERR_CRYPTO_OPERATION);
    if ((uint32_t)sk_X509_num(certs) != rootCaNum) {
        sk_X509_pop_free(certs, X509_free);
        return CF_ERR_PARAMETER_CHECK;
    }

    *trustedCerts = certs;
    return CF_SUCCESS;
}

static CfResult ReadX509FromData(const CfEncodingBlob *encodingBlob, STACK_OF(X509) **certs)
{
    BIO *bio = BIO_new_mem_buf(encodingBlob->data, encodingBlob->len);
    if (bio == NULL) {
        return CF_ERR_CRYPTO_OPERATION;
    }
    STACK_OF(X509) *tmp = sk_X509_new_null();
    if (tmp == NULL) {
        BIO_free(bio);
        return CF_ERR_CRYPTO_OPERATION;
    }

    CfResult ret = CF_SUCCESS;
    uint32_t certNum = 0;

    ERR_clear_error();
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    while (cert != NULL) {
        if (sk_X509_push(tmp, cert) <= 0) {
            X509_free(cert);
            ret = CF_ERR_CRYPTO_OPERATION;
            break;
        }
        certNum++;
        if (certNum > MAX_CERT_NUM) {
            ret = CF_ERR_PARAMETER_CHECK;
            break;
        }
        cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    }
    // Record the error
    ProcessOpensslError(CF_ERR_CRYPTO_OPERATION);
    BIO_free(bio);
    if (ret != CF_SUCCESS) {
        sk_X509_pop_free(tmp, X509_free);
        return ret;
    }
    if (sk_X509_num(tmp) == 0) {
        sk_X509_pop_free(tmp, X509_free);
        return CF_ERR_PARAMETER_CHECK;
    }
    *certs = tmp;
    return ret;
}

static CfResult CreateCerts(const CfEncodingBlob *encodingBlob, STACK_OF(X509) **certs)
{
    STACK_OF(X509) *tmp = NULL;
    CfResult ret = ReadX509FromData(encodingBlob, &tmp);
    if (ret != CF_SUCCESS) {
        LOGE("ReadX509FromData failed, ret = %{public}d\n", ret);
        return ret;
    }

    if (sk_X509_num(tmp) < MIN_CERT_CHAIN_NUM || sk_X509_num(tmp) > MAX_CERT_CHAIN_NUM) {
        sk_X509_pop_free(tmp, X509_free);
        return CF_ERR_PARAMETER_CHECK;
    }

    *certs = tmp;
    return CF_SUCCESS;
}

static CfResult CalculateSha256(CfBlob *data1, CfBlob *data2, uint8_t *buf, uint32_t len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return CF_ERR_CRYPTO_OPERATION;
    }

    if (EVP_DigestInit(ctx, EVP_sha256()) != 1 ||
        EVP_DigestUpdate(ctx, data1->data, data1->size) != 1 ||
        EVP_DigestUpdate(ctx, data2->data, data2->size) != 1 ||
        EVP_DigestFinal(ctx, buf, &len)!= 1) {
        EVP_MD_CTX_free(ctx);
        return CF_ERR_CRYPTO_OPERATION;
    }

    EVP_MD_CTX_free(ctx);
    return CF_SUCCESS;
}

static bool Uint8ArrayCmp(uint8_t *data1, uint32_t len1, uint8_t *data2, uint32_t len2)
{
    if (len1 != len2) {
        return false;
    }

    if (memcmp(data1, data2, len1) != 0) {
        return false;
    }
    return true;
}

void AttestInfoFree(HmAttestationInfo *info)
{
    if (info == NULL) {
        return;
    }

    if (info->type == HM_ATTEST_TYPE_STANDARD) {
        FreeHmAttestationRecord(info->attestationRecord);
    }
    if (info->type == HM_ATTEST_TYPE_LEGACY) {
        FreeHmKeyDescription(info->legacyKeyDescription);
    }

    if (info->trustedChain != NULL) {
        sk_X509_pop_free(info->trustedChain, X509_free);
    }

    FreeAttestationDevSecLevel(info->attestationDevSecLevel);
    FreeDeviveActiveCertExt(info->deviveActiveCertExt);
    CfFree(info);
}

static CfResult ParseAttestationCert(X509 *cert, HmAttestationInfo *info)
{
    AttestationRecord *attestationRecord = NULL;
    CfResult ret = GetHmAttestationRecord(cert, &attestationRecord);
    if (ret == CF_SUCCESS) {
        info->type = HM_ATTEST_TYPE_STANDARD;
        info->attestationRecord = attestationRecord;
        return CF_SUCCESS;
    }

    if (ret != CF_ERR_EXTENSION_NOT_EXIST) {
        LOGE("GetHmAttestationRecord failed, ret = %{public}d\n", ret);
        return ret;
    }

    LegacyKeyDescription *desc = NULL;
    ret = GetHmKeyDescription(cert, &desc);
    if (ret == CF_SUCCESS) {
        info->type = HM_ATTEST_TYPE_LEGACY;
        info->legacyKeyDescription = desc;
        return CF_SUCCESS;
    }

    if (ret != CF_ERR_EXTENSION_NOT_EXIST) {
        LOGE("GetHmKeyDescription failed, ret = %{public}d\n", ret);
        return ret;
    }

    return ret;
}

static CfResult ParseDeviceCert(X509 *deviceCert, HmAttestationInfo *info)
{
    DeviceCertSecureLevel *level = NULL;
    AttestationRecord *devActRecord = NULL;
    CfResult ret = GetDeviceCertSecureLevel(deviceCert, &level);
    if (ret != CF_SUCCESS && ret != CF_ERR_EXTENSION_NOT_EXIST) {
        LOGE("GetDeviceCertSecureLevel failed, ret = %{public}d\n", ret);
        return ret;
    }

    if (ret == CF_SUCCESS) {
        int version = -1;
        int secLevel = -1;
        ret = GetDeviceSecureLevel(level, &version, &secLevel);
        if (version != 0 && version != 1) {
            LOGE("version is invalid, version = %{public}d\n", version);
            ret = CF_ERR_INVALID_EXTENSION;
            goto exit;
        }

        if (secLevel < DEVICE_SECURITY_LEVEL_MIN || secLevel > DEVICE_SECURITY_LEVEL_MAX) {
            LOGE("secLevel is invalid, secLevel = %{public}d\n", secLevel);
            ret = CF_ERR_INVALID_EXTENSION;
            goto exit;
        }
    }

    ret = GetDeviceActivationCertExt(deviceCert, &devActRecord);
    if (ret != CF_SUCCESS && ret != CF_ERR_EXTENSION_NOT_EXIST) {
        LOGE("GetDeviceActivationCertExt failed, ret = %{public}d\n", ret);
        goto exit;
    }

    info->attestationDevSecLevel = level;
    info->deviveActiveCertExt = devActRecord;
    return CF_SUCCESS;
exit:
    FreeAttestationDevSecLevel(level);
    return ret;
}

static CfResult CheckCertsOrder(STACK_OF(X509) *certs, STACK_OF(X509) *chain)
{
    int num1 = sk_X509_num(certs);
    int num2 = sk_X509_num(chain);
    if (num2 < MIN_CERT_CHAIN_NUM) {
        LOGE("Incorrect number of chain, num2 = %{public}d\n", num2);
        return CF_ERR_PARAMETER_CHECK;
    }

    if (num1 != num2 && (num1 + 1) != num2) {
        LOGE("Incorrect number of chain, num1 = %{public}d, num2 = %{public}d\n", num1, num2);
        return CF_ERR_PARAMETER_CHECK;
    }

    int i;
    for (i = 0; i < num1; i++) {
        if (X509_cmp(sk_X509_value(certs, i), sk_X509_value(chain, i)) != 0) {
            LOGE("Wrong certificate order\n");
            return CF_ERR_PARAMETER_CHECK;
        }
    }
    return CF_SUCCESS;
}

static CfResult VerifyAttestCerts(const CfEncodingBlob *encodingBlob, const HcfAttestCertVerifyParam *param,
    STACK_OF(X509) **out)
{
    STACK_OF(X509) *certs = NULL;
    STACK_OF(X509) *trustedCerts = NULL;
    STACK_OF(X509) *chain = NULL;
    CfResult ret = CreateCerts(encodingBlob, &certs);
    if (ret != CF_SUCCESS) {
        LOGE("CreateCerts failed, ret = %{public}d\n", ret);
        goto exit;
    }
    ret = CreateTrustedCerts(param, &trustedCerts);
    if (ret != CF_SUCCESS) {
        LOGE("CreateTrustedCerts failed, ret = %{public}d\n", ret);
        goto exit;
    }
    ret = VerifyCerts(certs, trustedCerts, param, &chain);
    if (ret != CF_SUCCESS) {
        LOGE("VerifyCerts failed, ret = %{public}d\n", ret);
        goto exit;
    }
    ret = CheckCertsOrder(certs, chain);
    if (ret != CF_SUCCESS) {
        LOGE("VerifyCerts failed, ret = %{public}d\n", ret);
        goto exit;
    }
    *out = chain;
    chain = NULL;
exit:
    sk_X509_pop_free(certs, X509_free);
    sk_X509_pop_free(trustedCerts, X509_free);
    if (chain != NULL) {
        sk_X509_pop_free(chain, X509_free);
    }
    return ret;
}

CfResult AttestCertVerify(const CfEncodingBlob *encodingBlob, const HcfAttestCertVerifyParam *param,
    HmAttestationInfo **info)
{
    if (encodingBlob == NULL || info == NULL) {
        return CF_NULL_POINTER;
    }

    STACK_OF(X509) *chain = NULL;
    X509 *trustSubCa = NULL;
    HmAttestationInfo *tmp = NULL;

    CfResult ret = VerifyAttestCerts(encodingBlob, param, &chain);
    if (ret != CF_SUCCESS) {
        LOGE("AttestCertVerify failed, ret = %{public}d\n", ret);
        goto exit;
    }

    trustSubCa = sk_X509_value(chain, sk_X509_num(chain) - MIN_CERT_CHAIN_NUM);
    ret = VerifySubCa(trustSubCa, param);
    if (ret != CF_SUCCESS) {
        LOGE("VerifyCerts failed, ret = %{public}d\n", ret);
        goto exit;
    }

    tmp = (HmAttestationInfo *)CfMalloc(sizeof(HmAttestationInfo), 0);
    if (tmp == NULL) {
        LOGE("Malloc failed\n");
        ret = CF_ERR_MALLOC;
        goto exit;
    }

    tmp->type = HM_ATTEST_TYPE_UNKNOWN;
    tmp->hasParseExtension = false;
    tmp->trustedChain = chain;
    *info = tmp;
    tmp = NULL;
    chain = NULL;
    ret = CF_SUCCESS;
exit:
    ProcessOpensslError(ret);
    AttestInfoFree(tmp);
    if (chain != NULL) {
        sk_X509_pop_free(chain, X509_free);
    }
    return ret;
}

CfResult AttestCertParseExtension(HmAttestationInfo *info)
{
    if (info == NULL) {
        return CF_NULL_POINTER;
    }
    if (info->hasParseExtension == true) {
        return CF_SUCCESS;
    }

    if (info->trustedChain == NULL || sk_X509_num(info->trustedChain) < MIN_CERT_CHAIN_NUM) {
        return CF_ERR_PARAMETER_CHECK;
    }

    info->hasParseExtension = true;

    CfResult ret = ParseAttestationCert(sk_X509_value(info->trustedChain, 0), info);
    if (ret != CF_SUCCESS && ret != CF_ERR_EXTENSION_NOT_EXIST) {
        LOGE("ParseAttestationCert failed, ret = %{public}d\n", ret);
        ProcessOpensslError(ret);
        return ret;
    }

    ret = ParseDeviceCert(sk_X509_value(info->trustedChain, 1), info);
    if (ret != CF_SUCCESS && ret != CF_ERR_EXTENSION_NOT_EXIST) {
        LOGE("ParseDeviceCert failed, ret = %{public}d\n", ret);
        ProcessOpensslError(ret);
        return ret;
    }
    if (ret == CF_ERR_EXTENSION_NOT_EXIST) {
        ret = CF_SUCCESS;
    }
    return CF_SUCCESS;
}

CfResult AttestCheckBoundedWithUdId(HmAttestationInfo *info)
{
    if (info == NULL) {
        return CF_NULL_POINTER;
    }

    if (info->type != HM_ATTEST_TYPE_STANDARD) {
        return CF_ERR_EXTENSION_NOT_EXIST;
    }

    if (info->deviveActiveCertExt == NULL || info->data == NULL) {
        return CF_ERR_EXTENSION_NOT_EXIST;
    }

    HmAttestationCertExt deviceId1 = {0};
    HmAttestationCertExt nonce = {0};
    HmAttestationCertExt udid = {0};

    CfResult ret = GetAttestCertExt(info->deviveActiveCertExt, DEVICE_ACTIVATION_DEVICE_ID1, &deviceId1);
    if (ret != CF_SUCCESS) {
        LOGE("Get deviceId1 failed, ret = %{public}d\n", ret);
        return ret;
    }

    ret = GetAttestCertExt(info->attestationRecord, ATTESTATION_NONCE, &nonce);
    if (ret != CF_SUCCESS) {
        LOGE("Get nonce failed when check deviceId1, ret = %{public}d\n", ret);
        return ret;
    }

    ret = GetAttestCertExt(info->attestationRecord, ATTESTATION_UDID, &udid);
    if (ret != CF_SUCCESS) {
        LOGE("Get udid failed, ret = %{public}d\n", ret);
        return ret;
    }

    uint8_t nonceUdidHash[SHA256_DIGEST_LENGTH] = {0};
    ret = CalculateSha256(&udid.blob, &nonce.blob, nonceUdidHash, sizeof(nonceUdidHash));
    if (ret != CF_SUCCESS) {
        ProcessOpensslError(ret);
        LOGE("CalculateSha256 udid failed, ret = %{public}d\n", ret);
        return ret;
    }

    if (Uint8ArrayCmp(deviceId1.blob.data, deviceId1.blob.size, nonceUdidHash, SHA256_DIGEST_LENGTH) == false) {
        LOGE("deviceId1 is not equal to udid+nonce sha256\n");
        return CF_ERR_INVALID_EXTENSION;
    }

    return CF_SUCCESS;
}

CfResult AttestCheckBoundedWithSocid(HmAttestationInfo *info)
{
    if (info == NULL) {
        return CF_NULL_POINTER;
    }

    if (info->type != HM_ATTEST_TYPE_STANDARD) {
        return CF_ERR_EXTENSION_NOT_EXIST;
    }

    if (info->deviveActiveCertExt == NULL || info->data == NULL) {
        return CF_ERR_EXTENSION_NOT_EXIST;
    }

    HmAttestationCertExt deviceId2 = {0};
    HmAttestationCertExt nonce = {0};
    HmAttestationCertExt socId = {0};

    CfResult ret = GetAttestCertExt(info->deviveActiveCertExt, DEVICE_ACTIVATION_DEVICE_ID2, &deviceId2);
    if (ret != CF_SUCCESS) {
        LOGE("Get deviceId2 failed, ret = %{public}d\n", ret);
        return ret;
    }

    ret = GetAttestCertExt(info->attestationRecord, ATTESTATION_NONCE, &nonce);
    if (ret != CF_SUCCESS) {
        LOGE("Get nonce failed when check deviceId2, ret = %{public}d\n", ret);
        return ret;
    }

    ret = GetAttestCertExt(info->attestationRecord, ATTESTATION_SOCID, &socId);
    if (ret != CF_SUCCESS) {
        LOGE("Get socid failed, ret = %{public}d\n", ret);
        return ret;
    }

    uint8_t nonceSocidHash[SHA256_DIGEST_LENGTH] = {0};
    ret = CalculateSha256(&socId.blob, &nonce.blob, nonceSocidHash, sizeof(nonceSocidHash));
    if (ret != CF_SUCCESS) {
        ProcessOpensslError(ret);
        LOGE("CalculateSha256 socid failed, ret = %{public}d\n", ret);
        return ret;
    }

    if (Uint8ArrayCmp(deviceId2.blob.data, deviceId2.blob.size, nonceSocidHash, SHA256_DIGEST_LENGTH) == false) {
        LOGE("deviceId2 is not equal to socId+nonce sha256\n");
        return CF_ERR_INVALID_EXTENSION;
    }

    return CF_SUCCESS;
}

CfResult AttestGetCertExtension(HmAttestationInfo *info, HmAttestationCertExtType type, HmAttestationCertExt *ext)
{
    if (info == NULL || ext == NULL) {
        return CF_NULL_POINTER;
    }
    if (info->hasParseExtension == false) {
        return CF_ERR_SHOULD_NOT_CALL;
    }

    if (type == DEVICE_ACTIVATION_DEVICE_ID1 || type == DEVICE_ACTIVATION_DEVICE_ID2) {
        return GetAttestCertExt(info->deviveActiveCertExt, type, ext);
    }

    if (type >= ATTESTATION_KEY_PURPOSE && type < ATTESTATION_CERT_EXT_TYPE_MAX) {
        if (info->type != HM_ATTEST_TYPE_STANDARD) {
            return CF_ERR_EXTENSION_NOT_EXIST;
        }
        return GetAttestCertExt(info->attestationRecord, type, ext);
    }

    if (type >= LEGACY_VERSION && type < KM_TAG_TYPE_MAX) {
        if (info->type != HM_ATTEST_TYPE_LEGACY) {
            return CF_ERR_EXTENSION_NOT_EXIST;
        }
        return GetKeyDescriptionExt(info->legacyKeyDescription, type, ext);
    }
    return CF_ERR_PARAMETER_CHECK;
}

CfResult AttestCreateVerifyParam(HcfAttestCertVerifyParam **param)
{
    if (param == NULL) {
        return CF_NULL_POINTER;
    }
    *param = (HcfAttestCertVerifyParam *)CfMalloc(sizeof(HcfAttestCertVerifyParam), 0);
    if (*param == NULL) {
        LOGE("Malloc failed\n");
        return CF_ERR_MALLOC;
    }
    (*param)->checkTime = true;
    return CF_SUCCESS;
}

CfResult AttestSetVerifyParamCheckTime(HcfAttestCertVerifyParam *param, bool checkTime)
{
    if (param == NULL) {
        return CF_NULL_POINTER;
    }
    param->checkTime = checkTime;
    return CF_SUCCESS;
}

CfResult AttestSetVerifyParamRootCa(HcfAttestCertVerifyParam *param, const CfEncodingBlob *rootCa)
{
    if (param == NULL || rootCa == NULL) {
        return CF_NULL_POINTER;
    }
    if (param->trustedCerts != NULL) {
        return CF_ERR_SHOULD_NOT_CALL;
    }
    if (rootCa->data == NULL || rootCa->len == 0) {
        return CF_ERR_PARAMETER_CHECK;
    }
    STACK_OF(X509) *cas = NULL;
    CfResult ret = ReadX509FromData(rootCa, &cas);
    if (ret != CF_SUCCESS) {
        LOGE("ReadX509FromData failed, ret = %{public}d\n", ret);
        return ret;
    }

    param->trustedCerts = cas;
    return ret;
}

CfResult AttestSetVerifyParamSnInfos(HcfAttestCertVerifyParam *param, const HmAttestationSnInfo *snInfos)
{
    if (param == NULL || snInfos == NULL) {
        return CF_NULL_POINTER;
    }

    if (param->snInfos != NULL) {
        return CF_ERR_SHOULD_NOT_CALL;
    }

    param->snInfos = snInfos;
    return CF_SUCCESS;
}

void AttestFreeVerifyParam(HcfAttestCertVerifyParam *param)
{
    if (param == NULL) {
        return;
    }
    if (param->trustedCerts != NULL) {
        sk_X509_pop_free(param->trustedCerts, X509_free);
    }
    CfFree(param);
}
