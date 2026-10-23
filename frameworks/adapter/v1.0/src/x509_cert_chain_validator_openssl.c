/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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

static CfResult ConvertOpensslErrorMsg(int32_t errCode)
{
    for (uint32_t i = 0; i < sizeof(ERROR_TO_RESULT_MAP) / sizeof(OpensslErrorToResult); i++) {
        if (ERROR_TO_RESULT_MAP[i].errCode == errCode) {
            return ERROR_TO_RESULT_MAP[i].result;
        }
    }
    return CF_ERR_CRYPTO_OPERATION;
}

static CfResult ConvertOpensslErrorMsgEx(int32_t errCode)
{
    for (uint32_t i = 0; i < sizeof(ERROR_TO_RESULT_MAP_EX) / sizeof(OpensslErrorToResult); i++) {
        if (ERROR_TO_RESULT_MAP_EX[i].errCode == errCode) {
            return ERROR_TO_RESULT_MAP_EX[i].result;
        }
    }
    return ConvertOpensslErrorMsg(errCode);
}

static CfResult DownloadCertFromAiaUrl(const char *url, X509 **cert)
{
    ERR_clear_error();
    *cert = X509_load_http(url, NULL, NULL, DOWNLOAD_TIMEOUT_SECONDS);
    if (*cert != NULL) {
        LOGI("Cert download successful, URL: %{public}s", url);
        return CF_SUCCESS;
    }
    LOGW("Failed to download the cert, URL: %{public}s, errno: %{public}d", url, errno);
    unsigned long err = ERR_peek_error();
    int reason = ERR_GET_REASON(err);
    if (reason == BIO_R_CONNECT_TIMEOUT || reason == BIO_R_TRANSFER_TIMEOUT) {
        return CF_ERR_NETWORK_TIMEOUT;
    }
    return CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
}

static CfResult TryDownloadFromSingleAia(ACCESS_DESCRIPTION *ad, uint32_t *remainingCount, X509 **cert)
{
    if (ad == NULL || ad->method == NULL || ad->location == NULL || remainingCount == NULL) {
        return CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
    }
    if (OBJ_obj2nid(ad->method) != NID_ad_ca_issuers) {
        return CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
    }
    if (ad->location->type != GEN_URI) {
        return CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
    }
    ASN1_IA5STRING *uri = ad->location->d.uniformResourceIdentifier;
    if (uri == NULL || uri->data == NULL) {
        return CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
    }
    int len = ASN1_STRING_length(uri);
    if (len <= 0) {
        return CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
    }
    char *url = (char *)CfMallocEx(len + 1);
    if (url == NULL) {
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(url, len, uri->data, len);
    url[len] = '\0';

    (*remainingCount)--;
    CfResult res = DownloadCertFromAiaUrl(url, cert);
    CfFree(url);
    return res;
}

static const char *GetX509CertChainValidatorClass(void)
{
    return X509_CERT_CHAIN_VALIDATOR_OPENSSL_CLASS;
}

static void DestroyX509CertChainValidator(CfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Invalid params!");
        return;
    }
    if (!CfIsClassMatch(self, GetX509CertChainValidatorClass())) {
        LOGE("Class is not match.");
        return;
    }
    CfFree((HcfCertChainValidatorSpi *)self);
}

static CfResult InitX509Certs(const CfArray *certsList, CertsInfo **certs)
{
    uint32_t certsInfoLen = sizeof(CertsInfo) * certsList->count;
    CertsInfo *certsInfo = (CertsInfo *)CfMalloc(certsInfoLen, 0);
    if (certsInfo == NULL) {
        LOGE("Failed to new memory for cert info.");
        return CF_ERR_MALLOC;
    }
    for (uint32_t i = 0; i < certsList->count; ++i) {
        CertsInfo *info = &(certsInfo[i]);
        info->data = certsList->data[i].data;
        info->len = certsList->data[i].size;
    }
    *certs = certsInfo;
    return CF_SUCCESS;
}

static void FreeX509Certs(CertsInfo **certs, uint32_t certNum)
{
    if (certs == NULL) {
        LOGD("Input NULL certs, no need to free.");
        return;
    }
    for (uint32_t i = 0; i < certNum; ++i) {
        if ((*certs)[i].x509 != NULL) {
            X509_free((*certs)[i].x509);
            (*certs)[i].x509 = NULL;
        }
    }
    CfFree(*certs);
    *certs = NULL;
}

static X509 *GetX509Cert(const uint8_t *data, size_t len, enum CfEncodingFormat format)
{
    X509 *x509 = NULL;
    BIO *bio = BIO_new_mem_buf(data, len);
    if (bio == NULL) {
        LOGE("Failed to new memory for bio.");
        return NULL;
    }

    if (format == CF_FORMAT_DER) {
        x509 = d2i_X509_bio(bio, NULL);
    } else if (format == CF_FORMAT_PEM) {
        x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    }

    BIO_free(bio);
    return x509;
}

static CfResult ValidateCertChainInner(CertsInfo *certs, uint32_t certNum)
{
    CfResult res = CF_SUCCESS;
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *verifyCtx = X509_STORE_CTX_new();
    do {
        if ((store == NULL) || (verifyCtx == NULL)) {
            LOGE("Failed to verify cert chain init.");
            res = CF_ERR_MALLOC;
            break;
        }

        for (uint32_t i = certNum - 1; i > 0; i--) { // certs[certNum - 1] represents the 0th cert.
            if (X509_STORE_add_cert(store, certs[i].x509) != CF_OPENSSL_SUCCESS) {
                LOGE("Failed to add cert to store.");
                CfPrintOpensslError();
                res = CF_ERR_MALLOC;
                break;
            }
        }
        if (res != CF_SUCCESS) {
            break;
        }
        /* Do not check cert validity against current time. */
        X509_STORE_set_flags(store, X509_V_FLAG_NO_CHECK_TIME);
        int32_t resOpenssl = X509_STORE_CTX_init(verifyCtx, store, certs[0].x509, NULL);
        if (resOpenssl != CF_OPENSSL_SUCCESS) {
            LOGE("Failed to init verify ctx.");
            res = CF_ERR_CRYPTO_OPERATION;
            CfPrintOpensslError();
            break;
        }
        resOpenssl = X509_verify_cert(verifyCtx);
        if (resOpenssl != CF_OPENSSL_SUCCESS) {
            int32_t errCode = X509_STORE_CTX_get_error(verifyCtx);
            const char *pChError = X509_verify_cert_error_string(errCode);
            LOGE("Failed to verify cert, openssl openssl error code = %{public}d, error msg:%{public}s.",
                errCode, pChError);
            res = ConvertOpensslErrorMsg(errCode);
            break;
        }
    } while (0);

    if (verifyCtx != NULL) {
        X509_STORE_CTX_free(verifyCtx);
    }
    if (store != NULL) {
        X509_STORE_free(store);
    }
    return res;
}

static CfResult ValidateCertChain(CertsInfo *certs, uint32_t certNum, enum CfEncodingFormat format)
{
    for (uint32_t i = 0; i < certNum; ++i) {
        X509 *x509 = GetX509Cert(certs[i].data, certs[i].len, format);
        if (x509 == NULL) {
            LOGE("Failed to convert cert blob to x509.");
            return CF_ERR_CRYPTO_OPERATION; /* X509 will be freed by caller func. */
        }
        certs[i].x509 = x509;
    }
    return ValidateCertChainInner(certs, certNum);
}

static CfResult Validate(HcfCertChainValidatorSpi *self, const CfArray *certsList)
{
    if ((self == NULL) || (certsList == NULL) || (certsList->count <= 1)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetX509CertChainValidatorClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    CertsInfo *certs = NULL;
    CfResult res = InitX509Certs(certsList, &certs);
    if (res != CF_SUCCESS) {
        LOGE("Failed to init certs, res = %{public}d.", res);
        return res;
    }
    res = ValidateCertChain(certs, certsList->count, certsList->format);
    if (res != CF_SUCCESS) {
        LOGE("Failed to validate cert chain, res = %{public}d.", res);
    }
    FreeX509Certs(&certs, certsList->count);
    return res;
}

static char *GetCertSubjectName(X509 *cert, char *buf, int bufLen)
{
    if (cert == NULL) {
        return NULL;
    }
    X509_NAME *subjectName = X509_get_subject_name(cert);
    if (subjectName == NULL) {
        return NULL;
    }
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        return NULL;
    }
    char *result = NULL;
    int ret = X509_NAME_print_ex(bio, subjectName, 0, XN_FLAG_SEP_COMMA_PLUS | ASN1_STRFLGS_UTF8_CONVERT);
    if (ret > 0) {
        int len = BIO_get_mem_data(bio, NULL);
        if (len <= 0) {
            return NULL;
        }
        len = len > bufLen ? bufLen : len;
        len--;
        ret = BIO_read(bio, buf, len);
        if (ret > 0) {
            buf[ret] = '\0';
            result = buf;
        }
    }
    BIO_free(bio);
    return result;
}

static void AppendCertSubjectToErrorMsg(X509 *cert, CertVerifyResultInner *result)
{
    if (result->errorMsg == NULL) {
        return;
    }

    char subjectNameBuf[MAX_SUBJECT_NAME_LEN] = {0};
    char *subjectName = GetCertSubjectName(cert, subjectNameBuf, MAX_SUBJECT_NAME_LEN);
    if (subjectName == NULL) {
        return;
    }

    const char *prefix = " | current cert subject name: ";
    if ((strlen(result->errorMsg) + strlen(subjectName) + strlen(prefix) + 1) > MAX_ERROR_MSG_BUF_LEN) {
        return;
    }

    uint32_t len = 0;
    (void)memcpy_s(result->errorMsgBuf, sizeof(result->errorMsgBuf), result->errorMsg, strlen(result->errorMsg));
    len += strlen(result->errorMsg);
    (void)memcpy_s(result->errorMsgBuf + len, sizeof(result->errorMsgBuf) - len, prefix, strlen(prefix));
    len += strlen(prefix);
    (void)memcpy_s(result->errorMsgBuf + len, sizeof(result->errorMsgBuf) - len, subjectName, strlen(subjectName));
    len += strlen(subjectName);
    result->errorMsgBuf[len] = '\0';
    result->errorMsg = result->errorMsgBuf;
}

static void SetVerifyErrorMsg(HcfCertVerifyResult *result, const char *msg)
{
    if (result == NULL || msg == NULL || result->error != NULL) {
        return;
    }
    HcfCertVerifyErrorResult *error = (HcfCertVerifyErrorResult *)CfMallocEx(sizeof(HcfCertVerifyErrorResult));
    if (error == NULL) {
        return;
    }
    (void)memset_s(error, sizeof(HcfCertVerifyErrorResult), 0, sizeof(HcfCertVerifyErrorResult));
    uint32_t len = (uint32_t)strlen(msg) + 1;
    error->errorMsg = (char *)CfMallocEx(len);
    if (error->errorMsg == NULL) {
        CfFree(error);
        return;
    }
    (void)memcpy_s(error->errorMsg, len, msg, len);
    result->error = error;
}

static void CopyVerifyErrorMsg(const CertVerifyResultInner *inner, HcfCertVerifyResult *result)
{
    if (inner->errorMsg == NULL) {
        return;
    }
    SetVerifyErrorMsg(result, inner->errorMsg);
    if (result->error == NULL || inner->revokedCert == NULL) {
        return;
    }

    HcfCertRevocationInfo *info = (HcfCertRevocationInfo *)CfMallocEx(sizeof(HcfCertRevocationInfo));
    if (info == NULL) {
        return;
    }
    (void)memset_s(info, sizeof(HcfCertRevocationInfo), 0, sizeof(HcfCertRevocationInfo));
    info->usedMethod = inner->usedMethod;
    info->revocationReason = inner->revocationReason;
    (void)memcpy_s(info->revocationTime, sizeof(info->revocationTime),
        inner->revocationTime, sizeof(info->revocationTime));

    X509 *revokedX509 = inner->revokedCert;
    if (X509ToHcfX509Certificate(revokedX509, &info->cert) != CF_SUCCESS) {
        info->cert = NULL;
    }
    result->error->revocationInfo = info;
}

static CfResult CheckSingleCertRevocation(X509 *cert,
    const HcfX509CertValidatorParams *params,
    HcfX509CertValidatorOpenSSLParams *opensslParams, CertVerifyResultInner *result);

static CfResult GetIssuerFromStore(X509 *cert, X509_STORE *store,
    X509 **issuer, CertVerifyResultInner *result);

static CfResult CheckKeyUsage(X509 *x509, const HcfX509CertValidatorParams *params, CertVerifyResultInner *result)
{
    if (params->keyUsage.count == 0) {
        return CF_SUCCESS;
    }
    uint32_t keyUsage = X509_get_key_usage(x509);
    for (uint32_t i = 0; i < params->keyUsage.count; i++) {
        int32_t kuType = params->keyUsage.data[i];
        if (kuType < 0 || (uint32_t)kuType >= MAX_KEYUSAGE_COUNT) {
            RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK, "Invalid key usage type.", result);
        }
        uint32_t kuBit = KEYUSAGE_TO_OPENSSL_MAP[kuType];
        if (!(keyUsage & kuBit)) {
            RETURN_VERIFY_ERROR(CF_ERR_CERT_KEY_USAGE_MISMATCH,
                "The certificate key usage is not matched.", result);
        }
    }
    return CF_SUCCESS;
}

static CfResult CheckHostnames(X509 *x509, const HcfX509CertValidatorParams *params, CertVerifyResultInner *result)
{
    if (params->hostnames.count == 0) {
        return CF_SUCCESS;
    }
    for (uint32_t i = 0; i < params->hostnames.count; i++) {
        if (X509_check_host(x509, params->hostnames.data[i], strlen(params->hostnames.data[i]), 0, NULL) == 1) {
            return CF_SUCCESS;
        }
    }
    RETURN_VERIFY_ERROR(CF_ERR_CERT_HOST_NAME_MISMATCH,
        "The certificate hostname is not matched.", result);
}

static CfResult CheckEmailAddresses(X509 *x509, const HcfX509CertValidatorParams *params, CertVerifyResultInner *result)
{
    if (params->emailAddresses.count == 0) {
        return CF_SUCCESS;
    }
    for (uint32_t i = 0; i < params->emailAddresses.count; i++) {
        if (X509_check_email(x509, params->emailAddresses.data[i],
            strlen(params->emailAddresses.data[i]), 0) == 1) {
            return CF_SUCCESS;
        }
    }
    RETURN_VERIFY_ERROR(CF_ERR_CERT_EMAIL_MISMATCH,
        "The certificate email address is not matched.", result);
}

static CfResult CheckCertValidatorExtensions(X509 *x509, const HcfX509CertValidatorParams *params,
    const HcfX509CertValidatorOpenSSLParams *opensslParams, CertVerifyResultInner *result)
{
    CfResult res = CheckKeyUsage(x509, params, result);
    if (res != CF_SUCCESS) {
        return res;
    }

    res = CheckHostnames(x509, params, result);
    if (res != CF_SUCCESS) {
        return res;
    }

    res = CheckEmailAddresses(x509, params, result);
    if (res != CF_SUCCESS) {
        return res;
    }

    res = CheckIpAddresses(x509, params, result);
    if (res != CF_SUCCESS) {
        return res;
    }

    res = CheckExtendedKeyUsage(x509, params, result);
    if (res != CF_SUCCESS) {
        return res;
    }
    return CF_SUCCESS;
}

static CfResult GetX509FromHcfCertificate(const HcfCertificate *hcfCert, X509 **cert, bool isDup,
    CertVerifyResultInner *result)
{
    X509 *cert0 = GetX509FromHcfX509Certificate(hcfCert);
    if (cert0 == NULL) {
        RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK, "Failed to obtain the certificate to be verified.", result);
    }
    if (!isDup) {
        *cert = cert0;
        return CF_SUCCESS;
    }

    *cert = X509_dup(cert0);
    if (*cert == NULL) {
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Call X509_dup failed.", result);
    }
    return CF_SUCCESS;
}

static CfResult ConstructUntrustedStack(const HcfX509CertValidatorParams *params, STACK_OF(X509) **untrustedStack,
    bool isDup, CertVerifyResultInner *result)
{
    STACK_OF(X509) *tmpStack = sk_X509_new_null();
    if (tmpStack == NULL) {
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Call sk_X509_new_null failed.", result);
    }
    for (uint32_t i = 0; i < params->untrustedCerts.count; i++) {
        X509 *untrustedX509 = NULL;
        CfResult ret = GetX509FromHcfCertificate((HcfCertificate *)params->untrustedCerts.data[i], &untrustedX509,
            isDup, result);
        if (ret != CF_SUCCESS) {
            sk_X509_pop_free(tmpStack, X509_free);
            return ret;
        }
        if (!isDup) {
            if (X509_up_ref(untrustedX509) != 1) {
                sk_X509_pop_free(tmpStack, X509_free);
                RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Call X509_up_ref failed.", result);
            }
        }

        if (!sk_X509_push(tmpStack, untrustedX509)) {
            sk_X509_pop_free(tmpStack, X509_free);
            X509_free(untrustedX509);
            RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Call sk_X509_push failed.", result);
        }
    }
    *untrustedStack = tmpStack;
    return CF_SUCCESS;
}

static CfResult ConstructTrustedStore(const HcfX509CertValidatorParams *params, X509_STORE **store, bool isDup,
    CertVerifyResultInner *result)
{
    X509_STORE *storeTmp = X509_STORE_new();
    if (storeTmp == NULL) {
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Call X509_STORE_new failed.", result);
    }

    for (uint32_t i = 0; i < params->trustedCerts.count; i++) {
        X509 *cert = NULL;
        CfResult ret = GetX509FromHcfCertificate((HcfCertificate *)params->trustedCerts.data[i], &cert, isDup, result);
        if (ret != CF_SUCCESS) {
            X509_STORE_free(storeTmp);
            return ret;
        }
        int res = X509_STORE_add_cert(storeTmp, cert);
        if (isDup) {
            X509_free(cert);
        }
        if (res != 1) {
            X509_STORE_free(storeTmp);
            RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Call X509_STORE_add_cert failed.", result);
        }
    }

    if (params->trustSystemCa) {
        int loadRet = X509_STORE_load_locations(storeTmp, NULL, CERT_VERIFY_DIR);
        if (loadRet != 1) {
            X509_STORE_free(storeTmp);
            RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Set CERT_VERIFY_DIR failed.", result);
        }
        loadRet = X509_STORE_load_locations(storeTmp, NULL, SYSTEM_GM_CERT_DIR);
        if (loadRet != 1) {
            X509_STORE_free(storeTmp);
            RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Set SYSTEM_GM_CERT_DIR failed.", result);
        }
    }

    for (uint32_t i = 0; i < params->trustCertPath.count; i++) {
        const char *path = params->trustCertPath.data[i];
        if (path == NULL) {
            continue;
        }
        int loadRet = X509_STORE_load_locations(storeTmp, NULL, path);
        if (loadRet != 1) {
            X509_STORE_free(storeTmp);
            RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Call X509_STORE_load_locations for trustCertPath failed.",
                result);
        }
    }
    *store = storeTmp;
    return CF_SUCCESS;
}

static CfResult BuildSystemCaStore(X509_STORE **store, CertVerifyResultInner *result)
{
    X509_STORE *storeTmp = X509_STORE_new();
    if (storeTmp == NULL) {
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Call X509_STORE_new failed when build system CA store.", result);
    }
    if (X509_STORE_load_locations(storeTmp, NULL, CERT_VERIFY_DIR) != 1 ||
        X509_STORE_load_locations(storeTmp, NULL, SYSTEM_GM_CERT_DIR) != 1) {
        X509_STORE_free(storeTmp);
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Load system CA dir failed.", result);
    }
    *store = storeTmp;
    return CF_SUCCESS;
}

bool IsTrustAnchorSystemCa(STACK_OF(X509) *certChain, X509_STORE *systemCaStore)
{
    if (certChain == NULL || systemCaStore == NULL) {
        return false;
    }
    int num = sk_X509_num(certChain);
    if (num <= 0) {
        return false;
    }
    X509 *anchor = sk_X509_value(certChain, num - 1);
    if (anchor == NULL) {
        return false;
    }
    STACK_OF(X509_OBJECT) *objs = X509_STORE_get0_objects(systemCaStore);
    if (objs == NULL) {
        return false;
    }
    int objNum = sk_X509_OBJECT_num(objs);
    for (int i = 0; i < objNum; i++) {
        X509_OBJECT *obj = sk_X509_OBJECT_value(objs, i);
        if (obj == NULL || X509_OBJECT_get_type(obj) != X509_LU_X509) {
            continue;
        }
        X509 *ca = X509_OBJECT_get0_X509(obj);
        if (ca != NULL && X509_cmp(anchor, ca) == 0) {
            return true;
        }
    }
    return false;
}

static CfResult ConvertTimeStrToTimeT(const char *timeStr, time_t *result, CertVerifyResultInner *resultInner)
{
    struct tm tm;
    time_t ret = 0;
    ASN1_TIME *asn1Time = ASN1_TIME_new();
    if (asn1Time == NULL) {
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Call ASN1_TIME_new failed.", resultInner);
    }

    if (ASN1_TIME_set_string(asn1Time, timeStr) != 1) {
        ASN1_TIME_free(asn1Time);
        RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK, "Invalid time string.", resultInner);
    }

    if (ASN1_TIME_to_tm(asn1Time, &tm) != 1) {
        ASN1_TIME_free(asn1Time);
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Call ASN1_TIME_to_tm failed.", resultInner);
    }
    ASN1_TIME_free(asn1Time);

    ret = timegm(&tm);
    if (ret == -1) {
        LOGE("Call timegm failed, errno = %{public}d.", errno);
        RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK, "Call timegm failed.", resultInner);
    }
    *result = ret;
    return CF_SUCCESS;
}

static void FreeOpenSSLParams(HcfX509CertValidatorOpenSSLParams *opensslParams)
{
    if (opensslParams == NULL) {
        return;
    }
    /* Note: opensslParams->cert is obtained from GetX509FromHcfX509Certificate which doesn't increment
     * refcount. The original HcfX509Certificate owns this reference, so we should NOT free it here. */
    if (opensslParams->certDup) {
        X509_free(opensslParams->cert);
    }
    opensslParams->cert = NULL;
    if (opensslParams->store != NULL) {
        X509_STORE_free(opensslParams->store);
        opensslParams->store = NULL;
    }
    if (opensslParams->untrustedCertStack != NULL) {
        sk_X509_pop_free(opensslParams->untrustedCertStack, X509_free);
        opensslParams->untrustedCertStack = NULL;
    }
    if (opensslParams->systemCaStore != NULL) {
        X509_STORE_free(opensslParams->systemCaStore);
        opensslParams->systemCaStore = NULL;
    }
}

static CfResult ParseIgnoreErrs(const HcfX509CertValidatorParams *params,
    HcfX509CertValidatorOpenSSLParams *opensslParams, CertVerifyResultInner *resultInner)
{
    if (params->ignoreErrs.data == NULL || params->ignoreErrs.count == 0) {
        return CF_SUCCESS;
    }
    if (params->ignoreErrs.count > MAX_IGNORE_ERR_COUNT) {
        RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK, "Invalid ignoreErrs count, max count is 8.", resultInner);
    }
    opensslParams->ignoreOcspRespNotFound = false;
    opensslParams->ignoreNetworkTimeout = false;
    uint32_t pos = 0;
    for (uint32_t i = 0; i < params->ignoreErrs.count; i++) {
        if (params->ignoreErrs.data[i] == OCSP_RESPONSE_NOT_FOUND) {
            opensslParams->ignoreOcspRespNotFound = true;
            continue;
        }
        if (params->ignoreErrs.data[i] == NETWORK_TIMEOUT) {
            opensslParams->ignoreNetworkTimeout = true;
            continue;
        }
        uint32_t j;
        for (j = 0; j < sizeof(X509_VERIFY_IGNORE_ERR_MAP) / sizeof(X509_VERIFY_IGNORE_ERR_MAP[0]); j++) {
            if (params->ignoreErrs.data[i] == X509_VERIFY_IGNORE_ERR_MAP[j].result) {
                opensslParams->ignoreErrs[pos++] = X509_VERIFY_IGNORE_ERR_MAP[j].errCode;
                break;
            }
        }
        if (j == sizeof(X509_VERIFY_IGNORE_ERR_MAP) / sizeof(X509_VERIFY_IGNORE_ERR_MAP[0])) {
            RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK, "Invalid ignoreErrs, only support CERT_NOT_YET_VALID, "\
                "CERT_HAS_EXPIRED, CRL_NOT_YET_VALID, CRL_HAS_EXPIRED, CRL_NOT_FOUND, "\
                "CERT_UNKNOWN_CRITICAL_EXTENSION, OCSP_RESPONSE_NOT_FOUND and NETWORK_TIMEOUT.", resultInner);
        }
    }
    opensslParams->ignoreErrs[pos] = 0;
    return CF_SUCCESS;
}

static bool HasRevocationFlag(const HcfX509CertRevokedParams *revo, int32_t flag);

static void SetupRevocationCache(const HcfX509CertValidatorParams *params,
    HcfX509CertValidatorOpenSSLParams *opensslParams, CertVerifyResultInner *result)
{
    if (params->revokedParams != NULL && params->revokedParams->enableRevocationCache && params->trustSystemCa) {
        CfResult ret = BuildSystemCaStore(&opensslParams->systemCaStore, result);
        if (ret == CF_SUCCESS) {
            opensslParams->cacheEnabled = true;
        } else {
            opensslParams->cacheEnabled = false;
            opensslParams->systemCaStore = NULL;
        }
    }
}

static CfResult ParseOpenSSLParams(const HcfX509Certificate *x509Cert, const HcfX509CertValidatorParams *params,
    HcfX509CertValidatorOpenSSLParams *opensslParams, CertVerifyResultInner *result)
{
    if (params->userId.data != NULL && params->userId.size != 0) {
        opensslParams->certDup = true;
    }

    /* Get X509 from HcfX509Certificate */
    CfResult ret = GetX509FromHcfCertificate((HcfCertificate *)x509Cert, &opensslParams->cert, opensslParams->certDup,
        result);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    /* Construct trusted store */
    ret = ConstructTrustedStore(params, &opensslParams->store, opensslParams->certDup, result);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    /* Construct untrusted cert stack */
    ret = ConstructUntrustedStack(params, &opensslParams->untrustedCertStack, opensslParams->certDup, result);
    if (ret != CF_SUCCESS) {
        LOGE("Failed to construct untrusted stack.");
        return ret;
    }

    /* Parse date if needed */
    if (params->validateDate && params->date != NULL) {
        ret = ConvertTimeStrToTimeT(params->date, &opensslParams->date, result);
        if (ret != CF_SUCCESS) {
            LOGE("Failed to convert date string to time_t.");
            return ret;
        }
    }

    /* Parse revocation check flags if revokedParams exists */
    if (params->revokedParams != NULL) {
        opensslParams->crlCheck = HasRevocationFlag(params->revokedParams, CERT_REVOCATION_CRL_CHECK);
        opensslParams->ocspCheck = HasRevocationFlag(params->revokedParams, CERT_REVOCATION_OCSP_CHECK);
        opensslParams->preferOcsp = HasRevocationFlag(params->revokedParams, CERT_REVOCATION_PREFER_OCSP);
        opensslParams->revocationCheckAll = HasRevocationFlag(params->revokedParams, CERT_REVOCATION_CHECK_ALL_CERT);
        if (!opensslParams->crlCheck && !opensslParams->ocspCheck) {
            RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK,
                "If enabling revocation checking CERT_REVOCATION_CRL_CHECK or CERT_REVOCATION_OCSP_CHECK must be set.",
                result);
        }
    }

    /* Parse ignoreErrs */
    if (params->ignoreErrs.data != NULL && params->ignoreErrs.count != 0) {
        ret = ParseIgnoreErrs(params, opensslParams, result);
        if (ret != CF_SUCCESS) {
            return ret;
        }
    }

    /* Revocation cache: parameter-level enable condition */
    SetupRevocationCache(params, opensslParams, result);
    return CF_SUCCESS;
}

static CfResult DownloadAndAddIntermediateCert(X509 *lastCert, STACK_OF(X509) *untrustedStack,
    CertVerifyResultInner *result)
{
    AUTHORITY_INFO_ACCESS *infoAccess = X509_get_ext_d2i(lastCert, NID_info_access, NULL, NULL);
    if (infoAccess == NULL) {
        RETURN_VERIFY_ERROR(CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, "No AIA extension found in certificate.",
            result);
    }

    X509 *downloadedCert = NULL;
    CfResult res = CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
    int num = sk_ACCESS_DESCRIPTION_num(infoAccess);
    if (num <= 0) {
        AUTHORITY_INFO_ACCESS_free(infoAccess);
        RETURN_VERIFY_ERROR(CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, "No AIA extension found in certificate.",
            result);
    }
    uint32_t remainingCount = MAX_INFO_ACCESS_TRAVERSE_COUNT;
    for (int i = 0; i < num && remainingCount > 0; i++) {
        ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(infoAccess, i);
        res = TryDownloadFromSingleAia(ad, &remainingCount, &downloadedCert);
        if (res == CF_SUCCESS || res == CF_ERR_MALLOC) {
            break;
        }
    }
    AUTHORITY_INFO_ACCESS_free(infoAccess);
    if (res == CF_SUCCESS) {
        if (!sk_X509_push(untrustedStack, downloadedCert)) {
            X509_free(downloadedCert);
            RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to add downloaded certificate to stack.", result);
        }
        return CF_SUCCESS;
    } else if (res == CF_ERR_MALLOC) {
        RETURN_VERIFY_ERROR(CF_ERR_MALLOC, "Failed to malloc when downloaded certificate.", result);
    } else if (res == CF_ERR_NETWORK_TIMEOUT) {
        RETURN_VERIFY_ERROR(CF_ERR_NETWORK_TIMEOUT, "Network timeout when downloading intermediate certificate.",
            result);
    } else {
        RETURN_VERIFY_ERROR(res, "Failed to download intermediate certificate from AIA.", result);
    }
}

static CfResult SetUserId(X509_STORE_CTX *verifyCtx)
{
    STACK_OF(X509) *chain = X509_STORE_CTX_get0_chain(verifyCtx);
    if (chain == NULL) {
        return CF_SUCCESS;
    }

    CfBlob *userId = (CfBlob *)X509_STORE_CTX_get_app_data(verifyCtx);
    if (userId == NULL) {
        return CF_SUCCESS;
    }
    if (userId->data == NULL || userId->size == 0) {
        return CF_SUCCESS;
    }

    CertVerifyResultInner *result = (CertVerifyResultInner *)X509_STORE_CTX_get_ex_data(verifyCtx, 1);
    if (result == NULL) {
        return CF_SUCCESS;
    }

    for (int i = 0; i < sk_X509_num(chain); i++) {
        X509 *cert = sk_X509_value(chain, i);
        if (X509_get0_distinguishing_id(cert) != NULL) {
            continue;
        }
        ASN1_OCTET_STRING *v = ASN1_OCTET_STRING_new();
        if (v == NULL) {
            RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "ASN1_OCTET_STRING_new failed when set user id.", result);
        }
        if (ASN1_OCTET_STRING_set(v, (unsigned char *)userId->data, (int)userId->size) != 1) {
            ASN1_OCTET_STRING_free(v);
            RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "ASN1_OCTET_STRING_set failed when set user id.", result);
        }
        X509_set0_distinguishing_id(cert, v);
    }
    return CF_SUCCESS;
}

static int VerifyCallback(int ret, X509_STORE_CTX *verifyCtx)
{
    CfResult cfRet = SetUserId(verifyCtx);
    if (cfRet != CF_SUCCESS) {
        return 0;
    }

    if (ret == 1) {
        return 1;
    }
    HcfX509CertValidatorOpenSSLParams *opensslParams =
        (HcfX509CertValidatorOpenSSLParams *)X509_STORE_CTX_get_ex_data(verifyCtx, USER_DATA_INDEX);
    if (opensslParams == NULL) {
        return ret;
    }
    int certVerifyResult = X509_STORE_CTX_get_error(verifyCtx);

    for (int i = 0; opensslParams->ignoreErrs[i] != 0; i++) {
        if (certVerifyResult == opensslParams->ignoreErrs[i]) {
            const char *errStr = X509_verify_cert_error_string(certVerifyResult);
            char subjectName[MAX_SUBJECT_NAME_LEN] = {0};
            char *subjectNamePtr = GetCertSubjectName(X509_STORE_CTX_get_current_cert(verifyCtx), subjectName,
                MAX_SUBJECT_NAME_LEN);
            if (subjectNamePtr == NULL) {
                continue;
            }
            LOGW("The \"%{public}s(%{public}d)\" error was ignored, current cert subject name: %{public}s", errStr,
                certVerifyResult, subjectNamePtr);
            return 1;
        }
    }
    return ret;
}

static CfResult SetAppdata(X509_STORE_CTX *verifyCtx, const HcfX509CertValidatorOpenSSLParams *opensslParams,
    const HcfX509CertValidatorParams *params, CertVerifyResultInner *result)
{
    int ret;
    if (opensslParams->ignoreErrs[0] != 0) {
        ret = X509_STORE_CTX_set_ex_data(verifyCtx, USER_DATA_INDEX, (void *)opensslParams);
        if (ret != 1) {
            RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Call set app data(opensslParams) failed.", result);
        }
    }

    if (!opensslParams->certDup) {
        return CF_SUCCESS;
    }

    ret = X509_STORE_CTX_set_app_data(verifyCtx, (void *)&params->userId);
    if (ret != 1) {
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Call set app data(userId) failed.", result);
    }

    ret = X509_STORE_CTX_set_ex_data(verifyCtx, 1, result);
    if (ret != 1) {
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Call set ex data(result) failed.", result);
    }
    return CF_SUCCESS;
}

static CfResult SetSslPurposeIfNeeded(X509_STORE_CTX *verifyCtx, const HcfX509CertValidatorParams *params,
    CertVerifyResultInner *result)
{
    if (params->sslMode == SSL_MODE_SERVER || params->sslMode == SSL_MODE_CLIENT) {
        X509_VERIFY_PARAM *verifyParam = X509_STORE_CTX_get0_param(verifyCtx);
        int purpose = (params->sslMode == SSL_MODE_SERVER) ? X509_PURPOSE_SSL_SERVER : X509_PURPOSE_SSL_CLIENT;
        if (verifyParam == NULL || X509_VERIFY_PARAM_set_purpose(verifyParam, purpose) != 1) {
            X509_STORE_CTX_free(verifyCtx);
            RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Call X509_VERIFY_PARAM_set_purpose failed.", result);
        }
    }
    return CF_SUCCESS;
}

static CfResult ExecuteSingleVerification(HcfX509CertValidatorOpenSSLParams *opensslParams,
    const HcfX509CertValidatorParams *params, CertVerifyResultInner *result)
{
    X509_STORE_CTX *verifyCtx = X509_STORE_CTX_new();
    if (verifyCtx == NULL) {
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Call X509_STORE_CTX_new failed.", result);
    }

    if (X509_STORE_CTX_init(verifyCtx, opensslParams->store, opensslParams->cert,
        opensslParams->untrustedCertStack) != 1) {
        X509_STORE_CTX_free(verifyCtx);
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Call X509_STORE_CTX_init failed.", result);
    }

    CfResult ret = SetAppdata(verifyCtx, opensslParams, params, result);
    if (ret != CF_SUCCESS) {
        X509_STORE_CTX_free(verifyCtx);
        return ret;
    }

    X509_STORE_CTX_set_verify_cb(verifyCtx, VerifyCallback);

    if (params->partialChain) {
        X509_STORE_CTX_set_flags(verifyCtx, X509_V_FLAG_PARTIAL_CHAIN);
    }

    ret = SetSslPurposeIfNeeded(verifyCtx, params, result);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    if (params->validateDate == false) {
        X509_STORE_CTX_set_flags(verifyCtx, X509_V_FLAG_NO_CHECK_TIME);
    } else if (params->date != NULL) {
        X509_STORE_CTX_set_time(verifyCtx, 0, opensslParams->date);
    }

    if (X509_verify_cert(verifyCtx) == 1) {
        result->certChain = X509_STORE_CTX_get1_chain(verifyCtx);
        X509_STORE_CTX_free(verifyCtx);
        if (result->certChain == NULL) {
            RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Call X509_STORE_CTX_get1_chain failed.", result);
        }
        result->errorMsg = NULL;
        return CF_SUCCESS;
    }

    result->errCode = X509_STORE_CTX_get_error(verifyCtx);
    result->lastCert = X509_STORE_CTX_get_current_cert(verifyCtx);
    const char *opensslErrMsg = X509_verify_cert_error_string(result->errCode);
    result->errorMsg = opensslErrMsg;
    if (result->errorMsg == NULL) {
        result->errorMsg = "Certificate verification failed, unknown error code.";
    }
    AppendCertSubjectToErrorMsg(result->lastCert, result);
    X509_STORE_CTX_free(verifyCtx);
    ret = ConvertOpensslErrorMsgEx(result->errCode);
    RETURN_VERIFY_ERROR(ret, result->errorMsg, result);
}

static CfResult AdjustCertChain(HcfX509CertValidatorOpenSSLParams *opensslParams,
    const HcfX509CertValidatorParams *params, CertVerifyResultInner *result)
{
    if (params->partialChain == false || result->certChain == NULL) {
        return CF_SUCCESS;
    }

    int certChainSize = sk_X509_num(result->certChain);
    if (certChainSize <= 1) {
        return CF_SUCCESS;
    }

    /* When initiating partial certificate chain verification, check whether the issuer of the penultimate certificate
    in the chain is present in the storage area. If not, then the certificate to be verified must be in the trusted
    storage area, and the returned certificate chain should only include the certificate to be verified */
    X509 *cert = sk_X509_value(result->certChain, certChainSize - 1 - 1);
    X509 *issuer = NULL;
    CfResult ret = GetIssuerFromStore(cert, opensslParams->store, &issuer, result);
    X509_free(issuer);
    if (ret == CF_SUCCESS) {
        return CF_SUCCESS;
    } else if (ret == CF_ERR_CRYPTO_OPERATION) {
        sk_X509_pop_free(result->certChain, X509_free);
        result->certChain = NULL;
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to get issuer cert from store when adjust cert chain.",
            result);
    }
    for (int i = certChainSize - 1; i > 0; i--) {
        cert = sk_X509_delete(result->certChain, i);
        X509_free(cert);
    }
    return CF_SUCCESS;
}

static CfResult BuildAndVerifyCertChain(HcfX509CertValidatorOpenSSLParams *opensslParams,
    const HcfX509CertValidatorParams *params, CertVerifyResultInner *result)
{
    uint32_t remainingCount = MAX_TOTAL_DOWNLOAD_CERT_COUNT + 1;
    CfResult ret = CF_SUCCESS;
    while (remainingCount > 0) {
        ret = ExecuteSingleVerification(opensslParams, params, result);
        if (ret == CF_SUCCESS) {
            ret = AdjustCertChain(opensslParams, params, result);
            return ret;
        }

        if (ret != CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) {
            return ret;
        }

        if (result->lastCert == NULL) {
            return ret;
        }

        if (!params->allowDownloadIntermediateCa) {
            return ret;
        }

        if (remainingCount == 1) {
            LOGW("The download certificate limit of 5 times has been reached");
            return ret;
        }

        remainingCount--;
        ret = DownloadAndAddIntermediateCert(result->lastCert, opensslParams->untrustedCertStack, result);
        if (ret != CF_SUCCESS) {
            AppendCertSubjectToErrorMsg(result->lastCert, result);
            return ret;
        }
    }
    return ret;
}

static bool HasRevocationFlag(const HcfX509CertRevokedParams *revo, int32_t flag)
{
    if (revo == NULL) {
        return false;
    }
    for (uint32_t i = 0; i < revo->revocationFlags.count; i++) {
        if (revo->revocationFlags.data[i] == flag) {
            return true;
        }
    }
    return false;
}

static const EVP_MD *GetOcspDigestByType(int32_t digestType)
{
    switch (digestType) {
        case OCSP_DIGEST_SHA1:
            return EVP_sha1();
        case OCSP_DIGEST_SHA224:
            return EVP_sha224();
        case OCSP_DIGEST_SHA384:
            return EVP_sha384();
        case OCSP_DIGEST_SHA512:
            return EVP_sha512();
        case OCSP_DIGEST_SHA256:
        default:
            return EVP_sha256();
    }
}

static bool IsValidHttpUrl(const char *url)
{
    if (url == NULL) {
        return false;
    }
    // Only allow http:// or https://
    if (strncmp(url, "http://", strlen("http://")) == 0 || strncmp(url, "https://", strlen("https://")) == 0) {
        return true;
    }
    return false;
}

static X509_CRL *TryDownloadCrlFromDistPoint(DIST_POINT *dp, int *remainingCount, CfResult *ret)
{
    if (dp == NULL || dp->distpoint == NULL || dp->distpoint->type != 0) {
        return NULL;
    }

    STACK_OF(GENERAL_NAME) *names = dp->distpoint->name.fullname;
    if (names == NULL) {
        return NULL;
    }

    int nameCount = sk_GENERAL_NAME_num(names);
    for (int j = 0; j < nameCount && *remainingCount > 0; j++) {
        GENERAL_NAME *genName = sk_GENERAL_NAME_value(names, j);
        if (genName == NULL || genName->type != GEN_URI) {
            continue;
        }

        ASN1_IA5STRING *uri = genName->d.uniformResourceIdentifier;
        if (uri == NULL || uri->data == NULL) {
            continue;
        }

        char *url = (char *)uri->data;
        if (!IsValidHttpUrl(url)) {
            LOGW("Invalid CRL URL (not http/https): %{public}s", url);
            continue;
        }
        (*remainingCount)--;
        ERR_clear_error();
        X509_CRL *crl = X509_CRL_load_http(url, NULL, NULL, CRL_DOWNLOAD_TIMEOUT_SECONDS);
        if (crl != NULL) {
            LOGI("CRL download successful, URL: %{public}s", url);
            return crl;
        }
        LOGW("Failed to download the CRL, URL: %{public}s, errno: %{public}d", url, errno);
        unsigned long err = ERR_peek_error();
        int reason = ERR_GET_REASON(err);
        if (reason == BIO_R_CONNECT_TIMEOUT || reason == BIO_R_TRANSFER_TIMEOUT) {
            *ret = CF_ERR_NETWORK_TIMEOUT;
        }
    }
    return NULL;
}

static CfResult DownloadCrlFromCdp(X509 *cert, X509_CRL **crlOut, CertVerifyResultInner *result)
{
    STACK_OF(DIST_POINT) *crldp = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
    if (crldp == NULL) {
        RETURN_VERIFY_ERROR(CF_ERR_CRL_NOT_FOUND, "No CRL distribution points extension found.", result);
    }

    X509_CRL *crl = NULL;
    CfResult ret = CF_ERR_CRL_NOT_FOUND;
    int remainingCount = MAX_TOTAL_DOWNLOAD_COUNT;
    int num = sk_DIST_POINT_num(crldp);
    for (int i = 0; i < num && crl == NULL && remainingCount > 0; i++) {
        DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);
        crl = TryDownloadCrlFromDistPoint(dp, &remainingCount, &ret);
    }
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (crl != NULL) {
        *crlOut = crl;
        return CF_SUCCESS;
    }

    if (ret == CF_ERR_NETWORK_TIMEOUT) {
        RETURN_VERIFY_ERROR(CF_ERR_NETWORK_TIMEOUT, "Failed to download CRL from CDP, network timeout.", result);
    }
    RETURN_VERIFY_ERROR(CF_ERR_CRL_NOT_FOUND, "Failed to download CRL from CDP.", result);
}

static CfResult AddCrlsToStore(X509_STORE *store, const HcfX509CertRevokedParams *revokedParams,
    CertVerifyResultInner *result)
{
    for (uint32_t i = 0; i < revokedParams->crls.count; i++) {
        HcfX509Crl *x509Crl = revokedParams->crls.data[i];
        if (x509Crl == NULL) {
            continue;
        }
        X509_CRL *crl = GetX509CrlFromHcfX509Crl(x509Crl);
        if (crl == NULL) {
            RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK, "Failed to parse CRL.", result);
        }
        if (X509_STORE_add_crl(store, crl) != 1) {
            RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to add CRL to store.", result);
        }
    }
    return CF_SUCCESS;
}

static CfResult AddCertChainToStore(X509_STORE *store, STACK_OF(X509) *certChain,
    CertVerifyResultInner *result)
{
    int chainLen = sk_X509_num(certChain);
    for (int i = 0; i < chainLen; i++) {
        X509 *chainCert = sk_X509_value(certChain, i);
        if (chainCert == NULL) {
            continue;
        }
        if (X509_STORE_add_cert(store, chainCert) != 1) {
            RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to add cert to store.", result);
        }
    }
    return CF_SUCCESS;
}

static CfResult ProcessIgnoreError(X509 *cert, HcfX509CertValidatorOpenSSLParams *opensslParams, CfResult res)
{
    char subjectNameBuf[MAX_SUBJECT_NAME_LEN] = {0};
    char *subjectName = GetCertSubjectName(cert, subjectNameBuf, MAX_SUBJECT_NAME_LEN);
    subjectName = subjectName == NULL ? "cert not have subject name" : subjectName;
    if (opensslParams->ignoreNetworkTimeout && res == CF_ERR_NETWORK_TIMEOUT) {
        LOGW("Ignore network timeout error when check cert revocation online, cert: %{public}s",
            subjectName);
        return CF_SUCCESS;
    }
    if (opensslParams->ignoreOcspRespNotFound && res == CF_ERR_OCSP_RESPONSE_NOT_FOUND) {
        LOGW("Ignore OCSP response not found error when check cert revocation, cert: %{public}s",
            subjectName);
        return CF_SUCCESS;
    }
    return res;
}

static CfResult CheckCertRevocation(CertVerifyResultInner *result, const HcfX509CertValidatorParams *params,
    HcfX509CertValidatorOpenSSLParams *opensslParams)
{
    if (result->certChain == NULL) {
        return CF_SUCCESS;
    }
    int chainLen = sk_X509_num(result->certChain);
    if (chainLen <= 0) {
        return CF_SUCCESS;
    }
    int checkCount = opensslParams->revocationCheckAll ? chainLen : 1;

    for (int i = 0; i < checkCount; i++) {
        X509 *cert = sk_X509_value(result->certChain, i);

        if (X509_self_signed(cert, 0) > 0) {
            continue;
        }

        // Set issuer from certChain
        opensslParams->issuer = (i + 1 < chainLen) ? sk_X509_value(result->certChain, i + 1) : NULL;

        CfResult res = CheckSingleCertRevocation(cert, params, opensslParams, result);
        res = ProcessIgnoreError(cert, opensslParams, res);
        if (res != CF_SUCCESS) {
            AppendCertSubjectToErrorMsg(cert, result);
            return res;
        }
    }

    return CF_SUCCESS;
}

static CfResult PerformRevocationCheck(CertVerifyResultInner *result, const HcfX509CertValidatorParams *params,
    HcfX509CertValidatorOpenSSLParams *opensslParams)
{
    HcfX509CertRevokedParams *revokedParams = params->revokedParams;

    CfResult res = AddCrlsToStore(opensslParams->store, revokedParams, result);
    if (res != CF_SUCCESS) {
        return res;
    }
    res = AddCertChainToStore(opensslParams->store, result->certChain, result);
    if (res != CF_SUCCESS) {
        return res;
    }

    return CheckCertRevocation(result, params, opensslParams);
}

static CfResult MapCrlErrorToResult(int err, X509 *cert, CertVerifyResultInner *result)
{
    result->errCode = err;
    switch (err) {
        case X509_V_ERR_UNABLE_TO_GET_CRL:
            RETURN_VERIFY_ERROR(CF_ERR_CRL_NOT_FOUND, "Unable to get CRL.", result);
        case X509_V_ERR_CRL_HAS_EXPIRED:
            RETURN_VERIFY_ERROR(CF_ERR_CRL_HAS_EXPIRED, "CRL has expired.", result);
        case X509_V_ERR_CRL_NOT_YET_VALID:
            RETURN_VERIFY_ERROR(CF_ERR_CRL_NOT_YET_VALID, "CRL not yet valid.", result);
        case X509_V_ERR_CRL_SIGNATURE_FAILURE:
            RETURN_VERIFY_ERROR(CF_ERR_CRL_SIGNATURE_FAILURE, "CRL signature verification failed.", result);
        case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
            RETURN_VERIFY_ERROR(CF_ERR_UNABLE_TO_GET_CRL_ISSUER, "Unable to get CRL issuer certificate.", result);
        case X509_V_ERR_CERT_REVOKED:
            RETURN_VERIFY_ERROR(CF_ERR_CERT_REVOKED, "Certificate is revoked by CRL.", result);
        default:
            result->errorMsg = X509_verify_cert_error_string(err);
            return ConvertOpensslErrorMsgEx(err);
    }
}

static CfResult VerifyCertByCrl(X509 *cert, X509_STORE_CTX *ctx, const HcfX509CertValidatorParams *params,
    const HcfX509CertValidatorOpenSSLParams *opensslParams, CertVerifyResultInner *result)
{
    if (X509_STORE_CTX_init(ctx, opensslParams->store, cert, NULL) != 1) {
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to init X509_STORE_CTX.", result);
    }

    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_PARTIAL_CHAIN);

    CfResult ret = SetAppdata(ctx, opensslParams, params, result);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    X509_STORE_CTX_set_verify_cb(ctx, VerifyCallback);

    if (params->validateDate == false) {
        X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_NO_CHECK_TIME);
    } else if (params->date != NULL) {
        X509_STORE_CTX_set_time(ctx, 0, opensslParams->date);
    }

    if (X509_verify_cert(ctx) == 1) {
        return CF_SUCCESS;
    }
    int err = X509_STORE_CTX_get_error(ctx);
    if (err == X509_V_ERR_CERT_REVOKED) {
        result->usedMethod = CERT_REVOKED_METHOD_CRL;
        result->revokedCert = cert;
        FillCrlRevocationInfo(cert, opensslParams, result);
    }
    return MapCrlErrorToResult(err, cert, result);
}

static CfResult HandleCrlNotFound(X509 *cert, X509_STORE_CTX *ctx,
    const HcfX509CertValidatorParams *params,
    const HcfX509CertValidatorOpenSSLParams *opensslParams,
    CertVerifyResultInner *result)
{
    char cacheId[MAX_REVOCATION_CACHE_ID_LEN] = {0};
    if (opensslParams->cacheEnabled &&
        BuildRevocationCacheIdentifier(cert, opensslParams->issuer, REVOCATION_TYPE_CRL,
            cacheId, sizeof(cacheId)) == CF_SUCCESS) {
        CfBlob der = {0};
        if (RevocationCacheQuery(cacheId, REVOCATION_TYPE_CRL, &der) == CF_SUCCESS && der.data != NULL) {
            const unsigned char *p = der.data;
            X509_CRL *cachedCrl = d2i_X509_CRL(NULL, &p, (long)der.size);
            if (cachedCrl != NULL && X509_STORE_add_crl(opensslParams->store, cachedCrl) == 1) {
                X509_CRL_free(cachedCrl);
                CfFree(der.data);
                X509_STORE_CTX_cleanup(ctx);
                return VerifyCertByCrl(cert, ctx, params, opensslParams, result);
            }
            if (cachedCrl != NULL) {
                X509_CRL_free(cachedCrl);
            }
        }
        CfFree(der.data);
    }

    X509_CRL *downloadedCrl = NULL;
    CfResult ret = DownloadCrlFromCdp(cert, &downloadedCrl, result);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    if (X509_STORE_add_crl(opensslParams->store, downloadedCrl) != 1) {
        X509_CRL_free(downloadedCrl);
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to add downloaded CRL to store.", result);
    }

    X509_STORE_CTX_cleanup(ctx);
    ret = VerifyCertByCrl(cert, ctx, params, opensslParams, result);
    /* Cache write: only cache when verification passes or revocation is explicitly determined */
    if (opensslParams->cacheEnabled && cacheId[0] != '\0' &&
        (ret == CF_SUCCESS || ret == CF_ERR_CERT_REVOKED)) {
        unsigned char *der = NULL;
        int derLen = i2d_X509_CRL(downloadedCrl, &der);
        if (derLen > 0 && der != NULL) {
            CfBlob blob = { (uint32_t)derLen, der };
            CfResult storeRet = RevocationCacheStore(cacheId, REVOCATION_TYPE_CRL, &blob,
                GetCrlExpirationTime(downloadedCrl));
            if (storeRet != CF_SUCCESS) {
                LOGW("Call RevocationCacheStore failed, ret = %{public}d.", storeRet);
            }
            OPENSSL_free(der);
        }
    }
    X509_CRL_free(downloadedCrl);
    return ret;
}

static CfResult CheckSingleCertByCrl(X509 *cert, const HcfX509CertValidatorParams *params,
    const HcfX509CertValidatorOpenSSLParams *opensslParams, CertVerifyResultInner *result)
{
    if (opensslParams->issuer == NULL) {
        RETURN_VERIFY_ERROR(CF_ERR_UNABLE_TO_GET_CRL_ISSUER,
            "Failed to find crl issuer. Note: If partial certificate chain verification is enabled, CRL checking for" \
            "the revocation status of all certificates is not supported.",
            result);
    }

    HcfX509CertRevokedParams *revo = params->revokedParams;
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (ctx == NULL) {
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to create X509_STORE_CTX.", result);
    }

    CfResult ret = VerifyCertByCrl(cert, ctx, params, opensslParams, result);
    if (ret == CF_SUCCESS) {
        X509_STORE_CTX_free(ctx);
        return ret;
    }

    int err = X509_STORE_CTX_get_error(ctx);
    if (err == X509_V_ERR_UNABLE_TO_GET_CRL && revo->allowDownloadCrl) {
        ret = HandleCrlNotFound(cert, ctx, params, opensslParams, result);
        X509_STORE_CTX_free(ctx);
        return ret;
    } else {
        X509_STORE_CTX_free(ctx);
        return ret;
    }
}

static CfResult GetOcspStatusResult(int status, CertVerifyResultInner *result)
{
    switch (status) {
        case V_OCSP_CERTSTATUS_GOOD:
            return CF_SUCCESS;
        case V_OCSP_CERTSTATUS_REVOKED:
            RETURN_VERIFY_ERROR(CF_ERR_CERT_REVOKED, "Certificate is revoked by OCSP.", result);
        case V_OCSP_CERTSTATUS_UNKNOWN:
            RETURN_VERIFY_ERROR(CF_ERR_OCSP_CERT_STATUS_UNKNOWN,
                "OCSP certificate status unknown.", result);
        default:
            LOGD("OCSP certificate status: %{public}d", status);
            RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "OCSP certificate status unknown.", result);
    }
}

static bool FindOcspResponseStatus(X509 *cert, X509 *issuer, OCSP_BASICRESP *bs,
    int *status, OcspTimeInfo *timeInfo)
{
    int respCount = OCSP_resp_count(bs);
    for (int i = 0; i < respCount; i++) {
        OCSP_SINGLERESP *singleResp = OCSP_resp_get0(bs, i);
        if (singleResp == NULL) {
            continue;
        }

        const OCSP_CERTID *respCertId = OCSP_SINGLERESP_get0_id(singleResp);
        if (respCertId == NULL) {
            continue;
        }

        ASN1_OBJECT *hashAlg = NULL;
        OCSP_id_get0_info(NULL, &hashAlg, NULL, NULL, (OCSP_CERTID *)respCertId);
        if (hashAlg == NULL) {
            continue;
        }

        const EVP_MD *respMd = EVP_get_digestbyobj(hashAlg);
        if (respMd == NULL) {
            continue;
        }

        OCSP_CERTID *certId = OCSP_cert_to_id(respMd, cert, issuer);
        if (certId == NULL) {
            continue;
        }

        if (OCSP_id_cmp(certId, respCertId) == 0) {
            int reason;
            ASN1_GENERALIZEDTIME *revtime = NULL;
            *status = OCSP_single_get0_status(singleResp, &reason, &revtime,
                &timeInfo->thisUpdate, &timeInfo->nextUpdate);
            timeInfo->reason = reason;
            timeInfo->revocationTime = revtime;
            OCSP_CERTID_free(certId);
            return *status >= 0;
        }
        OCSP_CERTID_free(certId);
    }
    return false;
}

static CfResult VerifyLocalOcspResponse(X509 *cert, X509 *issuer,
    OCSP_BASICRESP *bs,
    const HcfX509CertValidatorOpenSSLParams *opensslParams,
    CertVerifyResultInner *result)
{
    int status = V_OCSP_CERTSTATUS_UNKNOWN;
    OcspTimeInfo timeInfo = { 0 };
    if (!FindOcspResponseStatus(cert, issuer, bs, &status, &timeInfo)) {
        RETURN_VERIFY_ERROR(CF_ERR_OCSP_RESPONSE_NOT_FOUND, "OCSP response not found.", result);
    }

    if (OCSP_basic_verify(bs, result->certChain, opensslParams->store, 0) != 1) {
        RETURN_VERIFY_ERROR(CF_ERR_OCSP_SIGNATURE_FAILURE,
            "OCSP signature verification failed or cert verification failed.", result);
    }

    if (status == V_OCSP_CERTSTATUS_REVOKED) {
        result->usedMethod = CERT_REVOKED_METHOD_OCSP;
        result->revokedCert = cert;
        result->revocationReason = timeInfo.reason;
        FormatRevocationTime((const ASN1_TIME *)timeInfo.revocationTime, result->revocationTime,
            sizeof(result->revocationTime));
    }

    CfResult ret = GetOcspStatusResult(status, result);
    if (ret != CF_SUCCESS) {
        return ret;
    }
    if (OCSP_check_validity(timeInfo.thisUpdate, timeInfo.nextUpdate, OCSP_RESPONSE_TIMEOUT_TIME, -1) != 1) {
        RETURN_VERIFY_ERROR(CF_ERR_OCSP_RESPONSE_INVALID, "OCSP response has expired.", result);
    }
    return CF_SUCCESS;
}

static CfResult VerifyOcspResponseForCert(X509 *cert, X509 *issuer,
    CfBlob *ocspResponseData,
    const HcfX509CertValidatorOpenSSLParams *opensslParams,
    CertVerifyResultInner *result)
{
    const unsigned char *p = ocspResponseData->data;
    OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE(NULL, &p, ocspResponseData->size);
    if (resp == NULL) {
        RETURN_VERIFY_ERROR(CF_ERR_OCSP_RESPONSE_INVALID, "Failed to parse OCSP response.", result);
    }

    if (OCSP_response_status(resp) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        OCSP_RESPONSE_free(resp);
        RETURN_VERIFY_ERROR(CF_ERR_OCSP_RESPONSE_INVALID, "OCSP response status is not successful.", result);
    }

    OCSP_BASICRESP *bs = OCSP_response_get1_basic(resp);
    OCSP_RESPONSE_free(resp);
    if (bs == NULL) {
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to get basic OCSP response.", result);
    }

    CfResult res = VerifyLocalOcspResponse(cert, issuer, bs, opensslParams, result);

    OCSP_BASICRESP_free(bs);
    return res;
}

void StoreOcspResponseToCache(X509 *cert, const HcfX509CertValidatorOpenSSLParams *opensslParams,
    OCSP_RESPONSE *resp, ASN1_GENERALIZEDTIME *nextUpdate)
{
    if (!opensslParams->cacheEnabled || resp == NULL) {
        return;
    }
    char cacheId[MAX_REVOCATION_CACHE_ID_LEN] = {0};
    if (BuildRevocationCacheIdentifier(cert, opensslParams->issuer, REVOCATION_TYPE_OCSP,
        cacheId, sizeof(cacheId)) != CF_SUCCESS) {
        return;
    }
    unsigned char *der = NULL;
    int derLen = i2d_OCSP_RESPONSE(resp, &der);
    if (derLen <= 0 || der == NULL) {
        return;
    }
    uint64_t expiration = Asn1TimeToTimestamp((const ASN1_TIME *)nextUpdate);
    if (expiration == 0) {
        expiration = (uint64_t)(time(NULL) + OCSP_CACHE_FALLBACK_EXPIRE_SECONDS);
    }
    CfBlob blob = { (uint32_t)derLen, der };
    CfResult storeRet = RevocationCacheStore(cacheId, REVOCATION_TYPE_OCSP, &blob, expiration);
    if (storeRet != CF_SUCCESS) {
        LOGW("Call RevocationCacheStore failed, ret = %{public}d.", storeRet);
    }
    OPENSSL_free(der);
}

static void FillOcspRevocationInfo(X509 *cert, int reason, const ASN1_GENERALIZEDTIME *revtime,
    CertVerifyResultInner *result)
{
    result->usedMethod = CERT_REVOKED_METHOD_OCSP;
    result->revokedCert = cert;
    result->revocationReason = reason;
    FormatRevocationTime((const ASN1_TIME *)revtime, result->revocationTime, sizeof(result->revocationTime));
}

static CfResult VerifyOnlineOcspResponse(OCSP_REQUEST *req, OCSP_RESPONSE *resp, OCSP_CERTID *certId, X509 *cert,
    const HcfX509CertValidatorOpenSSLParams *opensslParams, CertVerifyResultInner *result)
{
    int status = OCSP_response_status(resp);
    if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        LOGD("OCSP response status is %{public}d", status);
        RETURN_VERIFY_ERROR(CF_ERR_OCSP_RESPONSE_NOT_FOUND, "OCSP response status is not successful.", result);
    }

    OCSP_BASICRESP *bs = OCSP_response_get1_basic(resp);
    if (bs == NULL) {
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to get basic OCSP response.", result);
    }

    int nonceRet = OCSP_check_nonce(req, bs);
    if (nonceRet == 0) {
        OCSP_BASICRESP_free(bs);
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "OCSP nonces both present, but not equal.", result);
    }
    if (nonceRet == -1) {
        LOGW("OCSP response nonce absent");
    }

    ASN1_GENERALIZEDTIME *thisUpdate = NULL;
    ASN1_GENERALIZEDTIME *nextUpdate = NULL;
    ASN1_GENERALIZEDTIME *revtime = NULL;
    int revocationReason = REVOCATION_REASON_NONE;

    if (OCSP_resp_find_status(bs, certId, &status, &revocationReason, &revtime, &thisUpdate, &nextUpdate) != 1) {
        OCSP_BASICRESP_free(bs);
        RETURN_VERIFY_ERROR(CF_ERR_OCSP_RESPONSE_NOT_FOUND,
            "Online OCSP response not found.", result);
    }

    if (OCSP_basic_verify(bs, result->certChain, opensslParams->store, 0) != 1) {
        OCSP_BASICRESP_free(bs);
        RETURN_VERIFY_ERROR(CF_ERR_OCSP_SIGNATURE_FAILURE,
            "Online OCSP signature verification failed or cert verification failed.", result);
    }

    if (status == V_OCSP_CERTSTATUS_REVOKED) {
        FillOcspRevocationInfo(cert, revocationReason, revtime, result);
    }

    CfResult cfRet = GetOcspStatusResult(status, result);
    if (cfRet == CF_SUCCESS) {
        if (OCSP_check_validity(thisUpdate, nextUpdate, OCSP_RESPONSE_TIMEOUT_TIME, -1) != 1) {
            OCSP_BASICRESP_free(bs);
            RETURN_VERIFY_ERROR(CF_ERR_OCSP_RESPONSE_INVALID, "Online OCSP response has expired.", result);
        }
    }

    /* Only cache when the status is conclusive (GOOD/REVOKED/UNKNOWN); */
    /* do not cache when signature/validity verification fails */
    if (status == V_OCSP_CERTSTATUS_GOOD || status == V_OCSP_CERTSTATUS_REVOKED ||
        status == V_OCSP_CERTSTATUS_UNKNOWN) {
        StoreOcspResponseToCache(cert, opensslParams, resp, nextUpdate);
    }

    OCSP_BASICRESP_free(bs);
    return cfRet;
}

static CfResult CreateConnectBio(const char *host, const char *port, BIO **bio, CertVerifyResultInner *result)
{
    BIO *tmpBio = BIO_new_connect(host);
    if (tmpBio == NULL) {
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to create connect BIO.", result);
    }
    BIO_set_conn_port(tmpBio, port);
    int ret = BIO_do_connect_retry(tmpBio, OCSP_REQUEST_TIMEOUT_SECONDS, 0);
    if (ret == 1) {
        *bio = tmpBio;
        return CF_SUCCESS;
    }
    BIO_free(tmpBio);
    int reason = ERR_GET_REASON(ERR_peek_error());
    if (reason == BIO_R_CONNECT_TIMEOUT || reason == BIO_R_TRANSFER_TIMEOUT) {
        LOGW("OCSP tcp connect timeout, reason=%{public}d", reason);
        RETURN_VERIFY_ERROR(CF_ERR_NETWORK_TIMEOUT, "OCSP tcp connect timeout.", result);
    }
    RETURN_VERIFY_ERROR(CF_ERR_OCSP_RESPONSE_NOT_FOUND, "OCSP tcp connect failed.", result);
}

static CfResult CreateOcspRequest(X509 *cert, X509 *issuer,
    const HcfX509CertRevokedParams *revo, CertVerifyResultInner *result, OCSP_REQUEST **reqOut)
{
    const EVP_MD *md = GetOcspDigestByType(revo->ocspDigest);
    *reqOut = OCSP_REQUEST_new();
    if (*reqOut == NULL) {
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to create OCSP request.", result);
    }

    OCSP_CERTID *certId = OCSP_cert_to_id(md, cert, issuer);
    if (certId == NULL) {
        OCSP_REQUEST_free(*reqOut);
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to create OCSP cert ID.", result);
    }

    if (OCSP_request_add0_id(*reqOut, certId) == NULL) {
        OCSP_REQUEST_free(*reqOut);
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to add cert ID to OCSP request.", result);
    }

    if (OCSP_request_add1_nonce(*reqOut, NULL, -1) != 1) {
        OCSP_REQUEST_free(*reqOut);
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to add nonce to OCSP request.", result);
    }
    return CF_SUCCESS;
}

static inline void FreeOcspConnectInfo(OcspConnectInfo *info)
{
    if (info == NULL) {
        return;
    }
    OPENSSL_free(info->host);
    OPENSSL_free(info->port);
    OPENSSL_free(info->path);
}

static CfResult SetupOcspRequestContext(BIO *bio, const OcspConnectInfo *info,
    OCSP_REQUEST *req, OSSL_HTTP_REQ_CTX **ctx, CertVerifyResultInner *result)
{
    OSSL_HTTP_REQ_CTX *ctxTmp = OCSP_sendreq_new(bio, info->path, NULL, -1);
    if (ctxTmp == NULL) {
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to create OCSP request context.", result);
    }

    if (OCSP_REQ_CTX_add1_header(ctxTmp, "Accept", "application/ocsp-response") != 1) {
        OSSL_HTTP_REQ_CTX_free(ctxTmp);
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to set OCSP request accept.", result);
    }

    if (OCSP_REQ_CTX_add1_header(ctxTmp, "Host", info->host) != 1) {
        OSSL_HTTP_REQ_CTX_free(ctxTmp);
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to set OCSP request host.", result);
    }

    if (OCSP_REQ_CTX_set1_req(ctxTmp, req) != 1) {
        OSSL_HTTP_REQ_CTX_free(ctxTmp);
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to set OCSP request.", result);
    }
    *ctx = ctxTmp;
    return CF_SUCCESS;
}

static CfResult SendOcspRequestWithTimeout(BIO *bio, const OcspConnectInfo *info, OCSP_REQUEST *req,
    OCSP_RESPONSE **respOut, CertVerifyResultInner *result)
{
    OSSL_HTTP_REQ_CTX *ctx = NULL;
    CfResult res = SetupOcspRequestContext(bio, info, req, &ctx, result);
    if (res != CF_SUCCESS) {
        return res;
    }

    OCSP_RESPONSE *resp = NULL;
    int ret;
    int tryNum = TRY_CONNECT_TIMES;
    time_t startTime = time(NULL);
    struct timespec waitTime;
    waitTime.tv_sec = 0;
    waitTime.tv_nsec = MAX_WAIT_TIME_NANOSECONDS;
    while (tryNum > 0) {
        ret = OCSP_sendreq_nbio(&resp, ctx);
        if (ret != -1) {
            break;
        }
        ret = BIO_wait(bio, time(NULL) + 1, 0);
        LOGW("BIO_wait ret=%{public}d, errno=%{public}d", ret, errno);
        if (ret <= 0 && (time(NULL) - startTime) < OCSP_REQUEST_TIMEOUT_SECONDS) {
            nanosleep(&waitTime, NULL);
            continue;
        }
        tryNum--;
    }
    OSSL_HTTP_REQ_CTX_free(ctx);

    if (resp != NULL) {
        *respOut = resp;
        LOGI("OCSP response download successful, URL: %{public}s", info->url);
        return CF_SUCCESS;
    }

    LOGW("OCSP response download failed, URL: %{public}s, errno: %{public}d", info->url, errno);
    int reason = ERR_GET_REASON(ERR_peek_error());
    if (reason == BIO_R_CONNECT_TIMEOUT || reason == BIO_R_TRANSFER_TIMEOUT) {
        LOGW("OCSP request timeout, reason=%{public}d", reason);
        RETURN_VERIFY_ERROR(CF_ERR_NETWORK_TIMEOUT, "OCSP request timeout.", result);
    }
    RETURN_VERIFY_ERROR(CF_ERR_OCSP_RESPONSE_NOT_FOUND, "OCSP response download failed.", result);
}

static CfResult TrySingleOcspUrl(const char *url, OcspCheckContext *ctx,
    const HcfX509CertValidatorOpenSSLParams *opensslParams, CertVerifyResultInner *result)
{
    OcspConnectInfo info = {0};

    if (OCSP_parse_url(url, &info.host, &info.port, &info.path, &info.useSsl) != 1) {
        LOGW("Failed to parse OCSP URL: %{public}s", url);
        RETURN_VERIFY_ERROR(CF_ERR_OCSP_RESPONSE_NOT_FOUND, "Failed to parse OCSP URL.", result);
    }
    info.url = url;

    (*ctx->remainingCount)--;
    BIO *bio = NULL;
    CfResult ret = CreateConnectBio(info.host, info.port, &bio, result);
    if (ret != CF_SUCCESS) {
        FreeOcspConnectInfo(&info);
        return ret;
    }

    OCSP_RESPONSE *resp = NULL;
    ret = SendOcspRequestWithTimeout(bio, &info, ctx->req, &resp, result);
    BIO_free(bio);
    FreeOcspConnectInfo(&info);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    ret = VerifyOnlineOcspResponse(ctx->req, resp, ctx->certId, ctx->cert, opensslParams, result);
    OCSP_RESPONSE_free(resp);
    return ret;
}

static CfResult PerformOnlineOcspCheck(X509 *cert, X509 *issuer,
    const HcfX509CertValidatorParams *params,
    const HcfX509CertValidatorOpenSSLParams *opensslParams,
    CertVerifyResultInner *result)
{
    STACK_OF(OPENSSL_STRING) *ocspUrls = X509_get1_ocsp(cert);
    if (ocspUrls == NULL || sk_OPENSSL_STRING_num(ocspUrls) == 0) {
        X509_email_free(ocspUrls);
        RETURN_VERIFY_ERROR(CF_ERR_OCSP_RESPONSE_NOT_FOUND, "No OCSP URL found in certificate.", result);
    }

    OCSP_REQUEST *req = NULL;
    CfResult res = CreateOcspRequest(cert, issuer, params->revokedParams, result, &req);
    if (res != CF_SUCCESS) {
        X509_email_free(ocspUrls);
        return res;
    }

    OCSP_ONEREQ *oneReq = OCSP_request_onereq_get0(req, 0);
    if (oneReq == NULL) {
        OCSP_REQUEST_free(req);
        X509_email_free(ocspUrls);
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to get OCSP onereq.", result);
    }

    OCSP_CERTID *certId = OCSP_CERTID_dup(OCSP_onereq_get0_id(oneReq));
    if (certId == NULL) {
        OCSP_REQUEST_free(req);
        X509_email_free(ocspUrls);
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to duplicate OCSP cert ID.", result);
    }

    int remainingCount = MAX_TOTAL_DOWNLOAD_COUNT;
    OcspCheckContext ctx = { req, certId, cert, &remainingCount };
    res = CF_ERR_OCSP_RESPONSE_NOT_FOUND;
    for (int i = 0; i < sk_OPENSSL_STRING_num(ocspUrls) && remainingCount > 0; i++) {
        res = TrySingleOcspUrl(sk_OPENSSL_STRING_value(ocspUrls, i), &ctx, opensslParams, result);
        if (res != CF_ERR_OCSP_RESPONSE_NOT_FOUND && res != CF_ERR_NETWORK_TIMEOUT) {
            break;
        }
    }
    OCSP_CERTID_free(certId);
    OCSP_REQUEST_free(req);
    X509_email_free(ocspUrls);
    return res;
}

static CfResult GetIssuerFromStore(X509 *cert, X509_STORE *store,
    X509 **issuer, CertVerifyResultInner *result)
{
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (ctx == NULL) {
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to create X509_STORE_CTX when checking OCSP.", result);
    }

    if (X509_STORE_CTX_init(ctx, store, cert, NULL) != 1) {
        X509_STORE_CTX_free(ctx);
        RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to init X509_STORE_CTX when checking OCSP.", result);
    }

    // Get issuer from store
    int ret = X509_STORE_CTX_get1_issuer(issuer, ctx, cert);
    X509_STORE_CTX_free(ctx);
    if (ret == 1) {
        return CF_SUCCESS;
    }

    if (ret == 0) {
        RETURN_VERIFY_ERROR(CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
            "No issuer found from store when checking OCSP.", result);
    }

    RETURN_VERIFY_ERROR(CF_ERR_CRYPTO_OPERATION, "Failed to get issuer from store when checking OCSP.", result);
}

static CfResult TryOcspCache(X509 *cert, X509 *issuer,
    const HcfX509CertValidatorOpenSSLParams *opensslParams, CertVerifyResultInner *result)
{
    char cacheId[MAX_REVOCATION_CACHE_ID_LEN] = {0};
    if (BuildRevocationCacheIdentifier(cert, issuer, REVOCATION_TYPE_OCSP,
        cacheId, sizeof(cacheId)) != CF_SUCCESS) {
        return CF_ERR_OCSP_RESPONSE_NOT_FOUND;
    }
    CfBlob der = {0};
    if (RevocationCacheQuery(cacheId, REVOCATION_TYPE_OCSP, &der) != CF_SUCCESS || der.data == NULL) {
        CfFree(der.data);
        return CF_ERR_OCSP_RESPONSE_NOT_FOUND;
    }
    CfResult cachedRet = VerifyOcspResponseForCert(cert, issuer, &der, opensslParams, result);
    CfFree(der.data);
    return (cachedRet == CF_SUCCESS || cachedRet == CF_ERR_CERT_REVOKED ||
        cachedRet == CF_ERR_OCSP_CERT_STATUS_UNKNOWN) ? cachedRet : CF_ERR_OCSP_RESPONSE_NOT_FOUND;
}

static CfResult CheckSingleCertByOcsp(X509 *cert,
    const HcfX509CertValidatorParams *params,
    HcfX509CertValidatorOpenSSLParams *opensslParams,
    CertVerifyResultInner *result)
{
    X509 *issuer = opensslParams->issuer;
    bool issuerFromStore = false;

    // If issuer not found in certChain, try to get from store
    if (issuer == NULL) {
        CfResult ret = GetIssuerFromStore(cert, opensslParams->store, &issuer, result);
        if (ret != CF_SUCCESS) {
            return ret;
        }
        issuerFromStore = true;
    }

    const HcfX509CertRevokedParams *revo = params->revokedParams;
    // Step 1: Check local OCSP responses
    for (uint32_t i = 0; i < revo->ocspResponses.count; i++) {
        if (revo->ocspResponses.data[i].data == NULL || revo->ocspResponses.data[i].size == 0) {
            continue;
        }
        CfResult ret = VerifyOcspResponseForCert(cert, issuer,
            &revo->ocspResponses.data[i], opensslParams, result);
        // Only CF_ERR_OCSP_RESPONSE_NOT_FOUND means try next response,
        // all other results are definitive and should return immediately.
        if (ret != CF_ERR_OCSP_RESPONSE_NOT_FOUND) {
            if (issuerFromStore) {
                X509_free(issuer);
            }
            return ret;
        }
    }

    // Step 2: Try revocation cache if enabled
    if (opensslParams->cacheEnabled) {
        CfResult res = TryOcspCache(cert, issuer, opensslParams, result);
        if (res != CF_ERR_OCSP_RESPONSE_NOT_FOUND) {
            if (issuerFromStore) {
                X509_free(issuer);
            }
            return res;
        }
    }

    // Step 3: Try online OCSP check if allowed
    if (revo->allowOcspCheckOnline) {
        ERR_clear_error();
        CfResult res = PerformOnlineOcspCheck(cert, issuer, params, opensslParams, result);
        if (issuerFromStore) {
            X509_free(issuer);
        }
        return res;
    }

    // Step 4: No OCSP response available
    if (issuerFromStore) {
        X509_free(issuer);
    }
    RETURN_VERIFY_ERROR(CF_ERR_OCSP_RESPONSE_NOT_FOUND, "OCSP response not found.", result);
}

static CfResult CheckSingleCertRevocation(X509 *cert,
    const HcfX509CertValidatorParams *params,
    HcfX509CertValidatorOpenSSLParams *opensslParams,
    CertVerifyResultInner *result)
{
    CfResult res;

    // Case 1: Both CRL and OCSP enabled
    if (opensslParams->crlCheck && opensslParams->ocspCheck) {
        if (opensslParams->preferOcsp) {
            res = CheckSingleCertByOcsp(cert, params, opensslParams, result);
            if (res == CF_ERR_OCSP_RESPONSE_NOT_FOUND || res == CF_ERR_NETWORK_TIMEOUT) {
                res = CheckSingleCertByCrl(cert, params, opensslParams, result);
            }
        } else {
            res = CheckSingleCertByCrl(cert, params, opensslParams, result);
            if (res == CF_ERR_UNABLE_TO_GET_CRL_ISSUER || res == CF_ERR_CRL_NOT_FOUND ||
                res == CF_ERR_NETWORK_TIMEOUT) {
                res = CheckSingleCertByOcsp(cert, params, opensslParams, result);
            }
        }
        return res;
    }

    // Case 2: OCSP only
    if (opensslParams->ocspCheck) {
        return CheckSingleCertByOcsp(cert, params, opensslParams, result);
    }

    // Case 3: CRL only
    if (opensslParams->crlCheck) {
        return CheckSingleCertByCrl(cert, params, opensslParams, result);
    }

    return CF_SUCCESS;
}

static CfResult CheckTrustSourceParams(const HcfX509CertValidatorParams *params, CertVerifyResultInner *result)
{
    if (params->trustedCerts.count == 0 && params->trustCertPath.count == 0 && params->trustSystemCa == false) {
        RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK,
            "Must set trustedCerts or trustCertPath, or set trustSystemCa to true.", result);
    }
    return CF_SUCCESS;
}

static CfResult CheckEnhancedCertParams(const HcfX509CertValidatorParams *params, CertVerifyResultInner *result)
{
    if (params->trustCertPath.count > MAX_TRUST_CERT_PATH_COUNT) {
        RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK, "The number of trustCertPath cannot exceed 5.", result);
    }

    for (uint32_t i = 0; i < params->trustCertPath.count; i++) {
        if (params->trustCertPath.data[i] == NULL ||
            strlen(params->trustCertPath.data[i]) > MAX_TRUST_CERT_PATH_LENGTH) {
            RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK,
                "The length of trustCertPath cannot exceed 128.", result);
        }
    }

    if (params->ipAddresses.count > MAX_IP_ADDRESSES_COUNT) {
        RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK, "The number of ipAddresses cannot exceed 100.", result);
    }

    for (uint32_t i = 0; i < params->ipAddresses.count; i++) {
        if (params->ipAddresses.data[i] == NULL ||
            strlen(params->ipAddresses.data[i]) > MAX_IP_ADDRESS_LENGTH) {
            RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK,
                "The length of ipAddresses cannot exceed 45.", result);
        }
    }

    if (params->extendedKeyUsage.count > MAX_EXTENDED_KEY_USAGE_COUNT) {
        RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK, "The number of extendedKeyUsage cannot exceed 9.", result);
    }

    if (params->sslMode < SSL_MODE_NONE || params->sslMode > SSL_MODE_SERVER) {
        RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK, "The sslMode must be within the scope of HcfSslMode.", result);
    }
    return CF_SUCCESS;
}

static CfResult CheckCertValidatorParams(const HcfX509CertValidatorParams *params, CertVerifyResultInner *result)
{
    CfResult ret;
    if (params == NULL) {
        RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK,
            "The HcfX509CertValidatorParams parameter is null.", result);
    }

    ret = CheckTrustSourceParams(params, result);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    if (params->keyUsage.count > MAX_KEYUSAGE_COUNT) {
        RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK, "The number of keyUsage cannot exceed 9.", result);
    }

    if (params->hostnames.count > MAX_HOSTNAMES_COUNT) {
        RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK, "The number of hostnames cannot exceed 100.", result);
    }

    if (params->emailAddresses.count > MAX_EMAIL_ADDRESS_COUNT) {
        RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK, "The number of emailAddresse cannot exceed 1.", result);
    }

    ret = CheckEnhancedCertParams(params, result);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    if (params->revokedParams != NULL) {
        if (params->revokedParams->revocationFlags.count == 0 ||
            params->revokedParams->revocationFlags.count > MAX_REVOCATION_FLAG_COUNT) {
            RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK,
                "If enabling revocation checking, the length of revocationFlags must be in [1, 4].", result);
        }
    }

    if (params->revokedParams != NULL) {
        if (params->revokedParams->ocspDigest < OCSP_DIGEST_SHA1 ||
            params->revokedParams->ocspDigest > OCSP_DIGEST_SHA512) {
            RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK,
                "The ocspDigest must be within the scope of OcspDigest enumeration.", result);
        }
    }

    if (params->userId.data != NULL && (params->userId.size > MAX_USER_ID_LEN || params->userId.size == 0)) {
        RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK, "The length of optional userId must be in [1, 128].", result);
    }

    if (params->userId.data != NULL && params->userId.size != 0) {
        if (params->revokedParams != NULL) {
            RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK, "If enabling revocation checking, cannot set userId.", result);
        }
    }

    return CF_SUCCESS;
}

CfResult FillVerifyCertResult(STACK_OF(X509) *verifiedChain, HcfCertVerifyResult *result)
{
    if (verifiedChain == NULL || sk_X509_num(verifiedChain) <= 0) {
        LOGE("Invalid verified chain.");
        SetVerifyErrorMsg(result, "Invalid verified chain.");
        return CF_ERR_CRYPTO_OPERATION;
    }

    uint32_t chainSize = (uint32_t)sk_X509_num(verifiedChain);

    result->certs.data = (HcfX509Certificate **)CfMallocEx(sizeof(HcfX509Certificate *) * chainSize);
    if (result->certs.data == NULL) {
        LOGE("Failed to allocate memory for certs data.");
        SetVerifyErrorMsg(result, "Failed to allocate memory for certs data.");
        return CF_ERR_MALLOC;
    }
    result->certs.count = 0;

    for (uint32_t i = 0; i < chainSize; i++) {
        X509 *vX509 = sk_X509_value(verifiedChain, i);
        HcfX509Certificate *hcfCert = NULL;
        CfResult ret = X509ToHcfX509Certificate(vX509, &hcfCert);
        if (ret != CF_SUCCESS) { // In theory, this should never fail, except in the case of insufficient memory.
            LOGE("Failed to convert x509 certificate to hcf certificate.");
            for (uint32_t j = 0; j < result->certs.count; j++) {
                CfObjDestroy(result->certs.data[j]);
                result->certs.data[j] = NULL;
            }
            CfFree(result->certs.data);
            result->certs.data = NULL;
            SetVerifyErrorMsg(result, "Failed to convert x509 certificate to hcf certificate.");
            return ret;
        }
        result->certs.data[result->certs.count] = hcfCert;
        result->certs.count++;
    }
    return CF_SUCCESS;
}

static CfResult ValidateX509CertParams(HcfCertChainValidatorSpi *self,
    HcfX509Certificate *x509Cert, HcfCertVerifyResult *result)
{
    if (self == NULL) {
        LOGE("The HcfCertChainValidatorSpi parameter is null.");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (result == NULL) {
        LOGE("The result parameter is null.");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (x509Cert == NULL) {
        LOGE("The x509Cert parameter is null.");
        SetVerifyErrorMsg(result, "The x509Cert parameter is null.");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (result->certs.count != 0 || result->certs.data != NULL) {
        LOGE("The result parameter already contains data.");
        SetVerifyErrorMsg(result, "The result parameter already contains data.");
        return CF_ERR_PARAMETER_CHECK;
    }
    return CF_SUCCESS;
}

static CfResult ValidateX509Cert(HcfCertChainValidatorSpi *self, HcfX509Certificate *x509Cert,
    const HcfX509CertValidatorParams *params, HcfCertVerifyResult *result)
{
    CfResult res = ValidateX509CertParams(self, x509Cert, result);
    if (res != CF_SUCCESS) {
        return res;
    }

    CertVerifyResultInner resultInner = { 0 };
    res = CheckCertValidatorParams(params, &resultInner);
    if (res != CF_SUCCESS) {
        CopyVerifyErrorMsg(&resultInner, result);
        return res;
    }

    /* Parse all OpenSSL params including the cert to be verified */
    HcfX509CertValidatorOpenSSLParams opensslParams;
    (void)memset_s(&opensslParams, sizeof(opensslParams), 0, sizeof(opensslParams));
    res = ParseOpenSSLParams(x509Cert, params, &opensslParams, &resultInner);
    if (res != CF_SUCCESS) {
        CopyVerifyErrorMsg(&resultInner, result);
        FreeOpenSSLParams(&opensslParams);
        return res;
    }

    /* Check certificate extensions */
    res = CheckCertValidatorExtensions(opensslParams.cert, params, &opensslParams, &resultInner);
    if (res != CF_SUCCESS) {
        CopyVerifyErrorMsg(&resultInner, result);
        FreeOpenSSLParams(&opensslParams);
        return res;
    }

    ERR_clear_error();
    res = BuildAndVerifyCertChain(&opensslParams, params, &resultInner);
    if (res == CF_SUCCESS && opensslParams.cacheEnabled &&
        (resultInner.certChain == NULL ||
        !IsTrustAnchorSystemCa(resultInner.certChain, opensslParams.systemCaStore))) {
        opensslParams.cacheEnabled = false;
    }
    if (res == CF_SUCCESS && params->revokedParams != NULL) {
        res = PerformRevocationCheck(&resultInner, params, &opensslParams);
    }

    FreeOpenSSLParams(&opensslParams);
    if (res == CF_SUCCESS) {
        res = FillVerifyCertResult(resultInner.certChain, result);
    } else {
        CopyVerifyErrorMsg(&resultInner, result);
    }

    if (resultInner.certChain != NULL) {
        sk_X509_pop_free(resultInner.certChain, X509_free);
    }
    return res;
}

CfResult HcfCertChainValidatorSpiCreate(HcfCertChainValidatorSpi **spi)
{
    if (spi == NULL) {
        LOGE("Invalid params, spi is null!");
        return CF_INVALID_PARAMS;
    }
    HcfCertChainValidatorSpi *validator = (HcfCertChainValidatorSpi *)CfMalloc(sizeof(HcfCertChainValidatorSpi), 0);
    if (validator == NULL) {
        LOGE("Failed to allocate certChain validator spi object memory!");
        return CF_ERR_MALLOC;
    }
    validator->base.getClass = GetX509CertChainValidatorClass;
    validator->base.destroy = DestroyX509CertChainValidator;
    validator->engineValidate = Validate;
    validator->engineValidateX509Cert = ValidateX509Cert;

    *spi = validator;
    return CF_SUCCESS;
}

