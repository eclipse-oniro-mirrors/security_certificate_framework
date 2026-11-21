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

#include "x509_cert_chain_openssl_ex.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include "x509_cert_chain_openssl.h"
#include "certificate_openssl_common.h"
#include "cf_blob.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "cf_result.h"
#include "revocation_check.h"
#include "utils.h"

typedef struct {
    OCSP_REQUEST *req;
    OCSP_RESPONSE *resp;
    OcspCertIdInfo *certIdInfo;
} OcspLocalParam;

typedef struct {
    X509 *leafCert;
    HcfRevocationCheckParam *revo;
    char **host;
    char **port;
    char **path;
    int *ssl;
} GetOcspUrlParams;

typedef struct {
    STACK_OF(X509) *x509CertChain;
    OcspCertIdInfo *certIdInfo;
    HcfX509TrustAnchor *trustAnchor;
    const HcfX509CertChainValidateParams *params;
    int index;
    OCSP_REQUEST **req;
    OCSP_RESPONSE **resp;
    BIO **cbio;
} PrepareOcspRequestParams;

static CfResult CheckCertChainIsRevoked(const HcfX509CertChainValidateParams *params,
    const STACK_OF(X509_CRL) *crlStack, const STACK_OF(X509) *certChain)
{
    int cerNum = sk_X509_num(certChain);
    if (cerNum == 0) {
        LOGE("sk X509 num : 0, failed!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    int crlNum = sk_X509_CRL_num(crlStack); // allow crlNum : 0, no crl
    for (int i = 0; i < crlNum; ++i) {
        X509_CRL *crl = sk_X509_CRL_value(crlStack, i);
        if (crl == NULL) {
            LOGE("sk X509 CRL value is null, failed!");
            CfPrintOpensslError();
            return CF_ERR_CRYPTO_OPERATION;
        }
        /* crl in certcrlcollection object is not null. */
        for (int j = 0; j < cerNum; ++j) {
            X509 *cert = sk_X509_value(certChain, j);
            if (cert == NULL) {
                LOGE("sk X509 value is null, failed!");
                CfPrintOpensslError();
                return CF_ERR_CRYPTO_OPERATION;
            }

            X509_REVOKED *rev = NULL;
            int32_t res = X509_CRL_get0_by_cert(crl, &rev, cert);
            if (res == 1) {
                LOGE("cert is revoked.");
                return CF_ERR_CRYPTO_OPERATION;
            }
            if (params->revocationCheckParam && params->revocationCheckParam->options &&
                ContainsOption(params->revocationCheckParam->options,
                    REVOCATION_CHECK_OPTION_LOCAL_CRL_ONLY_CHECK_END_ENTITY_CERT)) {
                LOGD("CheckCertChainIsLocalRevoked only check end entity cert!");
                break;
            }
        }
    }

    return CF_SUCCESS;
}

static X509_CRL *ParseX509CRL(const CfEncodingBlob *inStream)
{
    if ((inStream->data == NULL) || (inStream->len <= 0)) {
        LOGE("Invalid params!");
        return NULL;
    }
    BIO *bio = BIO_new_mem_buf(inStream->data, inStream->len);
    if (bio == NULL) {
        LOGE("bio get null!");
        CfPrintOpensslError();
        return NULL;
    }
    X509_CRL *crlOut = NULL;
    switch (inStream->encodingFormat) {
        case CF_FORMAT_DER:
            crlOut = d2i_X509_CRL_bio(bio, NULL);
            break;
        case CF_FORMAT_PEM:
            crlOut = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
            break;
        default:
            LOGE("Not support format!");
            break;
    }
    BIO_free_all(bio);
    if (crlOut == NULL) {
        LOGE("Parse X509 CRL fail!");
        CfPrintOpensslError();
        return NULL;
    }
    return crlOut;
}

static CfResult PushCrl2Stack(HcfX509CrlArray *crlArray, STACK_OF(X509_CRL) *outCrls)
{
    CfResult res = CF_SUCCESS;
    HcfX509Crl *x509Crl = NULL;
    X509_CRL *crl = NULL;
    for (uint32_t i = 0; i < crlArray->count; i++) {
        CfEncodingBlob encodedBlob = { 0 };
        x509Crl = crlArray->data[i];
        res = x509Crl->getEncoded(x509Crl, &encodedBlob);
        if (res != CF_SUCCESS) {
            LOGE("Failed to getEncoded of crl!");
            return res;
        }

        crl = ParseX509CRL(&encodedBlob);
        CfFree(encodedBlob.data);
        encodedBlob.data = NULL;
        if (crl == NULL) {
            LOGE("Failed to Parse x509 CRL!");
            return CF_INVALID_PARAMS;
        }
        if (sk_X509_CRL_push(outCrls, crl) == 0) {
            LOGE("sk_X509_CRL_push failed!");
            X509_CRL_free(crl);
            return CF_ERR_CRYPTO_OPERATION;
        }
    }
    return res;
}

static CfResult GetX509Crls(const HcfCertCRLCollectionArray *certCRLCollections, STACK_OF(X509_CRL) *outCrls)
{
    if (certCRLCollections == NULL) { // certCRLCollection is not force params for verify certchain
        LOGI("certcrlcollections is null!");
        return CF_SUCCESS;
    }

    CfResult res = CF_SUCCESS;
    HcfX509CrlArray *crlArray = NULL;
    HcfCertCrlCollection *crlCollection = NULL;
    for (uint32_t i = 0; i < certCRLCollections->count; i++) {
        crlCollection = certCRLCollections->data[i];
        res = crlCollection->getCRLs(crlCollection, &crlArray);
        if (res != CF_SUCCESS) {
            LOGE("getCRLs() from CertCrlCollection failed!");
            /* Warning: free outCrls in outside */
            return res;
        }
        if (crlArray->count == 0) {
            LOGI("crls array is empty.");
            continue;
        }
        res = PushCrl2Stack(crlArray, outCrls);
        if (res != CF_SUCCESS) {
            LOGE("push crls to stack failed!");
            /* Warning: free outCrls in outside */
            return res;
        }
    }

    return res;
}

CfResult ValidateCrlLocal(const HcfX509CertChainValidateParams *params, STACK_OF(X509) *x509CertChain)
{
    STACK_OF(X509_CRL) *crlStack = sk_X509_CRL_new_null();
    if (crlStack == NULL) {
        LOGE("sk X509 CRL new null failed!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    CfResult res = GetX509Crls(params->certCRLCollections, crlStack);
    if (res != CF_SUCCESS) {
        LOGE("GetX509Crls failed");
        sk_X509_CRL_pop_free(crlStack, X509_CRL_free);
        return res;
    }

    if (sk_X509_CRL_num(crlStack) == 0) {
        LOGI("crls count is 0");
        sk_X509_CRL_free(crlStack);
        return CF_SUCCESS;
    }

    res = CheckCertChainIsRevoked(params, crlStack, x509CertChain);
    sk_X509_CRL_pop_free(crlStack, X509_CRL_free);
    return res;
}

static CfResult CheckCrlIsRevoked(const HcfX509CertChainValidateParams *params, X509_CRL *crl,
    STACK_OF(X509) *x509CertChain)
{
    STACK_OF(X509_CRL) *crlStack = sk_X509_CRL_new_null();
    if (crlStack == NULL) {
        LOGE("Create crl stack failed!");
        X509_CRL_free(crl);
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    if (sk_X509_CRL_push(crlStack, crl) == 0) {
        LOGE("Push crl stack failed!");
        X509_CRL_free(crl);
        CfPrintOpensslError();
        sk_X509_CRL_pop_free(crlStack, X509_CRL_free);
        return CF_ERR_CRYPTO_OPERATION;
    }
    if (CheckCertChainIsRevoked(params, crlStack, x509CertChain) != CF_SUCCESS) {
        LOGE("Certchain is revoked, verify failed!");
        sk_X509_CRL_pop_free(crlStack, X509_CRL_free);
        return CF_ERR_CRYPTO_OPERATION;
    }
    sk_X509_CRL_pop_free(crlStack, X509_CRL_free);
    return CF_SUCCESS;
}

static CfResult ValidateCrlIntermediateCaOnline(const HcfX509CertChainValidateParams *params,
    STACK_OF(X509) *x509CertChain)
{
    CfResult res = CF_ERR_CRYPTO_OPERATION;
    if (sk_X509_num(x509CertChain) <= 1) {
        res = CF_SUCCESS;
    }
    for (int i = 1; i < sk_X509_num(x509CertChain) - 1; i++) {
        X509 *x509 = sk_X509_value(x509CertChain, i);
        if (x509 == NULL) {
            LOGE("Get cert from stack to check crl failed!");
            res = CF_ERR_CRYPTO_OPERATION;
            break;
        }
        int errReason = 0;
        X509_CRL *crl = GetCrlFromCertByDp(x509, &errReason);
        if (errReason == BIO_R_CONNECT_TIMEOUT) {
            res = CF_ERR_CONNECT_TIMEOUT;
        }
        if (errReason == -1) {
            LOGW("Validate IntermediateCaOnline success, index = %{public}d. Not found crlStack or url in cert.", i);
            res = CF_SUCCESS;
            continue;
        }
        if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR)) {
            if (crl == NULL && res == CF_ERR_CONNECT_TIMEOUT) {
                res = CF_SUCCESS;
                LOGW("Validate IntermediateCaOnline success, index = %{public}d with ignore network error option.", i);
                continue;
            }
        } else if (crl == NULL) {
            LOGE("Crl url exist, but get crl from cert by dp failed!");
            res = CF_ERR_CRYPTO_OPERATION;
            break;
        }
        res = CheckCrlIsRevoked(params, crl, x509CertChain);
        if (res != CF_SUCCESS) {
            LOGE("Certchain is revoked, verify failed!");
            break;
        }
    }
    return res;
}

static CfResult ValidateCrlLeftCertOnline(const HcfX509CertChainValidateParams *params, STACK_OF(X509) *x509CertChain)
{
    X509 *x509 = sk_X509_value(x509CertChain, 0);
    if (x509 == NULL) {
        LOGE("Get leaf cert failed!");
        return CF_INVALID_PARAMS;
    }
    int errReason = 0;
    X509_CRL *crl = GetCrlFromCert(params, x509, &errReason);
    if (crl == NULL) {
        LOGE("Get crl online is null, errReason = %{public}d!", errReason);
        if (errReason == BIO_R_CONNECT_TIMEOUT) {
            return CF_ERR_CONNECT_TIMEOUT;
        }
        return CF_ERR_CRYPTO_OPERATION;
    }

    CfResult res = CheckCrlIsRevoked(params, crl, x509CertChain);
    if (res != CF_SUCCESS) {
        LOGE("Certchain is revoked, verify failed!");
        return res;
    }
    return res;
}

static CfResult ValidateCrlOnline(const HcfX509CertChainValidateParams *params, STACK_OF(X509) *x509CertChain)
{
    CfResult res = ValidateCrlLeftCertOnline(params, x509CertChain);
    if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR)) {
        if (res != CF_SUCCESS && res != CF_ERR_CONNECT_TIMEOUT) {
            return res;
        }
        LOGW("ValidateCrlOnline leaf cert success with ignore network error option.");
    } else {
        if (res != CF_SUCCESS) {
            return res;
        }
    }
    if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE)) {
        res = ValidateCrlIntermediateCaOnline(params, x509CertChain);
        if (res != CF_SUCCESS) {
            LOGE("Certchain is revoked, verify failed!");
            return res;
        }
    }
    return res;
}

static CfResult VerifyOcspSigner(OCSP_BASICRESP *bs, STACK_OF(X509) *certChain, X509 *cert)
{
    if (cert == NULL) {
        LOGE("Input data cert is null!");
        return CF_INVALID_PARAMS;
    }
    X509_STORE *store = X509_STORE_new();
    if (store == NULL) {
        LOGE("New x509 store failed!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    CfResult res = SetVerifyParams(store, cert);
    if (res != CF_SUCCESS) {
        LOGE("Set verify params failed!");
        X509_STORE_free(store);
        return res;
    }

    if (OCSP_basic_verify(bs, certChain, store, 0) != 1) {
        LOGE("OCSP basic verify failed!");
        res = CF_ERR_CERT_SIGNATURE_FAILURE;
    }
    X509_STORE_free(store);

    return res;
}

static CfResult ParseResp(OCSP_BASICRESP *bs, OcspCertIdInfo *certIdInfo)
{
    int ocspStatus;
    ASN1_GENERALIZEDTIME *thisUpdate = NULL;
    ASN1_GENERALIZEDTIME *nextUpdate = NULL;
    CfResult res = CF_ERR_CRYPTO_OPERATION;

    OCSP_CERTID *certId = OCSP_cert_to_id(certIdInfo->md, certIdInfo->subjectCert, certIdInfo->issuerCert);
    if (certId == NULL) {
        LOGE("Unable to create certId.");
        return CF_ERR_CRYPTO_OPERATION;
    }

    if (OCSP_resp_find_status(bs, certId, &ocspStatus, NULL, NULL, &thisUpdate, &nextUpdate) == 1) {
        switch (ocspStatus) {
            case V_OCSP_CERTSTATUS_GOOD:
                LOGI("The OCSP status is [V_OCSP_CERTSTATUS_GOOD]!");
                res = CF_SUCCESS;
                break;
            case V_OCSP_CERTSTATUS_REVOKED:
                LOGE("The OCSP status is [V_OCSP_CERTSTATUS_REVOKED]!");
                break;
            case V_OCSP_CERTSTATUS_UNKNOWN:
            default:
                LOGE("!The OCSP status is [UNKNOWN]!");
                break;
        }
    }
    OCSP_CERTID_free(certId);
    return res;
}

static void ValidateOcspLocalGetTrustCert(STACK_OF(X509) *x509CertChain, HcfX509TrustAnchor *trustAnchor,
    const HcfX509CertChainValidateParams *params, HcfRevocationCheckParam *revo, X509 **trustCert)
{
    if (revo->ocspResponderCert != NULL) {
        *trustCert = GetX509FromHcfX509Certificate((HcfCertificate *)(params->revocationCheckParam->ocspResponderCert));
    } else if (trustAnchor->CACert != NULL) {
        *trustCert = GetX509FromHcfX509Certificate((HcfCertificate *)(trustAnchor->CACert));
    } else {
        *trustCert = sk_X509_value(x509CertChain, sk_X509_num(x509CertChain) - 1);
    }
}

static CfResult ValidateOcspVerify(OcspLocalParam localParam, STACK_OF(X509) *x509CertChain,
    HcfX509TrustAnchor *trustAnchor, const HcfX509CertChainValidateParams *params, int index)
{
    int i;
    X509 *trustCert = NULL;
    if (OCSP_response_status(localParam.resp) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        LOGE("The resp status is not success!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    OCSP_BASICRESP *bs = OCSP_response_get1_basic(localParam.resp);
    if (bs == NULL) {
        LOGE("Error parsing response!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    if (localParam.req != NULL && ((i = OCSP_check_nonce(localParam.req, bs)) <= 0)) {
        if (i == -1) {
            LOGW("No nonce in response!");
        } else {
            LOGE("Nonce Verify error!");
            OCSP_BASICRESP_free(bs);
            return CF_ERR_CRYPTO_OPERATION;
        }
    }
    if (index == 0) {
        ValidateOcspLocalGetTrustCert(x509CertChain, trustAnchor, params, params->revocationCheckParam, &trustCert);
    } else {
        if (index + 1 < sk_X509_num(x509CertChain)) {
            trustCert = sk_X509_value(x509CertChain, index + 1);
        } else {
            trustCert = GetX509FromHcfX509Certificate((HcfCertificate *)(trustAnchor->CACert));
        }
    }

    CfResult res = VerifyOcspSigner(bs, x509CertChain, trustCert);
    if (res != CF_SUCCESS) {
        LOGE("VerifySinger failed!");
        OCSP_BASICRESP_free(bs);
        return res;
    }
    res = ParseResp(bs, localParam.certIdInfo);
    if (res != CF_SUCCESS) {
        LOGE("ParseResp failed!");
        OCSP_BASICRESP_free(bs);
        return res;
    }
    OCSP_BASICRESP_free(bs);
    return res;
}

static void FreeCertIdInfo(OcspCertIdInfo *certIdInfo)
{
    if (certIdInfo == NULL) {
        return;
    }
    if (certIdInfo->subjectCert != NULL) {
        X509_free(certIdInfo->subjectCert);
    }
    if (certIdInfo->issuerCert != NULL) {
        X509_free(certIdInfo->issuerCert);
    }
}

static CfResult ValidateOcspLocal(OcspLocalParam localParam, STACK_OF(X509) *x509CertChain,
    HcfX509TrustAnchor *trustAnchor, const HcfX509CertChainValidateParams *params, int index)
{
    OCSP_RESPONSE *rsp = NULL;
    OcspCertIdInfo certIdInfo = {0};
    CfResult res = CfGetCertIdInfo(x509CertChain, params->revocationCheckParam->ocspDigest, trustAnchor,
        &certIdInfo, index);
    if (res != CF_SUCCESS) {
        LOGE("Get cert id info failed.");
        return res;
    }
    localParam.certIdInfo = &certIdInfo;
    HcfRevocationCheckParam *revo = params->revocationCheckParam;
    if (localParam.resp == NULL && index == 0 && revo->ocspResponses != NULL) {
        const unsigned char *p = revo->ocspResponses->data;
        rsp = d2i_OCSP_RESPONSE(NULL, &p, revo->ocspResponses->size);
        localParam.resp = rsp;
    }
    if (localParam.resp == NULL) {
        LOGE("The input data is null!");
        FreeCertIdInfo(&certIdInfo);
        return CF_ERR_CRYPTO_OPERATION;
    }
    res = ValidateOcspVerify(localParam, x509CertChain, trustAnchor, params, index);
    FreeCertIdInfo(&certIdInfo);
    if (res != CF_SUCCESS) {
        LOGE("ValidateOcspVerify failed!");
        OCSP_RESPONSE_free(rsp);
        return res;
    }
    OCSP_RESPONSE_free(rsp);
    return res;
}

static OCSP_RESPONSE *SendReqBioCustom(BIO *bio, const char *host, const char *path, OCSP_REQUEST *req)
{
    OCSP_RESPONSE *resp = NULL;
    OCSP_REQ_CTX *ctx;

    ctx = OCSP_sendreq_new(bio, path, NULL, -1);
    if (ctx == NULL) {
        LOGE("Create ocsp req ctx failed!");
        return NULL;
    }
    if (!OCSP_REQ_CTX_add1_header(ctx, "Accept", "application/ocsp-response")) {
        OCSP_REQ_CTX_free(ctx);
        return NULL;
    }
    if (!OCSP_REQ_CTX_add1_header(ctx, "Host", host)) {
        OCSP_REQ_CTX_free(ctx);
        return NULL;
    }
    if (!OCSP_REQ_CTX_set1_req(ctx, req)) {
        OCSP_REQ_CTX_free(ctx);
        return NULL;
    }
    int ret;
    int tryNum = TRY_CONNECT_TIMES;
    do {
        ret = OCSP_sendreq_nbio(&resp, ctx);
        tryNum--;
    } while ((ret == -1) && BIO_should_retry(bio) && tryNum != 0);
    OCSP_REQ_CTX_free(ctx);
    if (ret != 0) {
        return resp;
    }
    return NULL;
}

static bool ConnectToServer(BIO *bio, int tryNum, int *errReason)
{
    int ret = 0;
    int num = tryNum;
    do {
        ret = BIO_do_connect_retry(bio, OCSP_CONN_TIMEOUT, OCSP_CONN_MILLISECOND);
        if (ret == 1) {
            break;
        } else if (ret <= 0) {
            LOGE("OCSP connecte service failed.");
            ret = BIO_do_connect_retry(bio, LOAD_OCSP_CONN_TIMEOUT, OCSP_CONN_MILLISECOND);
            if (ret == 1) {
                break;
            }
            if (BIO_should_retry(bio)) {
                LOGI("Try to connect service again, [%{public}d]st.", num);
                num--;
            } else {
                break;
            }
        }
    } while (ret <= 0 && num != 0);
    if (ret != 1) {
        *errReason = ERR_GET_REASON(ERR_peek_last_error());
    }
    return (ret == 1 ? true : false);
}

static CfResult GetOcspUrl(GetOcspUrlParams *params, int index)
{
    char *url = NULL;
    if (params->leafCert == NULL) {
        LOGE("The input param invalid, index = %{public}d.", index);
        return CF_INVALID_PARAMS;
    }
    STACK_OF(OPENSSL_STRING) *ocspList = X509_get1_ocsp(params->leafCert);
    if (ocspList != NULL && sk_OPENSSL_STRING_num(ocspList) > 0) {
        url = sk_OPENSSL_STRING_value(ocspList, 0);
    }

    if (url == NULL) {
        if (index == 0) {
            if (params->revo->ocspResponderURI == NULL || params->revo->ocspResponderURI->data == NULL) {
                LOGE("Unable to get url.");
                X509_email_free(ocspList);
                return CF_ERR_CRYPTO_OPERATION;
            }
        } else {
            LOGW("Unable to get url from certificate, index = %{public}d.", index);
            X509_email_free(ocspList);
            return CF_ERR_EXTENSION_NOT_EXIST;
        }
    }
    char *urlValiable = (url == NULL) ? (char *)(params->revo->ocspResponderURI->data) : url;
    if (!CfIsUrlValid(urlValiable)) {
        LOGE("Invalid url.");
        X509_email_free(ocspList);
        return CF_INVALID_PARAMS;
    }
    if (!OCSP_parse_url(urlValiable, params->host, params->port, params->path, params->ssl)) {
        LOGE("Unable to parse url.");
        X509_email_free(ocspList);
        return CF_ERR_CRYPTO_OPERATION;
    }
    X509_email_free(ocspList);
    return CF_SUCCESS;
}

static CfResult PrepareCertIdInfoForRequest(PrepareOcspRequestParams *params, OcspCertIdInfo **certIdInfoToUse)
{
    if (params->certIdInfo != NULL) {
        *certIdInfoToUse = params->certIdInfo;
        return CF_SUCCESS;
    }

    OcspCertIdInfo *tempCertIdInfo = (OcspCertIdInfo *)CfMalloc(sizeof(OcspCertIdInfo), 0);
    if (tempCertIdInfo == NULL) {
        LOGE("Failed to malloc tempCertIdInfo.");
        return CF_ERR_MALLOC;
    }

    HcfRevocationCheckParam *revo = params->params->revocationCheckParam;
    CfResult res = CfGetCertIdInfo(params->x509CertChain, revo->ocspDigest, params->trustAnchor, tempCertIdInfo,
        params->index);
    if (res != CF_SUCCESS) {
        LOGE("Get cert id info failed.");
        CfFree(tempCertIdInfo);
        return res;
    }
    *certIdInfoToUse = tempCertIdInfo;
    return CF_SUCCESS;
}

static CfResult SetRequestData(HcfRevocationCheckParam *revo, OCSP_REQUEST *req, OcspCertIdInfo *certIdInfo)
{
    OCSP_CERTID *certId = OCSP_cert_to_id(certIdInfo->md, certIdInfo->subjectCert, certIdInfo->issuerCert);
    if (certId == NULL) {
        LOGE("Unable to create certId.");
        return CF_ERR_CRYPTO_OPERATION;
    }

    if (OCSP_request_add0_id(req, certId) == NULL) {
        LOGE("Unable to add certId to req.");
        OCSP_CERTID_free(certId);
        return CF_INVALID_PARAMS;
    }

    if (revo->ocspRequestExtension != NULL) {
        for (size_t i = 0; i < revo->ocspRequestExtension->count; i++) {
            const unsigned char *p = revo->ocspRequestExtension->data[i].data;
            X509_EXTENSION *ext = d2i_X509_EXTENSION(NULL, &p, revo->ocspRequestExtension->data[i].size);
            if (ext == NULL) {
                return CF_INVALID_PARAMS;
            }
            if (!OCSP_REQUEST_add_ext(req, ext, -1)) {
                X509_EXTENSION_free(ext);
                return CF_ERR_CRYPTO_OPERATION;
            }
            X509_EXTENSION_free(ext);
            ext = NULL;
        }
    }

    return CF_SUCCESS;
}

static CfResult BuildAndSendOcspRequest(PrepareOcspRequestParams *params, const char *host, const char *path,
    OcspCertIdInfo *certIdInfoToUse)
{
    HcfRevocationCheckParam *revo = params->params->revocationCheckParam;
    CfResult res = SetRequestData(revo, *(params->req), certIdInfoToUse);
    if (res != CF_SUCCESS) {
        LOGE("Unable to set request data.");
        return res;
    }

    *(params->resp) = SendReqBioCustom(*(params->cbio), host, path, *(params->req));
    if (*(params->resp) == NULL) {
        LOGE("Unable to send request.");
        return CF_ERR_CRYPTO_OPERATION;
    }
    return CF_SUCCESS;
}

static BIO *CreateConnectBio(const char *host, const char *port, int ssl)
{
    BIO *bio = NULL;
    if (ssl == 1) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();

        SSL_CTX *sslCtx = SSL_CTX_new(TLS_client_method());
        if (sslCtx == NULL) {
            return NULL;
        }
        bio = BIO_new_ssl_connect(sslCtx);
        if (bio == NULL) {
            LOGE("bio is null.");
            SSL_CTX_free(sslCtx);
            return NULL;
        }
        if (BIO_set_conn_hostname(bio, host) != 1) {
            LOGE("Set host name failed.");
            BIO_free_all(bio);
            SSL_CTX_free(sslCtx);
            return NULL;
        }
    } else {
        bio = BIO_new_connect(host);
    }

    if (bio == NULL) {
        LOGE("Create connect bio failed.");
        return bio;
    }

    if (port != NULL) {
        if (BIO_set_conn_port(bio, port) != 1) {
            LOGE("Set port failed.");
            BIO_free_all(bio);
            return NULL;
        }
    } else if (ssl != 0) {
        if (BIO_set_conn_port(bio, HTTPS_PORT) != 1) {
            LOGE("Set port failed.");
            BIO_free_all(bio);
            return NULL;
        }
    } else {
        if (BIO_set_conn_port(bio, HTTP_PORT) != 1) {
            LOGE("Set port failed.");
            BIO_free_all(bio);
            return NULL;
        }
    }
    return bio;
}

static CfResult CreateOcspConnection(const char *host, const char *port, int ssl, BIO **cbio)
{
    *cbio = CreateConnectBio(host, port, ssl);
    if (*cbio == NULL) {
        LOGE("Unable to create connection.");
        return CF_ERR_CRYPTO_OPERATION;
    }
    int errReason = 0;
    if (!ConnectToServer(*cbio, TRY_CONNECT_TIMES, &errReason)) {
        LOGE("Unable to connect service.");
        BIO_free_all(*cbio);
        *cbio = NULL;
        if (errReason == BIO_R_CONNECT_TIMEOUT) {
            return CF_ERR_CONNECT_TIMEOUT;
        }
        return CF_ERR_CRYPTO_OPERATION;
    }

    return CF_SUCCESS;
}

static CfResult PrepareOcspRequest(PrepareOcspRequestParams *params)
{
    char *host = NULL;
    char *port = NULL;
    char *path = NULL;
    int ssl = 0;
    HcfRevocationCheckParam *revo = params->params->revocationCheckParam;
    CfResult res = GetOcspUrl(&(GetOcspUrlParams) { .leafCert = sk_X509_value(params->x509CertChain, params->index),
        .revo = revo, .host = &host, .port = &port, .path = &path, .ssl = &ssl }, params->index);
    if (res != CF_SUCCESS) {
        LOGE("Unable to get ocps url.");
        return res;
    }

    OcspCertIdInfo *certIdInfoToUse = NULL;
    res = CreateOcspConnection(host, port, ssl, params->cbio);
    if (res != CF_SUCCESS) {
        LOGE("Unable to create ocsp connection.");
        goto exit;
    }

    *(params->req) = OCSP_REQUEST_new();
    if (*(params->req) == NULL) {
        LOGE("Unable to create req.");
        res = CF_ERR_CRYPTO_OPERATION;
        goto exit;
    }

    res = PrepareCertIdInfoForRequest(params, &certIdInfoToUse);
    if (res != CF_SUCCESS) {
        LOGE("Prepare cert id info failed.");
        goto exit;
    }

    res = BuildAndSendOcspRequest(params, host, path, certIdInfoToUse);
    if (res != CF_SUCCESS) {
        LOGE("Unable to build and send ocsp request.");
        CfPrintOpensslError();
        goto exit;
    }

exit:
    if (params->certIdInfo == NULL) {
        FreeCertIdInfo(certIdInfoToUse);
        CfFree(certIdInfoToUse);
    }
    OPENSSL_free(host);
    OPENSSL_free(port);
    OPENSSL_free(path);
    if (res != CF_SUCCESS) {
        OCSP_REQUEST_free(*(params->req));
        BIO_free_all(*(params->cbio));
    }
    return res;
}

static CfResult ValidateOcspOnline(STACK_OF(X509) *x509CertChain, OcspCertIdInfo *certIdInfo,
    HcfX509TrustAnchor *trustAnchor, const HcfX509CertChainValidateParams *params, int index)
{
    OCSP_REQUEST *req = NULL;
    OCSP_RESPONSE *resp = NULL;
    BIO *cbio = NULL;
    PrepareOcspRequestParams prepareParams = {
        .x509CertChain = x509CertChain,
        .certIdInfo = certIdInfo,
        .trustAnchor = trustAnchor,
        .params = params,
        .index = index,
        .req = &req,
        .resp = &resp,
        .cbio = &cbio
    };
    CfResult res = PrepareOcspRequest(&prepareParams);
    if (res != CF_SUCCESS) {
        return res;
    }

    if (index == 0) {
        res = ValidateOcspLocal(
            (OcspLocalParam) { .req = req, .resp = resp, .certIdInfo = NULL },
                x509CertChain, trustAnchor, params, index);
    } else {
        res = ValidateOcspVerify(
            (OcspLocalParam) { .req = req, .resp = resp, .certIdInfo = certIdInfo },
                x509CertChain, trustAnchor, params, index);
    }
    OCSP_REQUEST_free(req);
    BIO_free_all(cbio);
    OCSP_RESPONSE_free(resp);
    return res;
}

static CfResult ValidationIntermediateCert(X509 *cert, HcfX509TrustAnchor *trustAnchor)
{
    if (CheckIsSelfSigned(cert)) {
        LOGD("Self signed cert, skip validate.");
        return CF_SUCCESS;
    }
    X509 *trustCert = GetX509FromHcfX509Certificate((HcfCertificate *)(trustAnchor->CACert));
    if (trustCert == NULL) {
        LOGE("Get trust cert from trust anchor failed.");
        return CF_ERR_CRYPTO_OPERATION;
    }
    if (X509_cmp(trustCert, cert) == 0) {
        LOGD("Intermediate cert is the same as the trust anchor, skip validate.");
        return CF_SUCCESS;
    }
    return CF_ERR_CRYPTO_OPERATION;
}

static CfResult VerifyIntermediateOcspOnline(STACK_OF(X509) *x509CertChain, HcfX509TrustAnchor *trustAnchor,
    const HcfX509CertChainValidateParams *params)
{
    CfResult res = CF_ERR_CRYPTO_OPERATION;
    if (sk_X509_num(x509CertChain) <= 1) {
        res = CF_SUCCESS;
    }
    for (int i = 1; i < sk_X509_num(x509CertChain); i++) {
        if (ValidationIntermediateCert(sk_X509_value(x509CertChain, i), trustAnchor) == CF_SUCCESS) {
            LOGD("self signed cert, skip validate.");
            return CF_SUCCESS;
        }
        OcspCertIdInfo intermediateCertIdInfo = {0};
        res = CfGetCertIdInfo(x509CertChain, NULL, trustAnchor, &intermediateCertIdInfo, i);
        if (res != CF_SUCCESS) {
            LOGE("Get cert id info from intermediate cert failed.");
            return res;
        }
        res = ValidateOcspOnline(x509CertChain, &intermediateCertIdInfo, trustAnchor, params, i);
        FreeCertIdInfo(&intermediateCertIdInfo);
        if (res == CF_SUCCESS || res == CF_ERR_EXTENSION_NOT_EXIST) {
            LOGD("ValidateOcspOnline success, index = %{public}d.", i);
            res = CF_SUCCESS;
            continue;
        }
        if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR)) {
            if (res == CF_ERR_CONNECT_TIMEOUT) {
                LOGW("ValidateOcspOnline intermediate cert success,"
                    "index = %{public}d with ignore network error option.", i);
                res = CF_SUCCESS;
                continue;
            }
        }
        LOGE("ValidateOcspOnline failed, index = %{public}d.", i);
        return res;
    }
    return res;
}

static CfResult OnlineVerifyOcsp(STACK_OF(X509) *x509CertChain, HcfX509TrustAnchor *trustAnchor,
    const HcfX509CertChainValidateParams *params)
{
    CfResult res = ValidateOcspOnline(x509CertChain, NULL, trustAnchor, params, 0);
    if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR)) {
        if (res != CF_SUCCESS && res != CF_ERR_CONNECT_TIMEOUT) {
            LOGE("ValidateOcspOnline leaf cert failed with ignore network error option.");
            return res;
        }
        LOGW("ValidateOcspOnline leaf cert success with ignore network error option.");
    } else {
        if (res != CF_SUCCESS) {
            LOGE("ValidateOcspOnline leaf cert failed.");
            return res;
        }
    }
    LOGD("ValidateOcspOnline leaf cert success.");
    if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE)) {
        res = VerifyIntermediateOcspOnline(x509CertChain, trustAnchor, params);
        if (res != CF_SUCCESS) {
            LOGE("VerifyIntermediateOcspOnline failed!");
            return res;
        }
    }
    return res;
}

static CfResult ValidateRevocationOnLine(const HcfX509CertChainValidateParams *params, STACK_OF(X509) *x509CertChain,
    HcfX509TrustAnchor *trustAnchor)
{
    CfResult res = CF_INVALID_PARAMS;
    if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_PREFER_OCSP)) {
        if ((res = OnlineVerifyOcsp(x509CertChain, trustAnchor, params)) == CF_SUCCESS) {
            return res;
        }
        if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_FALLBACK_NO_PREFER)) {
            if ((res = ValidateCrlOnline(params, x509CertChain)) == CF_SUCCESS) {
                return res;
            }
        }
        if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_FALLBACK_LOCAL)) {
            if ((res = ValidateOcspLocal((OcspLocalParam) { .req = NULL, .resp = NULL, .certIdInfo = NULL },
                                        x509CertChain, trustAnchor, params, 0)) == CF_SUCCESS) {
                return res;
            }
            return ValidateCrlLocal(params, x509CertChain);
        } else {
            return IgnoreNetworkError(res, params->revocationCheckParam->options);
        }
    } else {
        if ((res = ValidateCrlOnline(params, x509CertChain)) == CF_SUCCESS) {
            return res;
        }
        if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_FALLBACK_NO_PREFER)) {
            if ((res = OnlineVerifyOcsp(x509CertChain, trustAnchor, params)) == CF_SUCCESS) {
                return res;
            }
        }
        if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_FALLBACK_LOCAL)) {
            if ((res = ValidateCrlLocal(params, x509CertChain)) == CF_SUCCESS) {
                return res;
            }
            return ValidateOcspLocal((OcspLocalParam) { .req = NULL, .resp = NULL, .certIdInfo = NULL },
                                                        x509CertChain, trustAnchor, params, 0);
        } else {
            return IgnoreNetworkError(res, params->revocationCheckParam->options);
        }
    }
    return res;
}

static CfResult ValidateRevocationLocal(const HcfX509CertChainValidateParams *params, STACK_OF(X509) *x509CertChain,
    HcfX509TrustAnchor *trustAnchor)
{
    CfResult res = CF_INVALID_PARAMS;
    if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_PREFER_OCSP)) {
        if ((res = ValidateOcspLocal((OcspLocalParam) { .req = NULL, .resp = NULL, .certIdInfo = NULL },
                                    x509CertChain, trustAnchor, params, 0)) == CF_SUCCESS) {
            return res;
        }
    } else {
        if ((res = ValidateCrlLocal(params, x509CertChain)) == CF_SUCCESS) {
            return res;
        }
    }
    return CF_INVALID_PARAMS;
}

CfResult ValidateRevocation(
    STACK_OF(X509) *x509CertChain, HcfX509TrustAnchor *trustAnchor, const HcfX509CertChainValidateParams *params)
{
    if (x509CertChain == NULL || params == NULL) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }

    if (params->revocationCheckParam && params->revocationCheckParam->options) {
        CfResult res = CF_INVALID_PARAMS;
        if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_ACCESS_NETWORK)) {
            res = ValidateRevocationOnLine(params, x509CertChain, trustAnchor);
            if (res != CF_SUCCESS) {
                LOGE("Try to validate revocation online failed.");
            }
        } else {
            res = ValidateRevocationLocal(params, x509CertChain, trustAnchor);
            if (res != CF_SUCCESS) {
                LOGE("Try to validate revocation local failed.");
            }
        }
        return res;
    } else {
        return ValidateCrlLocal(params, x509CertChain);
    }
}

