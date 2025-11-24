/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "x509_cert_chain_openssl.h"
#include "x509_cert_chain_openssl_ex.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ocsp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <securec.h>

#include "x509_certificate_create.h"
#include "certificate_openssl_class.h"
#include "certificate_openssl_common.h"
#include "cf_blob.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "cf_result.h"
#include "config.h"
#include "fwk_class.h"
#include "utils.h"
#include "x509_cert_chain_spi.h"

#define MAX_CERT_NUM 256 /* max certs number of a certchain */
#define TIMET_NUM 6
#define TIMET_YEAR_START 1900
#define TIMET_YEAR_OFFSET 100 // start time year from 1900 + 100
#define TRY_CONNECT_TIMES 3
#define OCSP_CONN_MILLISECOND 5000 // millisecond
#define OCSP_CONN_TIMEOUT (-1)     // timeout == 0 means no timeout, < 0 means exactly one try.
#define HTTP_PORT "80"
#define HTTPS_PORT "443"
#define CERT_VERIFY_DIR "/etc/security/certificates"

// helper functions
typedef struct {
    int32_t errCode;
    CfResult result;
} OpensslErrorToResult;

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
    const HcfX509CertChainValidateParams *params;
    int index;
    OCSP_REQUEST **req;
    OCSP_RESPONSE **resp;
    BIO **cbio;
} PrepareOcspRequestParams;

static const OpensslErrorToResult ERROR_TO_RESULT_MAP[] = {
    { X509_V_OK, CF_SUCCESS },
    { X509_V_ERR_CERT_SIGNATURE_FAILURE, CF_ERR_CERT_SIGNATURE_FAILURE },
    { X509_V_ERR_CERT_NOT_YET_VALID, CF_ERR_CERT_NOT_YET_VALID },
    { X509_V_ERR_CERT_HAS_EXPIRED, CF_ERR_CERT_HAS_EXPIRED },
    { X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY },
    { X509_V_ERR_KEYUSAGE_NO_CERTSIGN, CF_ERR_KEYUSAGE_NO_CERTSIGN },
    { X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE, CF_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE },
};

static CfResult ConvertOpensslErrorMsg(int32_t errCode)
{
    for (uint32_t i = 0; i < sizeof(ERROR_TO_RESULT_MAP) / sizeof(OpensslErrorToResult); ++i) {
        if (ERROR_TO_RESULT_MAP[i].errCode == errCode) {
            return ERROR_TO_RESULT_MAP[i].result;
        }
    }
    return CF_ERR_CRYPTO_OPERATION;
}

static void DestroyX509CertChain(CfObjectBase *self)
{
    if (self == NULL || !CfIsClassMatch(self, GetX509CertChainClass())) {
        LOGE("Invalid params!");
        return;
    }
    HcfX509CertChainOpensslImpl *impl = (HcfX509CertChainOpensslImpl *)self;
    if (impl->x509CertChain != NULL) {
        sk_X509_pop_free(impl->x509CertChain, X509_free);
        impl->x509CertChain = NULL;
    }

    CfFree(impl);
}

static CfResult GetCertlist(HcfX509CertChainSpi *self, HcfX509CertificateArray *certsList)
{
    if ((self == NULL) || (certsList == NULL)) {
        LOGE("[GetCertlist openssl] The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetX509CertChainClass())) {
        LOGE("[GetCertlist openssl] Input wrong class type!");
        return CF_INVALID_PARAMS;
    }

    CfResult res = CF_SUCCESS;
    HcfX509CertChainOpensslImpl *certChain = (HcfX509CertChainOpensslImpl *)self;
    STACK_OF(X509) *x509CertChain = certChain->x509CertChain;

    int32_t certsNum = sk_X509_num(x509CertChain);
    if (certsNum <= 0) {
        LOGE("sk X509 num : 0, failed!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    /* the list count has checked when create cert chain */
    certsList->data = (HcfX509Certificate **)CfMalloc(certsNum * sizeof(HcfX509Certificate *), 0);
    if (certsList->data == NULL) {
        LOGE("malloc failed");
        return CF_ERR_MALLOC;
    }

    certsList->count = (uint32_t)certsNum;
    for (int32_t i = 0; i < certsNum; ++i) {
        X509 *cert = sk_X509_value(x509CertChain, i);
        if (cert == NULL) {
            LOGE("sk X509 value is null, failed!");
            CfPrintOpensslError();
            FreeCertificateArray(certsList);
            return CF_ERR_CRYPTO_OPERATION;
        }
        HcfX509Certificate *x509Cert = NULL;
        res = X509ToHcfX509Certificate(cert, &x509Cert);
        if (res != CF_SUCCESS) {
            LOGE("convert x509 to HcfX509Certificate failed!");
            FreeCertificateArray(certsList);
            return res;
        }
        certsList->data[i] = x509Cert;
    }

    return res;
}

static bool ContainsOption(HcfRevChkOpArray *options, HcfRevChkOption op)
{
    if (options == NULL || options->data == NULL) {
        return false;
    }

    for (uint32_t i = 0; i < options->count; i++) {
        if (options->data[i] == op) {
            return true;
        }
    }
    return false;
}

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
            if (res != 0) {
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

static CfResult SetVerifyParams(X509_STORE *store, X509 *mostTrustCert)
{
    if (X509_STORE_add_cert(store, mostTrustCert) != CF_OPENSSL_SUCCESS) {
        LOGE("add cert to store failed!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    unsigned long flags = 0;
    if (!CheckIsSelfSigned(mostTrustCert)) {
        flags |= X509_V_FLAG_PARTIAL_CHAIN; // is not self signed
        LOGI("SetVerifyFlag() is a partitial chain, not self signed!");
    }

    /* date has verified before. */
    flags |= X509_V_FLAG_NO_CHECK_TIME;
    X509_STORE_set_flags(store, flags);

    return CF_SUCCESS;
}

static CfResult VerifyCertChain(X509 *mostTrustCert, STACK_OF(X509) *x509CertChain)
{
    if (mostTrustCert == NULL || x509CertChain == NULL) {
        LOGE("invalid params!");
        return CF_INVALID_PARAMS;
    }

    X509 *cert = sk_X509_value(x509CertChain, 0); // leaf cert
    if (cert == NULL) {
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (ctx == NULL) {
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    X509_STORE *store = X509_STORE_new();
    if (store == NULL) {
        LOGE("verify cert chain malloc failed!");
        X509_STORE_CTX_free(ctx);
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    CfResult res = SetVerifyParams(store, mostTrustCert);
    if (res == CF_SUCCESS) {
        if (X509_STORE_CTX_init(ctx, store, cert, x509CertChain) != CF_OPENSSL_SUCCESS) {
            LOGE("init verify ctx failed!");
            X509_STORE_CTX_free(ctx);
            X509_STORE_free(store);
            CfPrintOpensslError();
            return CF_ERR_CRYPTO_OPERATION;
        }

        if (X509_verify_cert(ctx) == CF_OPENSSL_SUCCESS) {
            res = CF_SUCCESS;
        } else {
            int32_t errCode = X509_STORE_CTX_get_error(ctx);
            const char *pChError = X509_verify_cert_error_string(errCode);
            LOGE("Failed to verify cert, openssl openssl error code = %{public}d, error msg:%{public}s.",
                errCode, pChError);
            res = ConvertOpensslErrorMsg(errCode);
        }
    }

    X509_STORE_CTX_free(ctx); // Cleanup: Free the allocated memory and release resources.
    X509_STORE_free(store);
    return res;
}

static EVP_PKEY *ConvertByteArrayToPubKey(const uint8_t *pubKeyBytes, size_t len)
{
    if (pubKeyBytes == NULL) {
        LOGE("ConvertByteArrayToPubkey invalid params.");
        return NULL;
    }
    EVP_PKEY *pubKey = d2i_PUBKEY(NULL, &pubKeyBytes, len); // pubkey DER format.
    if (pubKey == NULL) {
        LOGE("d2i_PUBKEY() failed!");
        CfPrintOpensslError();
        return NULL;
    }

    return pubKey;
}

static CfResult CheckOthersInTrustAnchor(const HcfX509TrustAnchor *anchor, X509 *rootCert, bool *checkResult)
{
    *checkResult = false;
    if (anchor->CAPubKey == NULL) {
        return CF_SUCCESS;
    }

    // 1. validate public key of the root CA.
    EVP_PKEY *pubKey = ConvertByteArrayToPubKey(anchor->CAPubKey->data, anchor->CAPubKey->size);
    if (pubKey == NULL) {
        LOGE("ConvertByteArrayToPubKey failed!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    /* pubkey in trust anchor may be the pubkey of self or of its upper level cert. */
    bool matchUpperPubKey = false;
    if (CheckSelfPubkey(rootCert, pubKey) != CF_SUCCESS) {
        matchUpperPubKey = (X509_verify(rootCert, pubKey) == CF_OPENSSL_SUCCESS);
        if (!matchUpperPubKey) {
            LOGE("verify pubkey in trust anchor failed!");
            CfPrintOpensslError();
            EVP_PKEY_free(pubKey);
            return CF_SUCCESS;
        }
    }

    /* If pubkey is of self cert, the subject should be of self cert.
     * If pubkey is of upper level cert, the subject should be of uppoer level cert (i.e. the issuer of self cert).
     */
    if (anchor->CASubject != NULL) {
        // 2. compare subject name of root CA.
        X509NameType nameType = NAME_TYPE_SUBJECT;
        if (matchUpperPubKey) {
            nameType = NAME_TYPE_ISSUER;
        }
        bool compareSubjectFlag = false;
        CfResult res = CompareNameObject(rootCert, anchor->CASubject, nameType, &compareSubjectFlag);
        if (res != CF_SUCCESS) {
            LOGE("verify subject in trust anchor failed!");
            EVP_PKEY_free(pubKey);
            return res;
        }
        LOGI("verify subject in trust anchor result: %{public}d", compareSubjectFlag);
        *checkResult = compareSubjectFlag;
    } else {
        *checkResult = true;
    }
    EVP_PKEY_free(pubKey);
    return CF_SUCCESS;
}

static CfResult GetTrustAnchor(const HcfX509TrustAnchor *trustAnchors, X509 *rootCert, X509 **mostTrustCertOut)
{
    if (trustAnchors == NULL || rootCert == NULL || mostTrustCertOut == NULL) {
        LOGE("GetTrustAnchorCert() invalid params!");
        return CF_INVALID_PARAMS;
    }

    if (trustAnchors->CACert != NULL) {
        X509 *cert = GetX509FromHcfX509Certificate((HcfCertificate *)trustAnchors->CACert);
        if (cert == NULL) {
            LOGE("GetTrustAnchorCert() cert is null.");
            return CF_INVALID_PARAMS;
        }

        X509_NAME *subjectName = X509_get_subject_name(cert);
        if (subjectName == NULL) {
            CfPrintOpensslError();
            return CF_ERR_CRYPTO_OPERATION;
        }
        X509_NAME *subjectRoot = X509_get_subject_name(rootCert);
        if (subjectRoot == NULL) {
            CfPrintOpensslError();
            return CF_ERR_CRYPTO_OPERATION;
        }
        EVP_PKEY *pubKey = X509_get_pubkey(cert); // validate public key of the trustAnchor CACert. X509_check_issued
        if (pubKey == NULL) {
            LOGE("X509_get_pubkey() failed!");
            CfPrintOpensslError();
            return CF_ERR_CRYPTO_OPERATION;
        }
        if (X509_verify(rootCert, pubKey) != CF_OPENSSL_SUCCESS && X509_NAME_cmp(subjectName, subjectRoot)) {
            LOGE("X509_verify() failed!");
            CfPrintOpensslError();
            EVP_PKEY_free(pubKey);
            return CF_SUCCESS; // continue to try next trustAnchor
        }
        EVP_PKEY_free(pubKey);
        *mostTrustCertOut = cert;
        return CF_SUCCESS;
    }

    bool checkResult = false;
    CfResult res = CheckOthersInTrustAnchor(trustAnchors, rootCert, &checkResult);
    if (res != CF_SUCCESS) {
        LOGE("CheckOthersInTrustAnchor failed.");
        return res;
    }

    if (checkResult) {
        *mostTrustCertOut = rootCert;
    }
    return CF_SUCCESS;
}

static void FreeTrustAnchorData(HcfX509TrustAnchor *trustAnchor)
{
    if (trustAnchor == NULL) {
        return;
    }
    CfBlobFree(&trustAnchor->CAPubKey);
    CfBlobFree(&trustAnchor->CASubject);
    CfObjDestroy(trustAnchor->CACert);
    trustAnchor->CACert = NULL;
}

static CfResult CopyHcfX509TrustAnchor(const HcfX509TrustAnchor *inputAnchor, HcfX509TrustAnchor *outAnchor)
{
    HcfX509Certificate *CACert = inputAnchor->CACert;
    CfBlob *CAPubKey = inputAnchor->CAPubKey;
    CfBlob *CASubject = inputAnchor->CASubject;
    CfBlob *nameConstraints = inputAnchor->nameConstraints;
    CfResult res = CF_SUCCESS;
    if (CACert != NULL) {
        HcfX509CertCreateFunc func = GetHcfX509CertCreateFunc();
        if (func == NULL) {
            LOGE("HcfX509CertificateCreate is null.");
            return CF_NULL_POINTER;
        }
        CfEncodingBlob encodedByte = { NULL, 0, CF_FORMAT_DER };
        CACert->base.getEncoded((HcfCertificate *)CACert, &encodedByte);
        res = func(&encodedByte, &outAnchor->CACert);
        CF_FREE_PTR(encodedByte.data);
        if (res != CF_SUCCESS) {
            LOGE("HcfX509CertificateCreate fail, res : %{public}d!", res);
            return CF_ERR_MALLOC;
        }
    }
    if (CAPubKey != NULL) {
        res = DeepCopyBlobToBlob(CAPubKey, &outAnchor->CAPubKey);
        if (res != CF_SUCCESS) {
            LOGE("DeepCopyDataToBlob failed");
            FreeTrustAnchorData(outAnchor);
            return res;
        }
    }
    if (CASubject != NULL) {
        res = DeepCopyBlobToBlob(CASubject, &outAnchor->CASubject);
        if (res != CF_SUCCESS) {
            LOGE("DeepCopyDataToBlob failed");
            FreeTrustAnchorData(outAnchor);
            return res;
        }
    }
    if (nameConstraints != NULL) {
        res = DeepCopyBlobToBlob(nameConstraints, &outAnchor->nameConstraints);
        if (res != CF_SUCCESS) {
            LOGE("DeepCopyDataToBlob failed");
            FreeTrustAnchorData(outAnchor);
            return res;
        }
    }

    return res;
}

static CfResult FillValidateResult(HcfX509TrustAnchor *inputAnchor, X509 *cert, HcfX509CertChainValidateResult *result)
{
    if (inputAnchor == NULL || cert == NULL) {
        LOGE("FillValidateResult() invalidate params!");
        return CF_INVALID_PARAMS;
    }
    CfResult res = CF_SUCCESS;
    HcfX509Certificate *entityCert = NULL;
    res = X509ToHcfX509Certificate(cert, &entityCert);
    if (res != CF_SUCCESS) {
        LOGE("X509ToHcfX509Certificate() failed!");
        return res;
    }

    result->trustAnchor = inputAnchor;
    result->entityCert = entityCert;
    return res;
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

static CfResult ValidateCrlLocal(const HcfX509CertChainValidateParams *params, STACK_OF(X509) *x509CertChain)
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

static CfResult ValidateNC(STACK_OF(X509) *x509CertChain, CfBlob *nameConstraints)
{
    if (nameConstraints == NULL) {
        LOGI("NameConstraints from js is null!");
        return CF_SUCCESS;
    }

    const unsigned char *p = nameConstraints->data;
    NAME_CONSTRAINTS *nc =
        (NAME_CONSTRAINTS *)ASN1_item_d2i(NULL, &p, nameConstraints->size, ASN1_ITEM_rptr(NAME_CONSTRAINTS));
    if (nc == NULL) {
        LOGE("Get nameConstraints from js failed!");
        return CF_INVALID_PARAMS;
    }

    CfResult res = CF_SUCCESS;
    for (int i = 0; i < sk_X509_num(x509CertChain); i++) {
        X509 *cert = sk_X509_value(x509CertChain, i);
        if (cert == NULL) {
            LOGE("Get cert from stack to check nameConstraints failed!");
            res = CF_INVALID_PARAMS;
            break;
        }
        if (CheckIsLeafCert(cert) && !CheckIsSelfSigned(cert)) {
            if (NAME_CONSTRAINTS_check(cert, nc) != X509_V_OK) {
                LOGE("Check nameConstraints failed!");
                res = CF_INVALID_PARAMS;
                break;
            }
        }
    }

    NAME_CONSTRAINTS_free(nc);
    return res;
}

static CfResult ValidateTrustAnchor(const HcfX509TrustAnchorArray *trustAnchorsArray, X509 *rootCert,
    STACK_OF(X509) *x509CertChain, HcfX509TrustAnchor *trustAnchorResult)
{
    CfResult res = CF_SUCCESS;
    for (uint32_t i = 0; i < trustAnchorsArray->count; ++i) {
        X509 *mostTrustAnchorCert = NULL;
        HcfX509TrustAnchor *trustAnchor = trustAnchorsArray->data[i];
        res = GetTrustAnchor(trustAnchor, rootCert, &mostTrustAnchorCert);
        if (res != CF_SUCCESS) {
            LOGE("Get trust anchor cert failed, try next trustAnchor.");
            return res;
        }
        if (mostTrustAnchorCert == NULL) {
            LOGE("most trust anchor cert is null.");
            res = CF_INVALID_PARAMS; /* if validate trust anchor list failed, return the last error. */
            continue;
        }

        res = VerifyCertChain(mostTrustAnchorCert, x509CertChain);
        if (res != CF_SUCCESS) { // verify the data & crl list of certchain
            LOGI("verify one trustanchor failed, try next trustAnchor.");
            continue;
        }

        res = ValidateNC(x509CertChain, trustAnchor->nameConstraints);
        if (res != CF_SUCCESS) {
            LOGI("verify nameConstraints failed, try next trustAnchor.");
            continue;
        }
        res = CopyHcfX509TrustAnchor(trustAnchor, trustAnchorResult);
        if (res != CF_SUCCESS) {
            LOGE("CopyHcfX509TrustAnchor() failed!");
            return res;
        }
        break;
    }

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
    for (int i = 1; i < sk_X509_num(x509CertChain) - 1; i++) {
        X509 *x509 = sk_X509_value(x509CertChain, i);
        if (x509 == NULL) {
            LOGE("Get cert from stack to check crl failed!");
            res = CF_ERR_CRYPTO_OPERATION;
            break;
        }
        X509_CRL *crl = NULL;
        res = GetIntermediateCrlFromCertByDp(x509, &crl);
        if (res != CF_SUCCESS) {
            LOGE("Load intermediate crl from dp failed!");
            break;
        }
        if (crl == NULL) {
            LOGE("Crl url is not found in crl distribution points.");
            continue;
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
    X509_CRL *crl = GetCrlFromCert(params, x509);
    if (crl == NULL) {
        LOGE("Get crl online is null!");
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
    if (res != CF_SUCCESS) {
        return res;
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

static CfResult ValidateOcspLocal(OcspLocalParam localParam, STACK_OF(X509) *x509CertChain,
    HcfX509TrustAnchor *trustAnchor, const HcfX509CertChainValidateParams *params, int index)
{
    OCSP_RESPONSE *rsp = NULL;
    if (localParam.certIdInfo == NULL) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    HcfRevocationCheckParam *revo = params->revocationCheckParam;
    if (localParam.resp == NULL && index == 0 && revo->ocspResponses != NULL) {
        const unsigned char *p = revo->ocspResponses->data;
        rsp = d2i_OCSP_RESPONSE(NULL, &p, revo->ocspResponses->size);
        localParam.resp = rsp;
    }
    if (localParam.resp == NULL) {
        LOGE("The input data is null!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    CfResult res = ValidateOcspVerify(localParam, x509CertChain, trustAnchor, params, index);
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

static bool ConnectToServer(BIO *bio, int tryNum)
{
    int ret = 0;
    int num = tryNum;
    do {
        ret = BIO_do_connect_retry(bio, OCSP_CONN_TIMEOUT, OCSP_CONN_MILLISECOND);
        if (ret == 1) {
            break;
        } else if (ret <= 0) {
            LOGE("OCSP connecte service failed.");
            CfPrintOpensslError();
            if (BIO_should_retry(bio)) {
                LOGI("Try to connect service again, [%{public}d]st.", num);
                num--;
            } else {
                break;
            }
        }
    } while (ret <= 0 && num != 0);
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
            LOGE("Unable to get url from certificate, index = %{public}d.", index);
            X509_email_free(ocspList);
            return CF_ERR_CRYPTO_OPERATION;
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

    if (!ConnectToServer(*cbio, TRY_CONNECT_TIMES)) {
        LOGE("Unable to connect service.");
        BIO_free_all(*cbio);
        *cbio = NULL;
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
    res = SetRequestData(revo, *(params->req), params->certIdInfo);
    if (res != CF_SUCCESS) {
        LOGE("Unable to set request data.");
        goto exit;
    }

    *(params->resp) = SendReqBioCustom(*(params->cbio), host, path, *(params->req));
    if (*(params->resp) == NULL) {
        LOGE("Unable to send request.");
        res = CF_ERR_CRYPTO_OPERATION;
        goto exit;
    }

exit:
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
            (OcspLocalParam) { .req = req, .resp = resp, .certIdInfo = certIdInfo },
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

static void FreeCertIdInfo(OcspCertIdInfo *certIdInfo)
{
    if (certIdInfo->subjectCert != NULL) {
        X509_free(certIdInfo->subjectCert);
    }
    if (certIdInfo->issuerCert != NULL) {
        X509_free(certIdInfo->issuerCert);
    }
}

static CfResult OnlineVerifyOcsp(STACK_OF(X509) *x509CertChain, OcspCertIdInfo *certIdInfo,
    HcfX509TrustAnchor *trustAnchor, const HcfX509CertChainValidateParams *params)
{
    CfResult res = ValidateOcspOnline(x509CertChain, certIdInfo, trustAnchor, params, 0);
    if (res != CF_SUCCESS) {
        LOGE("ValidateOcspOnline leaf cert failed.");
        return res;
    }
    LOGD("ValidateOcspOnline leaf cert success.");
    if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE)) {
        for (int i = 1; i < sk_X509_num(x509CertChain) - 1; i++) {
            OcspCertIdInfo intermediateCertIdInfo = {0};
            res = CfGetCertIdInfo(x509CertChain, NULL, &intermediateCertIdInfo, i);
            if (res != CF_SUCCESS) {
                LOGE("Get cert id info from intermediate cert failed.");
                FreeCertIdInfo(&intermediateCertIdInfo);
                return res;
            }
            res = ValidateOcspOnline(x509CertChain, &intermediateCertIdInfo, trustAnchor, params, i);
            if (res == CF_SUCCESS) {
                LOGD("ValidateOcspOnline success, index = %{public}d.", i);
                FreeCertIdInfo(&intermediateCertIdInfo);
                continue;
            }
            LOGE("ValidateOcspOnline failed, index = %{public}d.", i);
            FreeCertIdInfo(&intermediateCertIdInfo);
            return res;
        }
    }
    return res;
}

static CfResult ValidateRevocationOnLine(const HcfX509CertChainValidateParams *params, STACK_OF(X509) *x509CertChain,
    HcfX509TrustAnchor *trustAnchor, OcspCertIdInfo *certIdInfo)
{
    CfResult res = CF_INVALID_PARAMS;
    if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_PREFER_OCSP)) {
        if ((res = OnlineVerifyOcsp(x509CertChain, certIdInfo, trustAnchor, params)) == CF_SUCCESS) {
            return res;
        }
        if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_FALLBACK_NO_PREFER)) {
            if ((res = ValidateCrlOnline(params, x509CertChain)) == CF_SUCCESS) {
                return res;
            }
        }
        if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_FALLBACK_LOCAL)) {
            if ((res = ValidateOcspLocal((OcspLocalParam) { .req = NULL, .resp = NULL, .certIdInfo = certIdInfo },
                                        x509CertChain, trustAnchor, params, 0)) == CF_SUCCESS) {
                return res;
            }
            return ValidateCrlLocal(params, x509CertChain);
        }
    } else {
        if ((res = ValidateCrlOnline(params, x509CertChain)) == CF_SUCCESS) {
            return res;
        }
        if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_FALLBACK_NO_PREFER)) {
            if ((res = OnlineVerifyOcsp(x509CertChain, certIdInfo, trustAnchor, params)) == CF_SUCCESS) {
                return res;
            }
        }
        if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_FALLBACK_LOCAL)) {
            if ((res = ValidateCrlLocal(params, x509CertChain)) == CF_SUCCESS) {
                return res;
            }
            return ValidateOcspLocal((OcspLocalParam) { .req = NULL, .resp = NULL, .certIdInfo = certIdInfo },
                                                        x509CertChain, trustAnchor, params, 0);
        }
    }
    return res;
}

static CfResult ValidateRevocationLocal(const HcfX509CertChainValidateParams *params, STACK_OF(X509) *x509CertChain,
    HcfX509TrustAnchor *trustAnchor, OcspCertIdInfo *certIdInfo)
{
    CfResult res = CF_INVALID_PARAMS;
    if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_PREFER_OCSP)) {
        if ((res = ValidateOcspLocal((OcspLocalParam) { .req = NULL, .resp = NULL, .certIdInfo = certIdInfo },
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

static CfResult ValidateRevocation(
    STACK_OF(X509) *x509CertChain, HcfX509TrustAnchor *trustAnchor, const HcfX509CertChainValidateParams *params)
{
    if (x509CertChain == NULL || params == NULL) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }

    if (params->revocationCheckParam && params->revocationCheckParam->options) {
        CfResult res = CF_INVALID_PARAMS;
        OcspCertIdInfo certIdInfo = {0};
        res = CfGetCertIdInfo(x509CertChain, params->revocationCheckParam->ocspDigest, &certIdInfo, 0);
        if (res != CF_SUCCESS) {
            LOGE("Get cert id info failed.");
            return res;
        }
        if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_ACCESS_NETWORK)) {
            res = ValidateRevocationOnLine(params, x509CertChain, trustAnchor, &certIdInfo);
            if (res != CF_SUCCESS) {
                LOGE("Try to validate revocation online failed.");
            }
        } else {
            res = ValidateRevocationLocal(params, x509CertChain, trustAnchor, &certIdInfo);
            if (res != CF_SUCCESS) {
                LOGE("Try to validate revocation local failed.");
            }
        }
        FreeCertIdInfo(&certIdInfo);
        return res;
    } else {
        return ValidateCrlLocal(params, x509CertChain);
    }
}

static CfResult ValidatePolicy(const STACK_OF(X509) *x509CertChain, HcfValPolicyType policy, CfBlob *sslHostname)
{
    CfResult res = CF_SUCCESS;
    switch (policy) {
        case VALIDATION_POLICY_TYPE_SSL:
            if (sslHostname == NULL) {
                LOGE("The specified policy is SSL, but sslHostname is null!");
                return CF_INVALID_PARAMS;
            }
            if (!X509_check_host(
                    sk_X509_value(x509CertChain, 0), (const char *)(sslHostname->data), sslHostname->size, 0, NULL)) {
                LOGE("Validate SSL policy failed!");
                return CF_ERR_CRYPTO_OPERATION;
            }
            break;
        case VALIDATION_POLICY_TYPE_X509:
            res = CF_SUCCESS;
            break;
        default:
            LOGE("Unknown policy type!");
            res = CF_INVALID_PARAMS;
            break;
    }
    return res;
}

static CfResult ValidateUseage(const STACK_OF(X509) *x509CertChain, HcfKuArray *keyUsage)
{
    CfResult res = CF_SUCCESS;
    if (keyUsage != NULL) {
        X509 *cert = sk_X509_value(x509CertChain, 0);
        if (cert == NULL) {
            return CF_INVALID_PARAMS;
        }
        uint32_t count = 0;
        for (size_t i = 0; i < keyUsage->count; i++) {
            HcfKeyUsageType kuType = keyUsage->data[i];
            uint32_t usageFlag = 0;
            switch (kuType) {
                case KEYUSAGE_DIGITAL_SIGNATURE:
                    usageFlag = X509v3_KU_DIGITAL_SIGNATURE;
                    break;
                case KEYUSAGE_NON_REPUDIATION:
                    usageFlag = X509v3_KU_NON_REPUDIATION;
                    break;
                case KEYUSAGE_KEY_ENCIPHERMENT:
                    usageFlag = X509v3_KU_KEY_ENCIPHERMENT;
                    break;
                case KEYUSAGE_DATA_ENCIPHERMENT:
                    usageFlag = X509v3_KU_DATA_ENCIPHERMENT;
                    break;
                case KEYUSAGE_KEY_AGREEMENT:
                    usageFlag = X509v3_KU_KEY_AGREEMENT;
                    break;
                case KEYUSAGE_KEY_CERT_SIGN:
                    usageFlag = X509v3_KU_KEY_CERT_SIGN;
                    break;
                case KEYUSAGE_CRL_SIGN:
                    usageFlag = X509v3_KU_CRL_SIGN;
                    break;
                case KEYUSAGE_ENCIPHER_ONLY:
                    usageFlag = X509v3_KU_ENCIPHER_ONLY;
                    break;
                case KEYUSAGE_DECIPHER_ONLY:
                    usageFlag = X509v3_KU_DECIPHER_ONLY;
                    break;
                default:
                    return CF_INVALID_PARAMS;
            }
            if ((X509_get_key_usage(cert) & usageFlag)) {
                count++;
            }
        }
        res = (count == keyUsage->count) ? CF_SUCCESS : CF_ERR_CRYPTO_OPERATION;
    }
    return res;
}

static CfResult ValidateStrategies(const HcfX509CertChainValidateParams *params, STACK_OF(X509) *x509CertChain)
{
    CfResult res = ValidateDate(x509CertChain, params->date);
    if (res != CF_SUCCESS) {
        LOGE("Validate date failed.");
        return res;
    }
    res = ValidatePolicy(x509CertChain, params->policy, params->sslHostname);
    if (res != CF_SUCCESS) {
        LOGE("Validate policy failed.");
        return res;
    }
    res = ValidateUseage(x509CertChain, params->keyUsage);
    if (res != CF_SUCCESS) {
        LOGE("Validate usage failed.");
        return res;
    }
    return res;
}

static CfResult CreateStoreAndLoadCerts(X509_STORE **store)
{
    *store = X509_STORE_new();
    if (*store == NULL) {
        LOGE("Failed to new store");
        return CF_ERR_CRYPTO_OPERATION;
    }

    if (X509_STORE_load_path(*store, CERT_VERIFY_DIR) != CF_OPENSSL_SUCCESS) {
        LOGE("Failed to load system certificates");
        X509_STORE_free(*store);
        *store = NULL;
        return CF_ERR_CRYPTO_OPERATION;
    }

    return CF_SUCCESS;
}

static bool IsCertInStore(X509_STORE_CTX *storeCtx, X509 *cert)
{
    if (storeCtx == NULL || cert == NULL) {
        return false;
    }

    X509_OBJECT *obj = X509_OBJECT_new();
    if (obj == NULL) {
        LOGE("x509Cert new object failed!");
        return false;
    }

    bool found = false;
    X509_NAME *subjectName = X509_get_subject_name(cert);
    if (subjectName == NULL) {
        X509_OBJECT_free(obj);
        LOGE("x509Cert get subject name failed!");
        return found;
    }

    if (X509_STORE_get_by_subject(storeCtx, X509_LU_X509, subjectName, obj) <= 0) {
        X509_OBJECT_free(obj);
        LOGE("x509Cert get subject failed!");
        return found;
    }

    X509 *storeCert = X509_OBJECT_get0_X509(obj);
    if (storeCert != NULL && X509_cmp(storeCert, cert) == 0) {
        found = true;
    }

    X509_OBJECT_free(obj);
    return found;
}

static CfResult TryGetIssuerFromStore(X509_STORE_CTX *storeCtx, X509 *rootCert, X509 **mostTrustCert)
{
    if (X509_STORE_CTX_get1_issuer(mostTrustCert, storeCtx, rootCert) == CF_OPENSSL_SUCCESS) {
        return CF_SUCCESS;
    }
    return CF_ERR_CRYPTO_OPERATION;
}

static CfResult TryUseRootCertAsTrust(X509_STORE_CTX *storeCtx, X509 *rootCert, X509 **mostTrustCert)
{
    if (!IsCertInStore(storeCtx, rootCert)) {
        LOGE("root cert not in store");
        return CF_ERR_CRYPTO_OPERATION;
    }

    *mostTrustCert = X509_dup(rootCert);
    if (*mostTrustCert == NULL) {
        LOGE("Failed to duplicate root certificate");
        return CF_ERR_CRYPTO_OPERATION;
    }

    return CF_SUCCESS;
}

static CfResult GetMostTrustCert(const HcfX509CertChainValidateParams *params, X509_STORE *store, X509 *rootCert,
    STACK_OF(X509) *x509CertChain, X509 **mostTrustCert)
{
    if (store == NULL || rootCert == NULL || mostTrustCert == NULL) {
        return CF_INVALID_PARAMS;
    }

    X509_STORE_CTX *storeCtx = X509_STORE_CTX_new();
    if (storeCtx == NULL) {
        LOGE("Failed to create store context");
        return CF_ERR_CRYPTO_OPERATION;
    }

    CfResult res = CF_ERR_CRYPTO_OPERATION;
    if (X509_STORE_CTX_init(storeCtx, store, rootCert, x509CertChain) != CF_OPENSSL_SUCCESS) {
        LOGE("Failed to initialize verify context");
        goto exit;
    }

    /* Try to get issuer certificate from store */
    res = TryGetIssuerFromStore(storeCtx, rootCert, mostTrustCert);
    if (res == CF_SUCCESS) {
        res = ValidateCertDate(*mostTrustCert, params->date);
        if (res != CF_SUCCESS) {
            LOGE("Validate date failed.");
            goto exit;
        }
        goto exit;
    }

    /* If failed to get issuer certificate, try to use root certificate as trust anchor */
    LOGW("Failed to get issuer certificate, trying root cert");
    res = TryUseRootCertAsTrust(storeCtx, rootCert, mostTrustCert);

exit:
    X509_STORE_CTX_free(storeCtx);
    return res;
}

static CfResult CreateTrustAnchorFromMostTrustCert(X509 *mostTrustCert, STACK_OF(X509) *x509CertChain,
    HcfX509TrustAnchor *trustAnchor)
{
    CfResult res = X509ToHcfX509Certificate(mostTrustCert, &(trustAnchor->CACert));
    if (res != CF_SUCCESS) {
        LOGE("Failed to convert X509 to HcfX509Certificate");
        return res;
    }

    res = GetPubKeyDataFromX509(mostTrustCert, &(trustAnchor->CAPubKey));
    if (res != CF_SUCCESS) {
        LOGE("Failed to get public key data");
        return res;
    }

    res = GetSubjectNameFromX509(mostTrustCert, &(trustAnchor->CASubject));
    if (res != CF_SUCCESS) {
        LOGE("Failed to get subject name");
        return res;
    }

    (void)GetNameConstraintsFromX509(mostTrustCert, &(trustAnchor->nameConstraints));
    res = ValidateNC(x509CertChain, trustAnchor->nameConstraints);
    if (res != CF_SUCCESS) {
        LOGI("verify nameConstraints failed, try next trustAnchor.");
        return res;
    }

    return CF_SUCCESS;
}

static CfResult ValidateTrustCertDir(const HcfX509CertChainValidateParams *params, X509 *rootCert,
    STACK_OF(X509) *x509CertChain, HcfX509TrustAnchor *trustAnchorResult)
{
    X509_STORE *store = NULL;
    X509 *mostTrustCert = NULL;

    CfResult res = CreateStoreAndLoadCerts(&store);
    if (res != CF_SUCCESS) {
        return res;
    }

    res = GetMostTrustCert(params, store, rootCert, x509CertChain, &mostTrustCert);
    X509_STORE_free(store);
    if (res != CF_SUCCESS) {
        return res;
    }

    res = VerifyCertChain(mostTrustCert, x509CertChain);
    if (res != CF_SUCCESS) {
        LOGE("verify cert chain failed.");
        X509_free(mostTrustCert);
        return res;
    }

    res = CreateTrustAnchorFromMostTrustCert(mostTrustCert, x509CertChain, trustAnchorResult);
    if (res != CF_SUCCESS) {
        X509_free(mostTrustCert);
        return res;
    }

    X509_free(mostTrustCert);
    return CF_SUCCESS;
}

static CfResult ValidateOther(const HcfX509CertChainValidateParams *params, STACK_OF(X509) *x509CertChain,
    HcfX509TrustAnchor **trustAnchorResult)
{
    if (sk_X509_num(x509CertChain) < 1) {
        LOGE("No cert in the certchain!");
        return CF_INVALID_PARAMS;
    }
    X509 *rootCert = sk_X509_value(x509CertChain, sk_X509_num(x509CertChain) - 1);
    if (rootCert == NULL) {
        LOGE("Sk X509 value failed!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    HcfX509TrustAnchor *anchorResult = (HcfX509TrustAnchor *)CfMalloc(sizeof(HcfX509TrustAnchor), 0);
    if (anchorResult == NULL) {
        LOGE("Failed to allocate anchor result");
        return CF_ERR_MALLOC;
    }

    CfResult res = CF_INVALID_PARAMS;
    if ((params->trustAnchors != NULL) && (params->trustAnchors->data != NULL) && (params->trustAnchors->count != 0)) {
        res = ValidateTrustAnchor(params->trustAnchors, rootCert, x509CertChain, anchorResult);
    }
    if ((res != CF_SUCCESS) && (params->trustSystemCa)) {
        res = ValidateTrustCertDir(params, rootCert, x509CertChain, anchorResult);
    }
    if (res != CF_SUCCESS) {
        LOGE("ValidateTrust failed!");
        FreeTrustAnchorData(anchorResult);
        CfFree(anchorResult);
        return res;
    }
    res = ValidateRevocation(x509CertChain, anchorResult, params);
    if (res != CF_SUCCESS) {
        FreeTrustAnchorData(anchorResult);
        CfFree(anchorResult);
        return res;
    }
    *trustAnchorResult = anchorResult;
    return res;
}

static CfResult Validate(
    HcfX509CertChainSpi *self, const HcfX509CertChainValidateParams *params, HcfX509CertChainValidateResult *result)
{
    if ((self == NULL) || (params == NULL) || (!(params->trustSystemCa) && ((params->trustAnchors == NULL) ||
        (params->trustAnchors->data == NULL) || (params->trustAnchors->count == 0))) || (result == NULL)) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetX509CertChainClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    if (!((HcfX509CertChainOpensslImpl *)self)->isOrder) {
        LOGE("MisOrder certs chain, verify failed!");
        return CF_INVALID_PARAMS;
    }

    STACK_OF(X509) *x509CertChain = ((HcfX509CertChainOpensslImpl *)self)->x509CertChain;
    /* when check time with X509_STORE_CTX_set_time, the noAfter of cert is exclusive, but in RFC5280, it is inclusive,
    * so check manually here.
    */
    CfResult res = ValidateStrategies(params, x509CertChain);
    if (res != CF_SUCCESS) {
        LOGE("Validate part1 failed!");
        return res;
    }

    HcfX509TrustAnchor *trustAnchorResult = NULL;
    res = ValidateOther(params, x509CertChain, &trustAnchorResult);
    if (res != CF_SUCCESS) {
        LOGE("Validate part2 failed!");
        return res;
    }

    X509 *entityCert = sk_X509_value(x509CertChain, 0);
    if (entityCert == NULL) {
        CfPrintOpensslError();
        FreeTrustAnchorData(trustAnchorResult);
        CF_FREE_PTR(trustAnchorResult);
        return CF_ERR_CRYPTO_OPERATION;
    }

    res = FillValidateResult(trustAnchorResult, entityCert, result);
    if (res != CF_SUCCESS) {
        FreeTrustAnchorData(trustAnchorResult);
        CF_FREE_PTR(trustAnchorResult);
    }
    return res;
}

static int32_t CreateX509CertChainPEM(const CfEncodingBlob *inData, STACK_OF(X509) **certchainObj)
{
    STACK_OF(X509) *certsChain = NULL;
    X509 *cert = NULL;

    BIO *bio = BIO_new_mem_buf(inData->data, inData->len);
    if (bio == NULL) {
        LOGE("BIO new mem buf failed!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    /* Create cert chain object */
    certsChain = sk_X509_new_null();
    if (certsChain == NULL) {
        BIO_free(bio);
        LOGE("Error creating certificate chain.");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    /* Add cert to cert chain object */
    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) && cert != NULL) {
        if (sk_X509_push(certsChain, cert) <= 0) {
            LOGE("Memory allocation failure!");
            X509_free(cert);
            BIO_free(bio);
            sk_X509_pop_free(certsChain, X509_free);
            return CF_ERR_CRYPTO_OPERATION;
        }
        LOGI("push cert to certsChain.");
    }

    if (sk_X509_num(certsChain) == 0) {
        LOGE("cert chain size = 0.");
        CfPrintOpensslError();
        BIO_free(bio);
        sk_X509_free(certsChain);
        return CF_ERR_CRYPTO_OPERATION;
    }

    *certchainObj = certsChain;
    BIO_free(bio);
    return CF_SUCCESS;
}

/*
* create x509 certchain from DER format streams
* input params: inData
* output params: certchainObj
*/
static int32_t CreateX509CertChainDER(const CfEncodingBlob *inData, STACK_OF(X509) **certchainObj)
{
    STACK_OF(X509) *certsChain = NULL;
    X509 *cert = NULL;
    const unsigned char *p = inData->data; // DER data
    size_t length = inData->len;

    certsChain = sk_X509_new_null();
    if (certsChain == NULL) {
        LOGE("Error creating certificate chain.");
        return CF_ERR_MALLOC;
    }

    while (p < inData->data + length) {
        size_t lengthLeft = (inData->data + length - p);
        cert = d2i_X509(NULL, &p, lengthLeft);
        if (cert == NULL) {
            LOGE("Failed to parse certificate.");
            CfPrintOpensslError();
            sk_X509_pop_free(certsChain, X509_free);
            return CF_ERR_CRYPTO_OPERATION;
        }
        if (sk_X509_push(certsChain, cert) <= 0) {
            LOGE("Memory allocation failure!");
            X509_free(cert);
            sk_X509_pop_free(certsChain, X509_free);
            return CF_ERR_MALLOC;
        }
        LOGI("push cert to certsChain.");
    }

    if (sk_X509_num(certsChain) == 0) {
        sk_X509_free(certsChain);
        LOGE("sk_X509_num failed.");
        return CF_INVALID_PARAMS;
    }
    *certchainObj = certsChain;
    return CF_SUCCESS;
}

/*
* create x509 certchain from pkcs#7 streams
* input params: inData
* output params: certchainObj
*/
static CfResult CreateX509CertChainPKCS7(const CfEncodingBlob *inData, STACK_OF(X509) **certchainObj)
{
    size_t dataLength = inData->len;
    uint8_t *data = inData->data;
    BIO *bio = BIO_new_mem_buf(data, dataLength);
    if (bio == NULL) {
        LOGE("malloc failed");
        CfPrintOpensslError();
        return CF_ERR_MALLOC;
    }

    PKCS7 *pkcs7 = d2i_PKCS7_bio(bio, NULL); // DER format .p7b file
    if (pkcs7 == NULL) {
        LOGE("Failed to parse PKCS7 data.");
        BIO_free(bio);
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    /* Get cert chain from pkcs7 object */
    STACK_OF(X509) *oriCertsChain = NULL;
    int i = OBJ_obj2nid(pkcs7->type);
    if (i == NID_pkcs7_signed && pkcs7->d.sign != NULL) {
        oriCertsChain = pkcs7->d.sign->cert;
    } else if (i == NID_pkcs7_signedAndEnveloped && pkcs7->d.signed_and_enveloped != NULL) {
        oriCertsChain = pkcs7->d.signed_and_enveloped->cert;
    }

    if (oriCertsChain == NULL || sk_X509_num(oriCertsChain) == 0) {
        LOGE("Failed to get certchain object.");
        PKCS7_free(pkcs7);
        BIO_free(bio);
        return CF_ERR_CRYPTO_OPERATION;
    }

    /* Clone a cert chain object for free pkcs7 object */
    STACK_OF(X509) *certsChain = sk_X509_deep_copy(oriCertsChain, X509_dup, X509_free);
    if (certsChain == NULL) {
        PKCS7_free(pkcs7);
        BIO_free(bio);
        LOGE("deep clone cert chain failed.");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    *certchainObj = certsChain;
    PKCS7_free(pkcs7);
    BIO_free(bio);
    return CF_SUCCESS;
}

static int32_t CreateX509CertChainInner(const CfEncodingBlob *inData, STACK_OF(X509) **certchainObj)
{
    int32_t ret = CF_SUCCESS;
    if (inData->encodingFormat == CF_FORMAT_PKCS7) {
        ret = CreateX509CertChainPKCS7(inData, certchainObj);
    } else if (inData->encodingFormat == CF_FORMAT_DER) {
        // create certchain from CF_FORMAT_DER
        ret = CreateX509CertChainDER(inData, certchainObj);
    } else if (inData->encodingFormat == CF_FORMAT_PEM) {
        // create certchain from CF_FORMAT_PEM
        ret = CreateX509CertChainPEM(inData, certchainObj);
    } else {
        LOGE("invalid input params");
        return CF_INVALID_PARAMS;
    }

    if (ret != CF_SUCCESS) {
        LOGE("error happened");
        return ret;
    }

    int num = sk_X509_num(*certchainObj);
    if (num > MAX_CERT_NUM || num == 0) {
        LOGE("certchain certs number :%{public}d invalid. create certChain failed! ", num);
        sk_X509_pop_free(*certchainObj, X509_free);
        *certchainObj = NULL;
        return CF_INVALID_PARAMS;
    }

    return CF_SUCCESS;
}

CfResult HcfX509CertChainByEncSpiCreate(const CfEncodingBlob *inStream, HcfX509CertChainSpi **spi)
{
    int32_t ret = CF_SUCCESS;
    if (inStream == NULL || inStream->data == NULL || inStream->len == 0 || spi == NULL) {
        LOGE("HcfX509CertChainByEncSpiCreate(), Invalid params!");
        return CF_INVALID_PARAMS;
    }
    HcfX509CertChainOpensslImpl *certChain =
        (HcfX509CertChainOpensslImpl *)CfMalloc(sizeof(HcfX509CertChainOpensslImpl), 0);
    if (certChain == NULL) {
        LOGE("Failed to allocate certChain spi object memory!");
        return CF_ERR_MALLOC;
    }

    ret = CreateX509CertChainInner(inStream, &(certChain->x509CertChain));
    if (ret != CF_SUCCESS || certChain->x509CertChain == NULL) {
        CfFree(certChain);
        certChain = NULL;
        LOGE("Failed to create x509 cert chain");
        return CF_INVALID_PARAMS;
    }
    bool isOrder = true;
    ret = IsOrderCertChain(certChain->x509CertChain, &isOrder);
    if (ret != CF_SUCCESS) {
        LOGE("cert chain isOrder failed!");
        sk_X509_pop_free(certChain->x509CertChain, X509_free);
        CfFree(certChain);
        certChain = NULL;
        return ret;
    }

    certChain->isOrder = isOrder;
    certChain->base.base.getClass = GetX509CertChainClass;
    certChain->base.base.destroy = DestroyX509CertChain;
    certChain->base.engineGetCertList = GetCertlist;
    certChain->base.engineValidate = Validate;
    certChain->base.engineToString = CfToString;
    certChain->base.engineHashCode = CfHashCode;
    *spi = (HcfX509CertChainSpi *)certChain;
    return CF_SUCCESS;
}

static CfResult GetCertsStack(const HcfX509CertificateArray *inCerts, STACK_OF(X509) *certsStack)
{
    for (uint32_t i = 0; i < inCerts->count; ++i) {
        X509 *cert = GetX509FromHcfX509Certificate((HcfCertificate *)inCerts->data[i]);
        if (cert == NULL) {
            LOGE("GetX509Cert from encodedBlob failed!");
            return CF_INVALID_PARAMS;
        }

        X509 *certDup = X509_dup(cert);
        if (certDup == NULL) {
            LOGE("Memory allocation failure!");
            return CF_ERR_MALLOC;
        }

        if (sk_X509_push(certsStack, certDup) <= 0) {
            LOGE("Memory allocation failure!");
            X509_free(certDup);
            return CF_ERR_MALLOC;
        }
    }

    return CF_SUCCESS;
}

CfResult HcfX509CertChainByArrSpiCreate(const HcfX509CertificateArray *inCerts, HcfX509CertChainSpi **spi)
{
    if (spi == NULL || inCerts == NULL || inCerts->data == NULL || inCerts->count == 0 ||
        inCerts->count > MAX_CERT_NUM) {
        LOGE("Invalid params, is null!");
        return CF_INVALID_PARAMS;
    }

    HcfX509CertChainOpensslImpl *certChain =
        (HcfX509CertChainOpensslImpl *)CfMalloc(sizeof(HcfX509CertChainOpensslImpl), 0);
    if (certChain == NULL) {
        LOGE("Failed to allocate certChain spi object memory!");
        return CF_ERR_MALLOC;
    }

    STACK_OF(X509) *certsStack = sk_X509_new_null();
    if (certsStack == NULL) {
        LOGE("Error creating certificate chain.");
        CfFree(certChain);
        certChain = NULL;
        return CF_ERR_MALLOC;
    }

    CfResult res = GetCertsStack(inCerts, certsStack);
    if (res != CF_SUCCESS) {
        LOGE("Get Certs Stack failed!");
        sk_X509_pop_free(certsStack, X509_free);
        CfFree(certChain);
        certChain = NULL;
        return res;
    }

    bool isOrder = true;
    res = IsOrderCertChain(certsStack, &isOrder);
    if (res != CF_SUCCESS) {
        LOGE("cert chain isOrder failed!");
        sk_X509_pop_free(certsStack, X509_free);
        CfFree(certChain);
        certChain = NULL;
        return res;
    }

    certChain->isOrder = isOrder;
    certChain->x509CertChain = certsStack;
    certChain->base.base.getClass = GetX509CertChainClass;
    certChain->base.base.destroy = DestroyX509CertChain;
    certChain->base.engineGetCertList = GetCertlist;
    certChain->base.engineValidate = Validate;
    certChain->base.engineToString = CfToString;
    certChain->base.engineHashCode = CfHashCode;
    *spi = (HcfX509CertChainSpi *)certChain;

    return CF_SUCCESS;
}

bool ValidatCertChainX509(STACK_OF(X509) * x509CertChain, HcfX509CertChainValidateParams params)
{
    CfResult res = ValidateDate(x509CertChain, params.date);
    if (res != CF_SUCCESS) {
        return false;
    }
    X509 *rootCert = sk_X509_value(x509CertChain, sk_X509_num(x509CertChain) - 1);
    if (rootCert == NULL) {
        return false;
    }

    res = CF_INVALID_PARAMS;
    HcfX509TrustAnchor trustAnchorResult = {};
    if ((params.trustAnchors != NULL) && (params.trustAnchors->data != NULL) && (params.trustAnchors->count != 0)) {
        res = ValidateTrustAnchor(params.trustAnchors, rootCert, x509CertChain, &trustAnchorResult);
    }
    if ((res != CF_SUCCESS) && (params.trustSystemCa)) {
        res = ValidateTrustCertDir(&params, rootCert, x509CertChain, &trustAnchorResult);
    }
    FreeTrustAnchorData(&trustAnchorResult);
    if (res != CF_SUCCESS) {
        return false;
    }

    if (ValidateCrlLocal(&params, x509CertChain) != CF_SUCCESS) {
        return false;
    }
    return true;
}

static void PopFreeCerts(STACK_OF(X509) *allCerts, STACK_OF(X509) *leafCerts)
{
    sk_X509_pop_free(allCerts, X509_free);
    sk_X509_pop_free(leafCerts, X509_free);
}

static CfResult PackCertChain(const HcfX509CertChainBuildParameters *inParams, STACK_OF(X509) * out)
{
    STACK_OF(X509) *allCerts = sk_X509_new_null();
    STACK_OF(X509) *leafCerts = sk_X509_new_null();
    if (allCerts == NULL || leafCerts == NULL) {
        sk_X509_free(allCerts);
        sk_X509_free(leafCerts);
        return CF_ERR_CRYPTO_OPERATION;
    }
    CfResult res = GetLeafCertsFromCertStack(inParams, allCerts, leafCerts);
    if (res != CF_SUCCESS) {
        PopFreeCerts(allCerts, leafCerts);
        return res;
    }

    int allCertsLen = sk_X509_num(allCerts);
    int leafCertsLen = sk_X509_num(leafCerts);

    for (int i = 0; i < leafCertsLen; i++) {
        X509 *leafCert = sk_X509_value(leafCerts, i);
        if (CheckIsSelfSigned(leafCert)) {
            sk_X509_push(out, X509_dup(leafCert));
            if (ValidatCertChainX509(out, inParams->validateParameters)) {
                PopFreeCerts(allCerts, leafCerts);
                return CF_SUCCESS;
            }
        } else {
            sk_X509_push(out, X509_dup(leafCert));
            X509_NAME *issuerName = X509_get_issuer_name(leafCert);
            X509 *ca = FindCertificateBySubject(allCerts, issuerName);

            int depth = 0;
            int maxdepth = inParams->maxlength < 0 ? allCertsLen : inParams->maxlength;
            while (ca && (depth < maxdepth)) {
                sk_X509_push(out, X509_dup(ca));
                issuerName = X509_get_issuer_name(ca);
                ca = FindCertificateBySubject(allCerts, issuerName);
                depth++;
            }
            if (ValidatCertChainX509(out, inParams->validateParameters)) {
                PopFreeCerts(allCerts, leafCerts);
                return CF_SUCCESS;
            }
        }

        while (sk_X509_num(out) > 0) {
            X509_free(sk_X509_pop(out));
        }
    }
    PopFreeCerts(allCerts, leafCerts);
    return CF_INVALID_PARAMS;
}

CfResult HcfX509CertChainByParamsSpiCreate(const HcfX509CertChainBuildParameters *inParams, HcfX509CertChainSpi **spi)
{
    if (inParams == NULL || spi == NULL) {
        LOGE("Get certchain from js error, the input is null!");
        return CF_INVALID_PARAMS;
    }

    STACK_OF(X509) *certStack = sk_X509_new_null();
    if (certStack == NULL) {
        LOGE("Failed to new certificate stack.");
        return CF_ERR_MALLOC;
    }

    CfResult res = PackCertChain(inParams, certStack);
    if (res != CF_SUCCESS) {
        LOGE("Failed to pack certificate chain.");
        sk_X509_pop_free(certStack, X509_free);
        return res;
    }

    if (sk_X509_num(certStack) == 0) {
        sk_X509_free(certStack);
        LOGE("certs chain count = 0.");
        return CF_ERR_CERT_HAS_EXPIRED;
    }

    bool isOrder = true;
    res = IsOrderCertChain(certStack, &isOrder);
    if (res != CF_SUCCESS) {
        LOGE("cert chain isOrder failed!");
        sk_X509_pop_free(certStack, X509_free);
        return res;
    }

    HcfX509CertChainOpensslImpl *certChain =
        (HcfX509CertChainOpensslImpl *)CfMalloc(sizeof(HcfX509CertChainOpensslImpl), 0);
    if (certChain == NULL) {
        LOGE("Failed to allocate certChain spi object memory!");
        return CF_ERR_MALLOC;
    }
    certChain->isOrder = isOrder;
    certChain->x509CertChain = certStack;
    certChain->base.base.getClass = GetX509CertChainClass;
    certChain->base.base.destroy = DestroyX509CertChain;
    certChain->base.engineGetCertList = GetCertlist;
    certChain->base.engineValidate = Validate;
    certChain->base.engineToString = CfToString;
    certChain->base.engineHashCode = CfHashCode;
    *spi = (HcfX509CertChainSpi *)certChain;

    return res;
}