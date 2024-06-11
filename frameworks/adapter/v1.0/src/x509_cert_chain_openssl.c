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

#include "cert_crl_common.h"
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
#define HTTP_TIMEOUT 10
#define TRY_CONNECT_TIMES 3
#define OCSP_CONN_MILLISECOND 5000 // millisecond
#define OCSP_CONN_TIMEOUT (-1)     // timeout == 0 means no timeout, < 0 means exactly one try.
#define HTTP_PORT "80"
#define HTTPS_PORT "443"

// helper functions
typedef struct {
    int32_t errCode;
    CfResult result;
} OpensslErrorToResult;

typedef struct {
    OCSP_REQUEST *req;
    OCSP_RESPONSE *resp;
    OCSP_CERTID *certid;
} OcspLocalParam;

typedef struct {
    X509 *leafCert;
    HcfRevocationCheckParam *revo;
    char **host;
    char **port;
    char **path;
    int *ssl;
} GetOcspUrlParams;

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
    if (self == NULL || !IsClassMatch(self, GetX509CertChainClass())) {
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

static CfResult X509ToHcfX509Certificate(X509 *cert, HcfX509Certificate **returnObj)
{
    if (cert == NULL) {
        LOGE("X509ToHcfX509Certificate() failed!");
        return CF_INVALID_PARAMS;
    }

    int dataLength = 0;
    uint8_t *certData = GetX509EncodedDataStream(cert, &dataLength);
    if (certData == NULL) {
        LOGE("Falied to get certificate data!");
        return CF_ERR_CRYPTO_OPERATION;
    }

    HcfX509Certificate *x509cert = NULL;
    CfEncodingBlob encodingBlob = { certData, dataLength, CF_FORMAT_DER };
    CfResult res = HcfX509CertificateCreate(&encodingBlob, &x509cert);
    if (res != CF_SUCCESS) {
        LOGE("HcfX509CertificateCreate fail, res : %d!", res);
        CfFree(certData);
        return CF_ERR_MALLOC;
    }

    *returnObj = x509cert;
    CfFree(certData);
    return res;
}

static CfResult GetCertlist(HcfX509CertChainSpi *self, HcfX509CertificateArray *certsList)
{
    if ((self == NULL) || (certsList == NULL)) {
        LOGE("[GetCertlist openssl] The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertChainClass())) {
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
            return CF_ERR_CRYPTO_OPERATION;
        }
        HcfX509Certificate *x509Cert = NULL;
        res = X509ToHcfX509Certificate(cert, &x509Cert);
        if (res != CF_SUCCESS) {
            LOGE("convert x509 to HcfX509Certificate failed!");
            FreeCertArrayData(certsList);
            return res;
        }
        certsList->data[i] = x509Cert;
    }

    return res;
}

static X509 *GetX509FromHcfX509Certificate(const HcfCertificate *cert)
{
    if (!IsClassMatch((CfObjectBase *)cert, HCF_X509_CERTIFICATE_CLASS)) {
        LOGE("Input wrong openssl class type!");
        return NULL;
    }
    HcfX509CertificateImpl *impl = (HcfX509CertificateImpl *)cert;
    if (!IsClassMatch((CfObjectBase *)(impl->spiObj), X509_CERT_OPENSSL_CLASS)) {
        LOGE("Input wrong openssl class type!");
        return NULL;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)(impl->spiObj);

    return realCert->x509;
}

static CfResult CheckCertChainIsRevoked(const STACK_OF(X509_CRL) * crlStack, const STACK_OF(X509) * certChain)
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
        }
    }

    return CF_SUCCESS;
}

static CfResult SetVerifyParams(X509_STORE *store, X509 *mostTrustCert)
{
    LOGI("add most-trusted cert's to store: ");
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

static CfResult VerifyCertChain(X509 *mostTrustCert, STACK_OF(X509) * x509CertChain)
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
            LOGI("Certificate verification succeeded.");
            res = CF_SUCCESS;
        } else {
            int32_t errCode = X509_STORE_CTX_get_error(ctx);
            const char *pChError = X509_verify_cert_error_string(errCode);
            LOGE("Failed to verify cert, openssl openssl error code = %d, error msg:%s.", errCode, pChError);
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
        X509NameType nameType = NAME_TYPE_SUBECT;
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
        LOGI("verify subject in trust anchor result: %d", compareSubjectFlag);
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
        LOGI("GetTrustAnchorCert() use trustAnchor->CACert.");
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
        CfEncodingBlob encodedByte = { NULL, 0, CF_FORMAT_DER };
        CACert->base.getEncoded((HcfCertificate *)CACert, &encodedByte);
        res = HcfX509CertificateCreate(&encodedByte, &outAnchor->CACert);
        if (res != CF_SUCCESS) {
            LOGE("HcfX509CertificateCreate fail, res : %d!", res);
            CfFree(encodedByte.data);
            return CF_ERR_MALLOC;
        }
        CfFree(encodedByte.data);
    }
    if (CAPubKey != NULL) {
        res = DeepCopyBlobToBlob(CAPubKey, &outAnchor->CAPubKey);
        if (res != CF_SUCCESS) {
            LOGE("DeepCopyDataToBlob failed");
            CfObjDestroy(outAnchor->CACert);
            return res;
        }
    }
    if (CASubject != NULL) {
        res = DeepCopyBlobToBlob(CASubject, &outAnchor->CASubject);
        if (res != CF_SUCCESS) {
            LOGE("DeepCopyDataToBlob failed");
            CfObjDestroy(outAnchor->CACert);
            CfBlobFree(&outAnchor->CAPubKey);
            return res;
        }
    }
    if (nameConstraints != NULL) {
        res = DeepCopyBlobToBlob(nameConstraints, &outAnchor->nameConstraints);
        if (res != CF_SUCCESS) {
            LOGE("DeepCopyDataToBlob failed");
            CfObjDestroy(outAnchor->CACert);
            CfBlobFree(&outAnchor->CAPubKey);
            CfBlobFree(&outAnchor->CASubject);
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
    HcfX509TrustAnchor *validateTrustAnchors = (HcfX509TrustAnchor *)CfMalloc(sizeof(HcfX509TrustAnchor), 0);
    if (validateTrustAnchors == NULL) {
        LOGE("FillValidateResult() malloc failed");
        return CF_ERR_MALLOC;
    }
    res = CopyHcfX509TrustAnchor(inputAnchor, validateTrustAnchors);
    if (res != CF_SUCCESS) {
        LOGE("CopyHcfX509TrustAnchor() failed!");
        CfFree(validateTrustAnchors);
        return res;
    }

    result->trustAnchor = validateTrustAnchors;
    HcfX509Certificate *entityCert = NULL;
    res = X509ToHcfX509Certificate(cert, &entityCert);
    if (res != CF_SUCCESS) {
        LOGE("X509ToHcfX509Certificate() failed!");
        FreeTrustAnchorData(result->trustAnchor);
        CF_FREE_PTR(result->trustAnchor);
        return res;
    }

    result->entityCert = entityCert;
    LOGI("FillValidateResult() success!");
    return res;
}

static X509_CRL *ParseX509CRL(const CfEncodingBlob *inStream)
{
    if ((inStream->data == NULL) || (inStream->len <= 0)) {
        LOGE("Invalid Paramas!");
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

static CfResult PushCrl2Stack(HcfX509CrlArray *crlArray, STACK_OF(X509_CRL) * outCrls)
{
    CfResult res = CF_SUCCESS;
    HcfX509Crl *x509Crl = NULL;
    X509_CRL *crl = NULL;
    STACK_OF(X509_CRL) *stackCrls = sk_X509_CRL_new_null();
    for (uint32_t i = 0; i < crlArray->count; i++) {
        CfEncodingBlob encodedBlob = { 0 };
        x509Crl = crlArray->data[i];
        res = x509Crl->getEncoded(x509Crl, &encodedBlob);
        if (res != CF_SUCCESS) {
            LOGE("Failed to getEncoded of crl!");
            sk_X509_CRL_pop_free(stackCrls, X509_CRL_free);
            return res;
        }

        crl = ParseX509CRL(&encodedBlob);
        if (crl == NULL) {
            LOGE("Failed to Parse x509 CRL!");
            CfFree(encodedBlob.data);
            sk_X509_CRL_pop_free(stackCrls, X509_CRL_free);
            return CF_INVALID_PARAMS;
        }
        if (sk_X509_CRL_push(stackCrls, crl) == 0) {
            LOGE("sk_X509_CRL_push failed!");
            CfFree(encodedBlob.data);
            sk_X509_CRL_pop_free(stackCrls, X509_CRL_free);
            X509_CRL_free(crl);
            return CF_ERR_CRYPTO_OPERATION;
        }
        CfFree(encodedBlob.data);
    }

    /* Move stackCrls elements to outCrls */
    while (sk_X509_CRL_num(stackCrls) > 0) {
        crl = sk_X509_CRL_pop(stackCrls);
        LOGI("push crl to crlStack.");
        if (sk_X509_CRL_push(outCrls, crl) == 0) {
            LOGE("sk_X509_CRL_push failed!");
            sk_X509_CRL_pop_free(stackCrls, X509_CRL_free);
            X509_CRL_free(crl);
            return CF_ERR_CRYPTO_OPERATION;
        }
    }

    sk_X509_CRL_free(stackCrls); /* Only free the stack, do not free elements */
    return res;
}

static CfResult GetX509Crls(const HcfCertCRLCollectionArray *certCRLCollections, STACK_OF(X509_CRL) * outCrls)
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

static CfResult ValidateCrlLocal(const HcfCertCRLCollectionArray *collectionArr, STACK_OF(X509) * x509CertChain)
{
    STACK_OF(X509_CRL) *crlStack = sk_X509_CRL_new_null();
    if (crlStack == NULL) {
        LOGE("sk X509 CRL new null failed!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    CfResult res = GetX509Crls(collectionArr, crlStack);
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
    res = CheckCertChainIsRevoked(crlStack, x509CertChain);
    sk_X509_CRL_pop_free(crlStack, X509_CRL_free);
    return res;
}

static CfResult ValidateNC(STACK_OF(X509) * x509CertChain, CfBlob *nameConstraints)
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
    STACK_OF(X509) * x509CertChain, HcfX509TrustAnchor **trustAnchorResult)
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
        *trustAnchorResult = trustAnchor;
        LOGI("Verify CertChain success!");
        break;
    }

    return res;
}

static const char *GetDpUrl(DIST_POINT *dp)
{
    GENERAL_NAMES *gens = NULL;
    GENERAL_NAME *gen = NULL;
    ASN1_STRING *url = NULL;

    if (dp == NULL || dp->distpoint == NULL || dp->distpoint->type != 0) {
        return NULL;
    }
    gens = dp->distpoint->name.fullname;
    if (gens == NULL) {
        return NULL;
    }
    for (int32_t i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
        gen = sk_GENERAL_NAME_value(gens, i);
        if (gen == NULL) {
            continue;
        }
        int gtype;
        url = GENERAL_NAME_get0_value(gen, &gtype);
        if (url == NULL) {
            continue;
        }
        if (gtype == GEN_URI && ASN1_STRING_length(url) > GEN_URI) {
            const char *uptr = (const char *)ASN1_STRING_get0_data(url);
            if (IsHttp(uptr)) {
                // can/should not use HTTPS here
                return uptr;
            }
        }
    }
    return NULL;
}

static X509_CRL *LoadCrlDp(STACK_OF(DIST_POINT) * crldp)
{
    const char *urlptr = NULL;
    for (int i = 0; i < sk_DIST_POINT_num(crldp); i++) {
        DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);
        urlptr = GetDpUrl(dp);
        if (urlptr != NULL) {
            return X509_CRL_load_http(urlptr, NULL, NULL, HTTP_TIMEOUT);
        }
    }
    return NULL;
}

static X509_CRL *GetCrlFromCert(const HcfX509CertChainValidateParams *params, X509 *x509)
{
    STACK_OF(DIST_POINT) *crlStack = X509_get_ext_d2i(x509, NID_crl_distribution_points, NULL, NULL);
    if (crlStack != NULL) {
        X509_CRL *crl = LoadCrlDp(crlStack);
        sk_DIST_POINT_pop_free(crlStack, DIST_POINT_free);
        if (crl != NULL) {
            return crl;
        }
    }

    if (params->revocationCheckParam->crlDownloadURI != NULL &&
        params->revocationCheckParam->crlDownloadURI->data != NULL) {
        char *url = (char *)params->revocationCheckParam->crlDownloadURI->data;
        if (IsUrlValid(url)) {
            return X509_CRL_load_http(url, NULL, NULL, HTTP_TIMEOUT);
        }
    }

    return NULL;
}

static CfResult ValidateCrlOnline(const HcfX509CertChainValidateParams *params, STACK_OF(X509) * x509CertChain)
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

    STACK_OF(X509_CRL) *crlStack = sk_X509_CRL_new_null();
    if (crlStack == NULL) {
        LOGE("Create crl stack failed!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    if (sk_X509_CRL_push(crlStack, crl) == 0) {
        LOGE("Push crl stack failed!");
        sk_X509_CRL_pop_free(crlStack, X509_CRL_free);
        return CF_ERR_CRYPTO_OPERATION;
    }
    if (CheckCertChainIsRevoked(crlStack, x509CertChain) != CF_SUCCESS) {
        LOGE("Certchain is revoked, verify failed!");
        sk_X509_CRL_pop_free(crlStack, X509_CRL_free);
        return CF_ERR_CRYPTO_OPERATION;
    }

    sk_X509_CRL_pop_free(crlStack, X509_CRL_free);
    return CF_SUCCESS;
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

static CfResult VerifyOcspSinger(OCSP_BASICRESP *bs, STACK_OF(X509) * certChain, X509 *cert)
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

static CfResult ParseResp(OCSP_BASICRESP *bs, OCSP_CERTID *certid)
{
    int ocspStatus;
    ASN1_GENERALIZEDTIME *thisUpdate = NULL;
    ASN1_GENERALIZEDTIME *nextUpdate = NULL;
    CfResult res = CF_ERR_CRYPTO_OPERATION;
    if (certid != NULL && OCSP_resp_find_status(bs, certid, &ocspStatus, NULL, NULL, &thisUpdate, &nextUpdate)) {
        LOGI("OCSP_resp_find_status success!");
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
    return res;
}

static CfResult ValidateOcspLocal(OcspLocalParam localParam, STACK_OF(X509) * x509CertChain,
    HcfX509TrustAnchor *trustAnchor, const HcfX509CertChainValidateParams *params)
{
    int i;
    OCSP_BASICRESP *bs = NULL;
    X509 *trustCert = NULL;

    HcfRevocationCheckParam *revo = params->revocationCheckParam;
    if (localParam.resp == NULL && revo->ocspResponses != NULL) {
        localParam.resp =
            d2i_OCSP_RESPONSE(NULL, (const unsigned char **)&(revo->ocspResponses->data), revo->ocspResponses->size);
    }
    if (localParam.resp == NULL || localParam.certid == NULL) {
        LOGE("The input data is null!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    if (OCSP_response_status(localParam.resp) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        LOGE("The resp status is not success!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    bs = OCSP_response_get1_basic(localParam.resp);
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
    if (revo->ocspResponderCert != NULL) {
        trustCert = GetX509FromHcfX509Certificate((HcfCertificate *)(params->revocationCheckParam->ocspResponderCert));
    } else if (trustAnchor->CACert != NULL) {
        trustCert = GetX509FromHcfX509Certificate((HcfCertificate *)(trustAnchor->CACert));
    } else {
        trustCert = sk_X509_value(x509CertChain, sk_X509_num(x509CertChain) - 1);
    }

    CfResult res = VerifyOcspSinger(bs, x509CertChain, trustCert);
    if (res != CF_SUCCESS) {
        LOGE("VerifySinger failed!");
        OCSP_BASICRESP_free(bs);
        return res;
    }
    res = ParseResp(bs, localParam.certid);
    OCSP_BASICRESP_free(bs);
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
        return NULL;
    }
    if (!OCSP_REQ_CTX_add1_header(ctx, "Host", host)) {
        return NULL;
    }
    if (!OCSP_REQ_CTX_set1_req(ctx, req)) {
        return NULL;
    }
    if (ctx == NULL) {
        return NULL;
    }
    int ret;
    int tryNum = TRY_CONNECT_TIMES;
    do {
        ret = OCSP_sendreq_nbio(&resp, ctx);
        tryNum--;
    } while ((ret == -1) && BIO_should_retry(bio) && tryNum != 0);
    OCSP_REQ_CTX_free(ctx);
    if (ret) {
        return resp;
    }
    return NULL;
}

static bool ConnectToServer(BIO *bio, int tryNum)
{
    int ret = 0;
    do {
        ret = BIO_do_connect_retry(bio, OCSP_CONN_TIMEOUT, OCSP_CONN_MILLISECOND);
        if (ret == 1) {
            LOGI("OCSP connecte service successfully.");
            break;
        } else if (ret <= 0) {
            LOGE("OCSP connecte service failed.");
            CfPrintOpensslError();
            if (BIO_should_retry(bio)) {
                LOGI("Try to connect service again, [%d]st.", tryNum);
                tryNum--;
            } else {
                break;
            }
        }
    } while (ret <= 0 && tryNum != 0);
    return (ret == 1 ? true : false);
}

static CfResult GetOcspUrl(GetOcspUrlParams *params)
{
    char *url = NULL;

    if (params->leafCert == NULL) {
        LOGE("Unable to get leafCert.");
        return CF_INVALID_PARAMS;
    }
    STACK_OF(OPENSSL_STRING) *ocspList = X509_get1_ocsp(params->leafCert);
    if (ocspList != NULL && sk_OPENSSL_STRING_num(ocspList) > 0) {
        url = sk_OPENSSL_STRING_value(ocspList, 0);
    }

    if (url == NULL) {
        if (params->revo->ocspResponderURI == NULL || params->revo->ocspResponderURI->data == NULL) {
            LOGE("Unable to get url.");
            return CF_ERR_CRYPTO_OPERATION;
        }
    }
    char *urlValiable = (url == NULL) ? (char *)(params->revo->ocspResponderURI->data) : url;
    if (!IsUrlValid(urlValiable)) {
        LOGE("Invalid url.");
        return CF_INVALID_PARAMS;
    }
    if (!OCSP_parse_url(urlValiable, params->host, params->port, params->path, params->ssl)) {
        LOGE("Unable to parse url.");
        return CF_ERR_CRYPTO_OPERATION;
    }
    return CF_SUCCESS;
}

static CfResult SetRequestData(HcfRevocationCheckParam *revo, OCSP_REQUEST *req, OCSP_CERTID *certId)
{
    if (OCSP_request_add0_id(req, certId) == NULL) {
        LOGE("Unable to add certId to req.");
        return CF_INVALID_PARAMS;
    }

    if (revo->ocspRequestExtension != NULL) {
        for (size_t i = 0; i < revo->ocspRequestExtension->count; i++) {
            X509_EXTENSION *ext =
                d2i_X509_EXTENSION(NULL, (const unsigned char **)&(revo->ocspRequestExtension->data[i].data),
                    revo->ocspRequestExtension->data[i].size);
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

static BIO *CreateConnectBio(char *host, char *port, int ssl)
{
    BIO *bio = NULL;
    if (ssl == 1) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();

        SSL_CTX *sslCtx = SSL_CTX_new(TLS_client_method());
        if (sslCtx == NULL) {
            LOGE("Create ssl context failed.");
            return NULL;
        }
        bio = BIO_new_ssl_connect(sslCtx);
        if (BIO_set_conn_hostname(bio, host) != 1) {
            LOGE("Set host name failed.");
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
            return NULL;
        }
    } else if (ssl) {
        if (BIO_set_conn_port(bio, HTTPS_PORT) != 1) {
            LOGE("Set port failed.");
            return NULL;
        }
    } else {
        if (BIO_set_conn_port(bio, HTTP_PORT) != 1) {
            LOGE("Set port failed.");
            return NULL;
        }
    }
    return bio;
}

static CfResult ValidateOcspOnline(STACK_OF(X509) * x509CertChain, OCSP_CERTID *certId, HcfX509TrustAnchor *trustAnchor,
    const HcfX509CertChainValidateParams *params)
{
    char *host = NULL;
    char *port = NULL;
    char *path = NULL;
    int ssl = 0;

    HcfRevocationCheckParam *revo = params->revocationCheckParam;

    CfResult res = GetOcspUrl(&(GetOcspUrlParams) { .leafCert = sk_X509_value(x509CertChain, 0),
        .revo = revo, .host = &host, .port = &port, .path = &path, .ssl = &ssl });
    if (res != CF_SUCCESS) {
        LOGE("Unable to get ocps url.");
        return res;
    }

    BIO *cbio = CreateConnectBio(host, port, ssl);
    if (cbio == NULL) {
        LOGE("Unable to create connection.");
        return CF_ERR_CRYPTO_OPERATION;
    }
    if (!ConnectToServer(cbio, TRY_CONNECT_TIMES)) {
        LOGE("Unable to connect service.");
        BIO_free_all(cbio);
        return CF_ERR_CRYPTO_OPERATION;
    }
    OCSP_REQUEST *req = OCSP_REQUEST_new();
    if (req == NULL) {
        LOGE("Unable to create req.");
        BIO_free_all(cbio);
        return CF_ERR_CRYPTO_OPERATION;
    }
    res = SetRequestData(revo, req, certId);
    if (res != CF_SUCCESS) {
        LOGE("Unable to set request data.");
        OCSP_REQUEST_free(req);
        BIO_free_all(cbio);
        return res;
    }

    /* Send OCSP request and wait for response */
    OCSP_RESPONSE *resp = SendReqBioCustom(cbio, host, path, req);
    if (resp == NULL) {
        LOGE("Unable to Send request.");
        OCSP_REQUEST_free(req);
        BIO_free_all(cbio);
        return CF_ERR_CRYPTO_OPERATION;
    }
    res = ValidateOcspLocal(
        (OcspLocalParam) { .req = req, .resp = resp, .certid = certId }, x509CertChain, trustAnchor, params);
    OCSP_REQUEST_free(req);
    BIO_free_all(cbio);
    OCSP_RESPONSE_free(resp);
    return res;
}

static const EVP_MD *GetHashDigest(const CfBlob *ocspDigest)
{
    if (ocspDigest == NULL || ocspDigest->data == NULL) {
        return EVP_sha256();
    }
    char *mdName = (char *)ocspDigest->data;
    if (strcmp(mdName, "SHA1") == 0) {
        return EVP_sha1();
    } else if (strcmp(mdName, "SHA224") == 0) {
        return EVP_sha224();
    } else if (strcmp(mdName, "SHA256") == 0) {
        return EVP_sha256();
    } else if (strcmp(mdName, "SHA384") == 0) {
        return EVP_sha384();
    } else if (strcmp(mdName, "SHA512") == 0) {
        return EVP_sha512();
    } else if (strcmp(mdName, "MD5") == 0) {
        return EVP_md5();
    }
    return EVP_sha256();
}

static OCSP_CERTID *GetCertId(STACK_OF(X509) * x509CertChain, const CfBlob *ocspDigest)
{
    X509 *issuerCert = NULL;
    X509 *leafCert = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *storeCtx = NULL;
    OCSP_CERTID* ret = NULL;
    do
    {
        store = X509_STORE_new();
        if (store == NULL) {
            LOGE("Unable to create store.");
            break;
        }
        leafCert = sk_X509_value(x509CertChain, 0);
        if (leafCert == NULL) {
            LOGE("Get the leaf cert is null.");
            break;
        }
        for (int i = 1; i < sk_X509_num(x509CertChain); i++) {
            X509 *tmpCert = sk_X509_value(x509CertChain, i);
            if ((X509_cmp(leafCert, tmpCert) != 0) && (!X509_STORE_add_cert(store, tmpCert))) {
                LOGE("Add cert to store failed.");
                break;
            }
        }
        storeCtx = X509_STORE_CTX_new();
        if (storeCtx == NULL) {
            LOGE("Unable to create storeCtx.");
            break;
        }
        if (X509_STORE_CTX_init(storeCtx, store, NULL, NULL) == 0) {
            LOGE("Unable to init STORE_CTX.");
            break;
        }

        if ((X509_STORE_CTX_get1_issuer(&issuerCert, storeCtx, leafCert) != 1) || (issuerCert == NULL)) {
            LOGE("Unable to get issuer.");
            break;
        }
        ret = OCSP_cert_to_id(GetHashDigest(ocspDigest), leafCert, issuerCert);
    } while (0);

    if (store != NULL) {
        X509_STORE_free(store);
    }
    if (storeCtx != NULL) {
        X509_STORE_CTX_free(storeCtx);
    }

    return ret;
}

static CfResult ValidateRevocationOnLine(const HcfX509CertChainValidateParams *params, STACK_OF(X509) * x509CertChain,
    HcfX509TrustAnchor *trustAnchor, OCSP_CERTID *certId)
{
    CfResult res = CF_INVALID_PARAMS;
    if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_PREFER_OCSP)) {
        if ((res = ValidateOcspOnline(x509CertChain, certId, trustAnchor, params)) == CF_SUCCESS) {
            LOGI("Excute validate ocsp online success.");
            return res;
        }
        if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_FALLBACK_NO_PREFER)) {
            if ((res = ValidateCrlOnline(params, x509CertChain)) == CF_SUCCESS) {
                LOGI("Excute validateCRLOnline success.");
                return res;
            }
        }
        if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_FALLBACK_LOCAL)) {
            if ((res = ValidateOcspLocal((OcspLocalParam) { .req = NULL, .resp = NULL, .certid = certId },
                     x509CertChain, trustAnchor, params)) == CF_SUCCESS) {
                LOGI("Excute validate ocsp local success.");
                return res;
            }
            LOGI("Try to run CRLLocal.");
            return ValidateCrlLocal(params->certCRLCollections, x509CertChain);
        }
    } else {
        if ((res = ValidateCrlOnline(params, x509CertChain)) == CF_SUCCESS) {
            LOGI("Excute validateCRLOnline success.");
            return res;
        }
        if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_FALLBACK_NO_PREFER)) {
            if ((res = ValidateOcspOnline(x509CertChain, certId, trustAnchor, params)) == CF_SUCCESS) {
                LOGI("Excute validate ocsp online success.");
                return res;
            }
        }
        if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_FALLBACK_LOCAL)) {
            if ((res = ValidateCrlLocal(params->certCRLCollections, x509CertChain)) == CF_SUCCESS) {
                LOGI("Excute validateCRLLocal success.");
                return res;
            }
            LOGI("Try to ValidateOcspLocal.");
            return ValidateOcspLocal(
                (OcspLocalParam) { .req = NULL, .resp = NULL, .certid = certId }, x509CertChain, trustAnchor, params);
        }
    }
    return res;
}

static CfResult ValidateRevocationLocal(const HcfX509CertChainValidateParams *params, STACK_OF(X509) * x509CertChain,
    HcfX509TrustAnchor *trustAnchor, OCSP_CERTID *certId)
{
    CfResult res = CF_INVALID_PARAMS;
    if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_PREFER_OCSP)) {
        if ((res = ValidateOcspLocal((OcspLocalParam) { .req = NULL, .resp = NULL, .certid = certId }, x509CertChain,
                 trustAnchor, params)) == CF_SUCCESS) {
            LOGI("Excute validate ocsp local success.");
            return res;
        }
    } else {
        if ((res = ValidateCrlLocal(params->certCRLCollections, x509CertChain)) == CF_SUCCESS) {
            LOGI("Excute validate crl local success.");
            return res;
        }
    }
    return CF_INVALID_PARAMS;
}

static CfResult ValidateRevocation(
    STACK_OF(X509) * x509CertChain, HcfX509TrustAnchor *trustAnchor, const HcfX509CertChainValidateParams *params)
{
    if (x509CertChain == NULL || params == NULL) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }

    if (params->revocationCheckParam && params->revocationCheckParam->options) {
        CfResult res = CF_INVALID_PARAMS;
        OCSP_CERTID *certId = GetCertId(x509CertChain, params->revocationCheckParam->ocspDigest);
        if (ContainsOption(params->revocationCheckParam->options, REVOCATION_CHECK_OPTION_ACCESS_NETWORK)) {
            res = ValidateRevocationOnLine(params, x509CertChain, trustAnchor, certId);
            if (res != CF_SUCCESS) {
                LOGI("Try to validate revocation online failed.");
                return res;
            }
        } else {
            res = ValidateRevocationLocal(params, x509CertChain, trustAnchor, certId);
            if (res != CF_SUCCESS) {
                LOGI("Try to validate revocation local failed.");
                return res;
            }
        }
        return res;
    } else {
        LOGI("Try to ValidateCrlLocal.");
        return ValidateCrlLocal(params->certCRLCollections, x509CertChain);
    }
}

static CfResult ValidateDate(const STACK_OF(X509) * x509CertChain, CfBlob *date)
{
    if (date == NULL) {
        LOGI("date is null");
        return CF_SUCCESS;
    }
    if (!CfBlobIsStr(date)) {
        LOGE("time format is invalid");
        return CF_INVALID_PARAMS;
    }
    ASN1_TIME *asn1InputDate = ASN1_TIME_new();
    if (asn1InputDate == NULL) {
        LOGE("Failed to malloc for asn1 time.");
        return CF_ERR_MALLOC;
    }
    if (ASN1_TIME_set_string(asn1InputDate, (const char *)date->data) != CF_OPENSSL_SUCCESS) {
        LOGE("Failed to set time for asn1 time.");
        CfPrintOpensslError();
        ASN1_TIME_free(asn1InputDate);
        return CF_INVALID_PARAMS;
    }
    CfResult res = CF_SUCCESS;
    int certsNum = sk_X509_num(x509CertChain);
    for (int i = 0; i < certsNum; ++i) {
        X509 *cert = sk_X509_value(x509CertChain, i);
        if (cert == NULL) {
            LOGE("sk X509 value is null, failed!");
            CfPrintOpensslError();
            ASN1_TIME_free(asn1InputDate);
            return CF_ERR_CRYPTO_OPERATION;
        }
        res = CompareDateWithCertTime(cert, asn1InputDate);
        if (res != CF_SUCCESS) {
            LOGE("check validate failed.");
            ASN1_TIME_free(asn1InputDate);
            return res;
        }
    }
    ASN1_TIME_free(asn1InputDate);
    return res;
}

static CfResult ValidatePolicy(const STACK_OF(X509) * x509CertChain, HcfValPolicyType policy, CfBlob *sslHostname)
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

static CfResult ValidateUseage(const STACK_OF(X509) * x509CertChain, HcfKuArray *keyUsage)
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

static CfResult ValidateStrategies(const HcfX509CertChainValidateParams *params, STACK_OF(X509) * x509CertChain)
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

static CfResult ValidateOther(const HcfX509CertChainValidateParams *params, STACK_OF(X509) * x509CertChain,
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

    CfResult res = ValidateTrustAnchor(params->trustAnchors, rootCert, x509CertChain, trustAnchorResult);
    if (res != CF_SUCCESS) {
        LOGE("ValidateTrustAnchor failed!");
        return res;
    }
    res = ValidateRevocation(x509CertChain, *trustAnchorResult, params);
    if (res != CF_SUCCESS) {
        return res;
    }
    return res;
}

static CfResult Validate(
    HcfX509CertChainSpi *self, const HcfX509CertChainValidateParams *params, HcfX509CertChainValidateResult *result)
{
    if ((self == NULL) || (params == NULL) || (params->trustAnchors == NULL) || (params->trustAnchors->data == NULL) ||
        (params->trustAnchors->count == 0) || (result == NULL)) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertChainClass())) {
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
        return CF_ERR_CRYPTO_OPERATION;
    }

    return FillValidateResult(trustAnchorResult, entityCert, result);
}

static int32_t CreateX509CertChainPEM(const CfEncodingBlob *inData, STACK_OF(X509) * *certchainObj)
{
    STACK_OF(X509) *certsChain = NULL;
    X509 *cert = NULL;

    BIO *bio = BIO_new_mem_buf(inData->data, inData->len);
    if (bio == NULL) {
        LOGE("BIO new mem buf failed!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    LOGI("createX509CertChainPEM CfEncodingBlob inData len: %u .", inData->len);

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
static int32_t CreateX509CertChainDER(const CfEncodingBlob *inData, STACK_OF(X509) * *certchainObj)
{
    STACK_OF(X509) *certsChain = NULL;
    X509 *cert = NULL;
    const unsigned char *p = inData->data; // DER data
    size_t length = inData->len;

    LOGI("createX509CertChainDER CfEncodingBlob inData len: %u.", length);
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
        LOGE("certs chain count = 0.");
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
static CfResult CreateX509CertChainPKCS7(const CfEncodingBlob *inData, STACK_OF(X509) * *certchainObj)
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
    LOGE("pkcs7->type : %d .", i);
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

static int32_t CreateX509CertChainInner(const CfEncodingBlob *inData, STACK_OF(X509) * *certchainObj)
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
        LOGE("certchain certs number :%u  invalid. create certChain failed! ", num);
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
        LOGE("Failed to create x509 cert chain");
        return CF_INVALID_PARAMS;
    }
    bool isOrder = true;
    ret = IsOrderCertChain(certChain->x509CertChain, &isOrder);
    if (ret != CF_SUCCESS) {
        LOGE("cert chain isOrder failed!");
        sk_X509_pop_free(certChain->x509CertChain, X509_free);
        CfFree(certChain);
        return ret;
    }

    certChain->isOrder = isOrder;
    certChain->base.base.getClass = GetX509CertChainClass;
    certChain->base.base.destroy = DestroyX509CertChain;
    certChain->base.engineGetCertList = GetCertlist;
    certChain->base.engineValidate = Validate;
    certChain->base.engineToString = ToString;
    certChain->base.engineHashCode = HashCode;
    *spi = (HcfX509CertChainSpi *)certChain;
    return CF_SUCCESS;
}

static CfResult GetCertsStack(const HcfX509CertificateArray *inCerts, STACK_OF(X509) * certsStack)
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
        return CF_ERR_MALLOC;
    }

    CfResult res = GetCertsStack(inCerts, certsStack);
    if (res != CF_SUCCESS) {
        LOGE("Get Certs Stack failed!");
        sk_X509_pop_free(certsStack, X509_free);
        CfFree(certChain);
        return res;
    }

    bool isOrder = true;
    res = IsOrderCertChain(certsStack, &isOrder);
    if (res != CF_SUCCESS) {
        LOGE("cert chain isOrder failed!");
        sk_X509_pop_free(certsStack, X509_free);
        CfFree(certChain);
        return res;
    }

    certChain->isOrder = isOrder;
    certChain->x509CertChain = certsStack;
    certChain->base.base.getClass = GetX509CertChainClass;
    certChain->base.base.destroy = DestroyX509CertChain;
    certChain->base.engineGetCertList = GetCertlist;
    certChain->base.engineValidate = Validate;
    certChain->base.engineToString = ToString;
    certChain->base.engineHashCode = HashCode;
    *spi = (HcfX509CertChainSpi *)certChain;

    return CF_SUCCESS;
}

static CfResult GetCertChainFromCollection(const HcfX509CertChainBuildParameters *inParams, STACK_OF(X509) * certStack)
{
    if (inParams->validateParameters.certCRLCollections == NULL) {
        LOGE("The input is NULL!");
        return CF_INVALID_PARAMS;
    }

    for (uint32_t i = 0; i < inParams->validateParameters.certCRLCollections->count; ++i) {
        HcfX509CertificateArray retCerts = { NULL, 0 };
        HcfCertCrlCollection *collection = inParams->validateParameters.certCRLCollections->data[i];
        CfResult res = collection->selectCerts(collection, &(inParams->certMatchParameters), &retCerts);
        if (res != CF_SUCCESS) {
            LOGE("Get mached certs failed!");
            return res;
        }
        for (uint32_t j = 0; j < retCerts.count; ++j) {
            X509 *cert = GetX509FromHcfX509Certificate((HcfCertificate *)retCerts.data[j]);
            if (cert == NULL) {
                LOGE("GetX509Cert from inParams failed!");
                return CF_INVALID_PARAMS;
            }

            X509 *certDup = X509_dup(cert);
            if (certDup == NULL) {
                LOGE("Memory allocation failure!");
                return CF_ERR_MALLOC;
            }
            if (sk_X509_push(certStack, certDup) <= 0) {
                LOGE("Push cert to SK failed!");
                X509_free(certDup);
                return CF_ERR_CRYPTO_OPERATION;
            }
        }
    }
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
    HcfX509TrustAnchor *trustAnchorResult = NULL;
    if (ValidateTrustAnchor(params.trustAnchors, rootCert, x509CertChain, &trustAnchorResult) != CF_SUCCESS) {
        return false;
    }
    if (ValidateCrlLocal(params.certCRLCollections, x509CertChain) != CF_SUCCESS) {
        return false;
    }
    return true;
}

CfResult GetCertStackInner(
    const HcfX509CertChainBuildParameters *inParams, STACK_OF(X509) * allCerts, STACK_OF(X509) * leafCerts)
{
    CfResult res = GetCertChainFromCollection(inParams, allCerts);
    if (res != CF_SUCCESS) {
        LOGE("Error geting certificates from collection.");
        return res;
    }

    int allCertsLen = sk_X509_num(allCerts);
    if (allCertsLen == 0) {
        LOGE("The num of all certificate from collection is 0.");
        return CF_INVALID_PARAMS;
    }
    for (int i = 0; i < allCertsLen; ++i) {
        if (CheckIsLeafCert(sk_X509_value(allCerts, i))) {
            if (sk_X509_push(leafCerts, X509_dup(sk_X509_value(allCerts, i))) != 1) {
                LOGE("Push the cert into stack failed.");
                return CF_ERR_CRYPTO_OPERATION;
            }
        }
    }

    int leafCertsLen = sk_X509_num(leafCerts);
    if (leafCertsLen == 0) {
        LOGE("The num of leaf certificate is 0.");
        return CF_INVALID_PARAMS;
    }
    return CF_SUCCESS;
}

CfResult PackCertChain(const HcfX509CertChainBuildParameters *inParams, STACK_OF(X509) * out)
{
    STACK_OF(X509) *allCerts = sk_X509_new_null();
    STACK_OF(X509) *leafCerts = sk_X509_new_null();
    if (allCerts == NULL || leafCerts == NULL) {
        return CF_ERR_CRYPTO_OPERATION;
    }
    CfResult res = GetCertStackInner(inParams, allCerts, leafCerts);
    if (res != CF_SUCCESS) {
        sk_X509_pop_free(allCerts, X509_free);
        sk_X509_pop_free(leafCerts, X509_free);
        return res;
    }

    int allCertsLen = sk_X509_num(allCerts);
    int leafCertsLen = sk_X509_num(leafCerts);
    LOGI("The num of certificates is:[allCertsLen:%d, leafCertsLen:%d].", allCertsLen, leafCertsLen);

    for (int i = 0; i < leafCertsLen; i++) {
        X509 *leafCert = sk_X509_value(leafCerts, i);
        if (CheckIsSelfSigned(leafCert)) {
            sk_X509_push(out, X509_dup(leafCert));
            if (ValidatCertChainX509(out, inParams->validateParameters)) {
                sk_X509_pop_free(allCerts, X509_free);
                sk_X509_pop_free(leafCerts, X509_free);
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
                sk_X509_pop_free(allCerts, X509_free);
                sk_X509_pop_free(leafCerts, X509_free);
                return CF_SUCCESS;
            }
        }

        while (sk_X509_num(out) > 0) {
            X509_free(sk_X509_pop(out));
        }
    }
    sk_X509_pop_free(allCerts, X509_free);
    sk_X509_pop_free(leafCerts, X509_free);
    return CF_INVALID_PARAMS;
}

CfResult HcfX509CertChainByParamsSpiCreate(const HcfX509CertChainBuildParameters *inParams, HcfX509CertChainSpi **spi)
{
    if (inParams == NULL || spi == NULL) {
        LOGE("Get certchain from js error, the input is null!");
        return CF_INVALID_PARAMS;
    }
    HcfX509CertChainOpensslImpl *certChain =
        (HcfX509CertChainOpensslImpl *)CfMalloc(sizeof(HcfX509CertChainOpensslImpl), 0);
    if (certChain == NULL) {
        LOGE("Failed to allocate certChain spi object memory!");
        return CF_ERR_MALLOC;
    }

    STACK_OF(X509) *certStack = sk_X509_new_null();
    if (certStack == NULL) {
        LOGE("Error creating certificate chain.");
        CfFree(certChain);
        return CF_ERR_MALLOC;
    }

    CfResult res = PackCertChain(inParams, certStack);
    if (res != CF_SUCCESS) {
        LOGE("Error creating certificate chain.");
        sk_X509_pop_free(certStack, X509_free);
        CfFree(certChain);
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
        CfFree(certChain);
        return res;
    }
    certChain->isOrder = isOrder;
    certChain->x509CertChain = certStack;
    certChain->base.base.getClass = GetX509CertChainClass;
    certChain->base.base.destroy = DestroyX509CertChain;
    certChain->base.engineGetCertList = GetCertlist;
    certChain->base.engineValidate = Validate;
    *spi = (HcfX509CertChainSpi *)certChain;

    return res;
}

static CfResult GetPubFromP12(EVP_PKEY *pkey, CfBlob **pub)
{
    *pub = (CfBlob *)CfMalloc(sizeof(CfBlob), 0);
    if (*pub == NULL) {
        LOGE("Failed to malloc pub key!");
        return CF_ERR_MALLOC;
    }
    int32_t size = i2d_PUBKEY(pkey, &((*pub)->data));
    if (size < 0) {
        LOGE("Failed to convert public key to DER format");
        CfFree(*pub);
        *pub = NULL;
        return CF_INVALID_PARAMS;
    }
    (*pub)->size = (uint32_t)size;
    return CF_SUCCESS;
}

static CfResult GetSubjectFromP12(X509 *cert, CfBlob **sub)
{
    X509_NAME *name = X509_get_subject_name(cert);
    if (!name) {
        LOGE("Failed to get subject name!");
        return CF_INVALID_PARAMS;
    }
    *sub = (CfBlob *)CfMalloc(sizeof(CfBlob), 0);
    if (*sub == NULL) {
        LOGE("Failed to malloc pub key!");
        return CF_ERR_MALLOC;
    }

    int32_t size = i2d_X509_NAME(name, &((*sub)->data));
    if (size <= 0) {
        LOGE("Failed to get subject DER data!");
        CfFree(*sub);
        *sub = NULL;
        return CF_ERR_CRYPTO_OPERATION;
    }
    (*sub)->size = (uint32_t)size;
    return CF_SUCCESS;
}

static CfResult GetNameConstraintsFromP12(X509 *cert, CfBlob **name)
{
    ASN1_BIT_STRING *nc = X509_get_ext_d2i(cert, NID_name_constraints, NULL, NULL);
    if (!nc) {
        LOGE("No nameConstraints found in certificate");
        return CF_INVALID_PARAMS;
    }
    *name = (CfBlob *)CfMalloc(sizeof(CfBlob), 0);
    if (*name == NULL) {
        LOGE("Failed to malloc pub key!");
        return CF_ERR_MALLOC;
    }
    int32_t size = i2d_ASN1_BIT_STRING(nc, &((*name)->data));
    if (size < 0) {
        LOGE("Failed to get name DER data!");
        CfFree(*name);
        *name = NULL;
        return CF_ERR_CRYPTO_OPERATION;
    }
    (*name)->size = (uint32_t)size;
    return CF_SUCCESS;
}

static CfResult ProcessP12Data(EVP_PKEY *pkey, X509 *cert, STACK_OF(X509) * ca, HcfX509TrustAnchorArray **result)
{
    CfResult ret = CF_SUCCESS;
    for (int i = 0; i < sk_X509_num(ca); i++) {
        // CACert
        ret = X509ToHcfX509Certificate(sk_X509_value(ca, i), &((*result)->data[i]->CACert));
        if (ret != CF_SUCCESS) {
            LOGD("Failed to get %d CACert!", i);
        }

        // CAPubKey
        ret = GetPubFromP12(X509_get_pubkey(sk_X509_value(ca, i)), &((*result)->data[i]->CAPubKey));
        if (ret != CF_SUCCESS) {
            LOGD("Failed to get %d CAPubKey!", i);
        }

        // CASubject
        ret = GetSubjectFromP12(cert, &((*result)->data[i]->CASubject));
        if (ret != CF_SUCCESS) {
            LOGD("Failed to get %d CASubject!", i);
        }

        // nameConstraints
        ret = GetNameConstraintsFromP12(cert, &((*result)->data[i]->nameConstraints));
        if (ret != CF_SUCCESS) {
            LOGD("Failed to get %d nameConstraints!", i);
        }
    }

    return CF_SUCCESS;
}

static void FreeHcfX509TrustAnchorArray(HcfX509TrustAnchorArray *trustAnchorArray, bool freeCertFlag)
{
    if (trustAnchorArray == NULL) {
        return;
    }
    for (uint32_t i = 0; i < trustAnchorArray->count; i++) {
        if (trustAnchorArray->data[i] != NULL) {
            if (freeCertFlag) {
                CfObjDestroy(trustAnchorArray->data[i]->CACert);
            }
            trustAnchorArray->data[i]->CACert = NULL;
            CfBlobFree(&trustAnchorArray->data[i]->CAPubKey);
            CfBlobFree(&trustAnchorArray->data[i]->CASubject);
            CfBlobFree(&trustAnchorArray->data[i]->nameConstraints);
            CfFree(trustAnchorArray->data[i]);
            trustAnchorArray->data[i] = NULL;
        }
    }

    CfFree(trustAnchorArray);
}

CfResult HcfX509CreateTrustAnchorWithKeyStoreFunc(
    const CfBlob *keyStore, const CfBlob *pwd, HcfX509TrustAnchorArray **trustAnchorArray)
{
    if (keyStore == NULL || pwd == NULL || trustAnchorArray == NULL) {
        LOGE("Invalid params!");
        return CF_INVALID_PARAMS;
    }
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    PKCS12 *p12 = (PKCS12 *)ASN1_item_d2i_ex(
        NULL, (const unsigned char **)&(keyStore->data), keyStore->size, ASN1_ITEM_rptr(PKCS12), NULL, NULL);
    if (p12 == NULL) {
        LOGE("Error reading PKCS#12 file!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    if (!PKCS12_parse(p12, (const char *)pwd->data, &pkey, &cert, &ca) || (ca == NULL) || (cert == NULL)) {
        LOGE("PKCS12_parse cert ca failed!");
        PKCS12_free(p12);
        return CF_ERR_CRYPTO_OPERATION;
    }
    PKCS12_free(p12);

    HcfX509TrustAnchorArray *anchor = (HcfX509TrustAnchorArray *)(CfMalloc(sizeof(HcfX509TrustAnchorArray), 0));
    if (anchor == NULL) {
        LOGE("Failed to allocate trustAnchorArray memory!");
        return CF_ERR_MALLOC;
    }
    int32_t count = sk_X509_num(ca);
    anchor->count = (uint32_t)(count < 0 ? 0 : count);
    anchor->data = (HcfX509TrustAnchor **)(CfMalloc(anchor->count * sizeof(HcfX509TrustAnchor *), 0));
    if (anchor->data == NULL) {
        LOGE("Failed to allocate data memory!");
        CfFree(anchor);
        return CF_ERR_MALLOC;
    }
    for (uint32_t i = 0; i < anchor->count; i++) {
        anchor->data[i] = (HcfX509TrustAnchor *)(CfMalloc(sizeof(HcfX509TrustAnchor), 0));
        if (anchor->data[i] == NULL) {
            LOGE("Failed to allocate data memory!");
            FreeHcfX509TrustAnchorArray(anchor, true);
            return CF_ERR_MALLOC;
        }
    }

    CfResult ret = ProcessP12Data(pkey, cert, ca, &anchor);
    if (ret != CF_SUCCESS) {
        LOGE("Failed to Process P12 Data!");
        FreeHcfX509TrustAnchorArray(anchor, true);
    }

    *trustAnchorArray = anchor;
    return ret;
}
