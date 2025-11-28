/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "certificate_openssl_class.h"
#include "certificate_openssl_common.h"
#include "cf_blob.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "cf_result.h"
#include "utils.h"
#include <securec.h>
#include "x509_cert_chain_spi.h"
#include "x509_certificate_create.h"
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#define CERT_PKCS12_MININUM_SALTLEN 8
#define CERT_PKCS12_MININUM_PASSWORD 4
#define X509_CERT_CHAIN_OPENSSL_CLASS "X509CertChainOpensslClass"

typedef struct {
    int nidKey;
    int keyIter;
    int keySaltLen;
    int nidCert;
    int certIter;
    int certSaltLen;
    int macSaltLen;
    int macIter;
    const EVP_MD *md;
    bool encryptCert;
    const char *pass;
} Pkcs12Params;

typedef struct {
    unsigned char keyid[SHA256_DIGEST_LENGTH];
    unsigned int keyidLen;
    int nidCert;
    int nidKey;
}Pkcs12KeyId;

typedef struct {
    CfPbesEncryptionAlgorithm algEnum;
    const char *alg;
    int nid;
} CfConvertAlgToNidMap;

const char *GetX509CertChainClass(void)
{
    return X509_CERT_CHAIN_OPENSSL_CLASS;
}

CfResult CfToString(HcfX509CertChainSpi *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetX509CertChainClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }

    HcfX509CertChainOpensslImpl *certChain = (HcfX509CertChainOpensslImpl *)self;
    STACK_OF(X509) *x509CertChain = certChain->x509CertChain;

    int32_t certsNum = sk_X509_num(x509CertChain);
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        LOGE("BIO_new error");
        return CF_ERR_MALLOC;
    }
    for (int32_t i = 0; i < certsNum; ++i) {
        X509 *cert = sk_X509_value(x509CertChain, i);
        int len = X509_print(bio, cert);
        if (len <= 0) {
            LOGE("X509_print error");
            BIO_free(bio);
            return CF_ERR_CRYPTO_OPERATION;
        }
    }
    BUF_MEM *bufMem = NULL;
    if (BIO_get_mem_ptr(bio, &bufMem) > 0 && bufMem != NULL) {
        CfResult res = DeepCopyDataToOut(bufMem->data, bufMem->length, out);
        BIO_free(bio);
        return res;
    }

    BIO_free(bio);
    LOGE("BIO_get_mem_ptr error");
    return CF_ERR_CRYPTO_OPERATION;
}

CfResult CfHashCode(HcfX509CertChainSpi *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetX509CertChainClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }

    HcfX509CertChainOpensslImpl *certChain = (HcfX509CertChainOpensslImpl *)self;
    STACK_OF(X509) *x509CertChain = certChain->x509CertChain;
    int32_t certsNum = sk_X509_num(x509CertChain);
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        LOGE("BIO_new error");
        return CF_ERR_MALLOC;
    }
    for (int32_t i = 0; i < certsNum; ++i) {
        X509 *cert = sk_X509_value(x509CertChain, i);
        int len = i2d_X509_bio(bio, cert);
        if (len < 0) {
            LOGE("i2d_X509_bio error");
            BIO_free(bio);
            return CF_ERR_CRYPTO_OPERATION;
        }
    }

    out->data = (uint8_t *)CfMalloc(SHA256_DIGEST_LENGTH, 0);
    if (out->data == NULL) {
        LOGE("CfMalloc error");
        BIO_free(bio);
        return CF_ERR_MALLOC;
    }
    BUF_MEM *bufMem = NULL;
    if (BIO_get_mem_ptr(bio, &bufMem) > 0 && bufMem != NULL) {
        SHA256((unsigned char *)bufMem->data, bufMem->length, out->data);
        out->size = SHA256_DIGEST_LENGTH;
        BIO_free(bio);
        return CF_SUCCESS;
    }

    BIO_free(bio);
    CfBlobDataFree(out);
    LOGE("BIO_get_mem_ptr error");
    return CF_ERR_CRYPTO_OPERATION;
}

X509 *GetX509FromHcfX509Certificate(const HcfCertificate *cert)
{
    if (!CfIsClassMatch((CfObjectBase *)cert, HCF_X509_CERTIFICATE_CLASS)) {
        LOGE("Input wrong openssl class type!");
        return NULL;
    }
    HcfX509CertificateImpl *impl = (HcfX509CertificateImpl *)cert;
    if (!CfIsClassMatch((CfObjectBase *)(impl->spiObj), X509_CERT_OPENSSL_CLASS)) {
        LOGE("Input wrong openssl class type!");
        return NULL;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)(impl->spiObj);

    return realCert->x509;
}

void FreeCertificateArray(HcfX509CertificateArray *certs)
{
    if (certs == NULL || certs->data == NULL) {
        return;
    }
    for (uint32_t i = 0; i < certs->count; ++i) {
        CfObjDestroy(certs->data[i]);
    }
    CF_FREE_PTR(certs->data);
    certs->count = 0;
}

static CfResult GetCertChainFromCollection(const HcfX509CertChainBuildParameters *inParams, STACK_OF(X509) *certStack)
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
                FreeCertificateArray(&retCerts);
                return CF_INVALID_PARAMS;
            }

            X509 *certDup = X509_dup(cert);
            if (certDup == NULL) {
                LOGE("Memory allocation failure!");
                FreeCertificateArray(&retCerts);
                return CF_ERR_MALLOC;
            }
            if (sk_X509_push(certStack, certDup) <= 0) {
                LOGE("Push cert to SK failed!");
                X509_free(certDup);
                FreeCertificateArray(&retCerts);
                return CF_ERR_CRYPTO_OPERATION;
            }
        }
        FreeCertificateArray(&retCerts);
    }
    return CF_SUCCESS;
}

CfResult GetLeafCertsFromCertStack(
    const HcfX509CertChainBuildParameters *inParams, STACK_OF(X509) *allCerts, STACK_OF(X509) *leafCerts)
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
        X509 *x509 = sk_X509_value(allCerts, i);
        if (!CheckIsLeafCert(x509)) {
            continue;
        }

        X509 *x = X509_dup(x509);
        if (x == NULL) {
            LOGE("Dup the cert failed.");
            return CF_ERR_CRYPTO_OPERATION;
        }
        if (!sk_X509_push(leafCerts, x)) {
            X509_free(x);
            LOGE("Push the cert into stack failed.");
            return CF_ERR_CRYPTO_OPERATION;
        }
    }

    if (sk_X509_num(leafCerts) <= 0) {
        LOGE("The num of leaf certificate is 0.");
        return CF_INVALID_PARAMS;
    }
    return CF_SUCCESS;
}

CfResult X509ToHcfX509Certificate(X509 *cert, HcfX509Certificate **returnObj)
{
    if (cert == NULL) {
        LOGE("The input params invalid.");
        return CF_INVALID_PARAMS;
    }

    HcfX509CertCreateFunc func = GetHcfX509CertCreateFunc();
    if (func == NULL) {
        LOGE("HcfX509CertificateCreate is null.");
        return CF_NULL_POINTER;
    }

    int dataLength = 0;
    uint8_t *certData = GetX509EncodedDataStream(cert, &dataLength);
    if (certData == NULL) {
        LOGE("Falied to get certificate data!");
        return CF_ERR_CRYPTO_OPERATION;
    }

    HcfX509Certificate *x509cert = NULL;
    CfEncodingBlob encodingBlob = { certData, dataLength, CF_FORMAT_DER };
    CfResult res = func(&encodingBlob, &x509cert);
    CfFree(certData);
    certData = NULL;
    if (res != CF_SUCCESS) {
        LOGE("HcfX509CertificateCreate fail, res : %{public}d!", res);
        return CF_ERR_MALLOC;
    }

    *returnObj = x509cert;
    return res;
}

void FreeResources(X509 *cert, EVP_PKEY *pkey, STACK_OF(X509) *caStack)
{
    if (cert != NULL) {
        X509_free(cert);
    }
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
    if (caStack != NULL) {
        sk_X509_pop_free(caStack, X509_free);
    }
}

void FreeHcfX509P12Collection(HcfX509P12Collection *p12Collection)
{
    if (p12Collection == NULL) {
        return;
    }
    if (p12Collection->cert != NULL) {
        CfFree(p12Collection->cert);
        p12Collection->cert = NULL;
    }
    if (p12Collection->prikey != NULL && p12Collection->prikey->data != NULL) {
        CfBlobFree(&p12Collection->prikey);
    }
    if (p12Collection->otherCerts != NULL && p12Collection->otherCertsCount != 0) {
        for (uint32_t i = 0; i < p12Collection->otherCertsCount; i++) {
            if (p12Collection->otherCerts[i] != NULL) {
                CfFree(p12Collection->otherCerts[i]);
                p12Collection->otherCerts[i] = NULL;
            }
        }
        CfFree(p12Collection->otherCerts);
        p12Collection->otherCerts = NULL;
    }
    CfFree(p12Collection);
}

CfResult AllocateAndConvertCert(X509 *cert, HcfX509P12Collection *collection, bool isGet)
{
    if (!isGet) {
        LOGI("The certificate for P12 does not need to be parsed!");
        return CF_SUCCESS;
    }
    if (cert == NULL) {
        LOGI("P12 does not have a cert!");
        return CF_SUCCESS;
    }
    CfResult ret = X509ToHcfX509Certificate(cert, &collection->cert);
    if (ret != CF_SUCCESS) {
        LOGE("Failed to convert X509 to HcfX509Certificate!");
        return ret;
    }
    return CF_SUCCESS;
}

CfResult AllocateAndConvertPkey(EVP_PKEY *pkey, HcfX509P12Collection *collection, bool isGet)
{
    if ((!isGet) || (pkey == NULL)) {
        LOGI("The prikey for P12 does not need to be parsed!");
        return CF_SUCCESS;
    }
    collection->prikey = (CfBlob *)CfMalloc(sizeof(CfBlob), 0);
    if (collection->prikey == NULL) {
        LOGE("Failed to malloc pri key!");
        return CF_ERR_MALLOC;
    }
    BIO *memBio = BIO_new(BIO_s_mem());
    if (collection->isPem) {
        if (!PEM_write_bio_PrivateKey(memBio, pkey, NULL, NULL, 0, 0, NULL)) {
            LOGE("PEM write bio PrivateKey failed");
            CfPrintOpensslError();
            CfBlobFree(&collection->prikey);
            BIO_free_all(memBio);
            return CF_ERR_CRYPTO_OPERATION;
        }
    } else {
        if (!i2d_PKCS8PrivateKey_bio(memBio, pkey, NULL, NULL, 0, NULL, NULL)) {
            LOGE("PrivateKey i2d failed");
            CfPrintOpensslError();
            CfBlobFree(&collection->prikey);
            BIO_free_all(memBio);
            return CF_ERR_CRYPTO_OPERATION;
        }
    }
    BUF_MEM *buf = NULL;
    if (BIO_get_mem_ptr(memBio, &buf) < 0 || buf == NULL) {
        LOGE("Failed to get mem ptr!");
        CfBlobFree(&collection->prikey);
        BIO_free_all(memBio);
        return CF_ERR_MALLOC;
    }
    collection->prikey->size = buf->length;
    collection->prikey->data = (uint8_t *)CfMalloc(collection->prikey->size, 0);
    if (collection->prikey->data == NULL) {
        LOGE("Failed to malloc pri key data!");
        CfBlobFree(&collection->prikey);
        BIO_free_all(memBio);
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(collection->prikey->data, buf->length, buf->data, buf->length);
    BIO_free_all(memBio);
    return CF_SUCCESS;
}

CfResult AllocateAndConvertCertStack(STACK_OF(X509) *ca, HcfX509P12Collection *collection, bool isGet)
{
    if (!isGet) {
        LOGI("The other certs for P12 does not need to be parsed!");
        return CF_SUCCESS;
    }
    if (ca == NULL) {
        LOGI("P12 does not have other certs!");
        return CF_SUCCESS;
    }
    int32_t count = sk_X509_num(ca);
    if (count <= 0) {
        LOGI("P12 other certs num is 0!");
        return CF_SUCCESS;
    }
    collection->otherCerts = (HcfX509Certificate **)CfMalloc(sizeof(HcfX509Certificate *) * count, 0);
    collection->otherCertsCount = (uint32_t)count;
    if (collection->otherCerts == NULL) {
        LOGE("Failed to malloc otherCerts!");
        return CF_ERR_MALLOC;
    }
    for (uint32_t i = 0; i < collection->otherCertsCount; i++) {
        X509 *cert = sk_X509_value(ca, i);
        CfResult ret = X509ToHcfX509Certificate(cert, &collection->otherCerts[i]);
        if (ret != CF_SUCCESS) {
            LOGE("Failed to convert X509 to HcfX509Certificate!");
            return ret;
        }
    }
    return CF_SUCCESS;
}

static void ProcessP12Data(STACK_OF(X509) *ca, HcfX509TrustAnchorArray *result)
{
    for (int i = 0; i < sk_X509_num(ca); i++) {
        X509 *x509 = sk_X509_value(ca, i);
        // CACert
        if (X509ToHcfX509Certificate(x509, &(result->data[i]->CACert)) != CF_SUCCESS) {
            LOGD("Failed to get %d CACert!", i);
        }

        // CAPubKey
        if (GetPubKeyDataFromX509(x509, &(result->data[i]->CAPubKey)) != CF_SUCCESS) {
            LOGD("Failed to get %d CAPubKey!", i);
        }

        // CASubject
        if (GetSubjectNameFromX509(x509, &(result->data[i]->CASubject)) != CF_SUCCESS) {
            LOGD("Failed to get %d CASubject!", i);
        }

        // nameConstraints
        if (GetNameConstraintsFromX509(x509, &(result->data[i]->nameConstraints)) != CF_SUCCESS) {
            LOGD("Failed to get %d nameConstraints!", i);
        }
    }
}

static void FreeHcfX509TrustAnchorArrayInner(HcfX509TrustAnchorArray *trustAnchorArray)
{
    if (trustAnchorArray == NULL) {
        return;
    }
    if (trustAnchorArray->data != NULL) {
        for (uint32_t i = 0; i < trustAnchorArray->count; i++) {
            if (trustAnchorArray->data[i] != NULL) {
                CfObjDestroy(trustAnchorArray->data[i]->CACert);
                trustAnchorArray->data[i]->CACert = NULL;
                CfBlobFree(&trustAnchorArray->data[i]->CAPubKey);
                CfBlobFree(&trustAnchorArray->data[i]->CASubject);
                CfBlobFree(&trustAnchorArray->data[i]->nameConstraints);
                CfFree(trustAnchorArray->data[i]);
                trustAnchorArray->data[i] = NULL;
            }
        }
        CfFree(trustAnchorArray->data);
        trustAnchorArray->data = NULL;
    }
}

static STACK_OF(X509) *GetCaFromP12(const CfBlob *keyStore, const CfBlob *pwd)
{
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    STACK_OF(X509) *caStack = NULL;
    PKCS12 *p12 = NULL;
    const unsigned char *in = (const unsigned char *)(keyStore->data);

    p12 = d2i_PKCS12(NULL, &in, keyStore->size);
    if (p12 == NULL) {
        LOGE("Error convert pkcs12 data to inner struct!");
        CfPrintOpensslError();
        return NULL;
    }

    int ret = PKCS12_parse(p12, (const char *)pwd->data, &pkey, &cert, &caStack);
    PKCS12_free(p12);
    if (ret != 1) {
        LOGE("PKCS12_parse failed!");
        CfPrintOpensslError();
        return NULL;
    }

    EVP_PKEY_free(pkey);
    if (cert == NULL) {
        LOGE("P12 does not have a cert!");
        sk_X509_pop_free(caStack, X509_free);
        return NULL;
    }
    X509_free(cert);

    if (caStack == NULL) {
        LOGE("P12 does not have ca!");
    }
    return caStack;
}

static HcfX509TrustAnchorArray *MallocTrustAnchorArray(int32_t count)
{
    HcfX509TrustAnchorArray *anchor = (HcfX509TrustAnchorArray *)(CfMalloc(sizeof(HcfX509TrustAnchorArray), 0));
    if (anchor == NULL) {
        LOGE("Failed to allocate trustAnchorArray memory!");
        return NULL;
    }

    anchor->count = (uint32_t)count;
    anchor->data = (HcfX509TrustAnchor **)(CfMalloc(anchor->count * sizeof(HcfX509TrustAnchor *), 0));
    if (anchor->data == NULL) {
        LOGE("Failed to allocate data memory!");
        CfFree(anchor);
        anchor = NULL;
        return NULL;
    }

    for (uint32_t i = 0; i < anchor->count; i++) {
        anchor->data[i] = (HcfX509TrustAnchor *)(CfMalloc(sizeof(HcfX509TrustAnchor), 0));
        if (anchor->data[i] == NULL) {
            LOGE("Failed to allocate data memory!");
            FreeHcfX509TrustAnchorArrayInner(anchor);
            CfFree(anchor);
            anchor = NULL;
            return NULL;
        }
    }
    return anchor;
}

CfResult HcfX509CreateTrustAnchorWithKeyStoreFunc(
    const CfBlob *keyStore, const CfBlob *pwd, HcfX509TrustAnchorArray **trustAnchorArray)
{
    if (keyStore == NULL || pwd == NULL || trustAnchorArray == NULL) {
        LOGE("Invalid params!");
        return CF_INVALID_PARAMS;
    }

    STACK_OF(X509) *ca = GetCaFromP12(keyStore, pwd);
    if (ca == NULL) {
        return CF_ERR_CRYPTO_OPERATION;
    }

    int32_t count = sk_X509_num(ca);
    if (count <= 0) {
        LOGE("P12 ca num is 0!");
        sk_X509_pop_free(ca, X509_free);
        return CF_ERR_CRYPTO_OPERATION;
    }

    HcfX509TrustAnchorArray *anchor = MallocTrustAnchorArray(count);
    if (anchor == NULL) {
        sk_X509_pop_free(ca, X509_free);
        return CF_ERR_MALLOC;
    }

    ProcessP12Data(ca, anchor);
    *trustAnchorArray = anchor;
    anchor = NULL;
    sk_X509_pop_free(ca, X509_free);
    return CF_SUCCESS;
}

static CfResult ParsePkcs12(const CfBlob *keyStore, const CfBlob *pwd,
    X509 **cert, EVP_PKEY **pkey, STACK_OF(X509) **caStack)
{
    PKCS12 *p12 = NULL;
    const unsigned char *in = (const unsigned char *)(keyStore->data);

    p12 = d2i_PKCS12(NULL, &in, keyStore->size);
    if (p12 == NULL) {
        LOGE("Error convert pkcs12 data to inner struct!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    int ret = PKCS12_parse(p12, (const char *)pwd->data, pkey, cert, caStack);
    PKCS12_free(p12);
    if (ret != 1) {
        LOGE("PKCS12_parse failed!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    return CF_SUCCESS;
}

CfResult HcfX509ParsePKCS12Func(
    const CfBlob *keyStore, const HcfParsePKCS12Conf *conf, HcfX509P12Collection **p12Collection)
{
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    STACK_OF(X509) *caStack = NULL;
    CfResult ret = ParsePkcs12(keyStore, conf->pwd, &cert, &pkey, &caStack);
    if (ret != CF_SUCCESS) {
        LOGE("Failed to parse PKCS12!");
        return ret;
    }

    HcfX509P12Collection *collection = (HcfX509P12Collection *)CfMalloc(sizeof(HcfX509P12Collection), 0);
    if (collection == NULL) {
        FreeResources(cert, pkey, caStack);
        LOGE("Failed to malloc collection!");
        return CF_ERR_MALLOC;
    }

    ret = AllocateAndConvertCert(cert, collection, conf->isGetCert);
    if (ret != CF_SUCCESS) {
        FreeResources(cert, pkey, caStack);
        FreeHcfX509P12Collection(collection);
        collection = NULL;
        LOGE("Failed to convert cert!");
        return ret;
    }

    collection->isPem = conf->isPem;
    ret = AllocateAndConvertPkey(pkey, collection, conf->isGetPriKey);
    if (ret != CF_SUCCESS) {
        FreeResources(cert, pkey, caStack);
        FreeHcfX509P12Collection(collection);
        collection = NULL;
        LOGE("Failed to convert pkey!");
        return ret;
    }

    ret = AllocateAndConvertCertStack(caStack, collection, conf->isGetOtherCerts);
    if (ret != CF_SUCCESS) {
        FreeResources(cert, pkey, caStack);
        FreeHcfX509P12Collection(collection);
        collection = NULL;
        LOGE("Failed to convert caStack!");
        return ret;
    }

    *p12Collection = collection;
    FreeResources(cert, pkey, caStack);
    return CF_SUCCESS;
}

static bool Pkcs12AddSafeBags(STACK_OF(PKCS7) **safes, STACK_OF(PKCS12_SAFEBAG) *bags,
    int nidCert, Pkcs12Params *params)
{
    PKCS7 *pkcs7 = NULL;
    if (nidCert == -1) {
        // No encryption cert
        pkcs7 = PKCS12_pack_p7data(bags);
    } else {
        // Encryption cert
        pkcs7 = PKCS12_pack_p7encdata_ex(nidCert, params->pass, -1, NULL, params->certSaltLen, params->certIter,
            bags, NULL, NULL);
    }
    if (pkcs7 == NULL) {
        LOGE("pkcs7 is null!");
        return false;
    }
    if (*safes != NULL) {
        if (sk_PKCS7_push(*safes, pkcs7) <= 0) {
            LOGE("Failed to push pkcs7 to safes!");
            PKCS7_free(pkcs7);
            return false;
        }
    } else {
        *safes = sk_PKCS7_new_null();
        if (*safes == NULL) {
            LOGE("Failed to create new safes!");
            PKCS7_free(pkcs7);
            return false;
        }
        if (sk_PKCS7_push(*safes, pkcs7) <= 0) {
            LOGE("Failed to push pkcs7 to safes!");
            PKCS7_free(pkcs7);
            sk_PKCS7_free(*safes);
            *safes = NULL;
            return false;
        }
    }
    return true;
}

static bool Pkcs12AddSafeBag(STACK_OF(PKCS12_SAFEBAG) **p12, PKCS12_SAFEBAG *data)
{
    if (*p12 != NULL) {
        if (sk_PKCS12_SAFEBAG_push(*p12, data) <= 0) {
            LOGE("sk_PKCS12_SAFEBAG_push failed!");
            return false;
        }
    } else {
        *p12 = sk_PKCS12_SAFEBAG_new_null();
        if (*p12 == NULL) {
            LOGE("sk_PKCS12_SAFEBAG_new_null failed!");
            return false;
        }
        if (sk_PKCS12_SAFEBAG_push(*p12, data) <= 0) {
            LOGE("sk_PKCS12_SAFEBAG_push failed!");
            sk_PKCS12_SAFEBAG_pop_free(*p12, PKCS12_SAFEBAG_free);
            *p12 = NULL;
            return false;
        }
    }
    return true;
}

static PKCS12_SAFEBAG *AddKeyToPkcs12(STACK_OF(PKCS12_SAFEBAG) **p12, EVP_PKEY *key,
    int nidKey, Pkcs12Params *params)
{
    PKCS8_PRIV_KEY_INFO *pkcs8 = EVP_PKEY2PKCS8(key);
    if (pkcs8 == NULL) {
        LOGE("EVP_PKEY2PKCS8 failed!");
        return NULL;
    }
    PKCS12_SAFEBAG *resultData = PKCS12_SAFEBAG_create_pkcs8_encrypt_ex(nidKey, params->pass, -1, NULL,
        params->keySaltLen, params->keyIter, pkcs8, NULL, NULL);
    if (resultData == NULL) {
        LOGE("PKCS12_SAFEBAG_create_pkcs8_encrypt_ex failed!");
        PKCS8_PRIV_KEY_INFO_free(pkcs8);
        return NULL;
    }
    PKCS8_PRIV_KEY_INFO_free(pkcs8);
    if (!Pkcs12AddSafeBag(p12, resultData)) {
        LOGE("Pkcs12AddSafeBag failed!");
        PKCS12_SAFEBAG_free(resultData);
        return NULL;
    }
    return resultData;
}

static bool CheckPkcs12ParamsAndDigest(X509 *cert, EVP_PKEY *pkey, STACK_OF(X509) *ca, unsigned char *data,
    unsigned int *dataLen)
{
    if (pkey == NULL && cert == NULL && ca == NULL) {
        LOGE("No data to put in PKCS12 structure!");
        return false;
    }
    if (pkey != NULL && cert != NULL) {
        if (X509_check_private_key(cert, pkey) != CF_OPENSSL_SUCCESS) {
            LOGE("Private key does not match certificate public key!");
            return false;
        }
        if (X509_digest(cert, EVP_sha1(), data, dataLen) != CF_OPENSSL_SUCCESS) {
            LOGE("Failed to get certificate digest!");
            return false;
        }
    }
    return true;
}

static bool AddCertsToBags(X509 *cert, STACK_OF(X509) *ca, Pkcs12KeyId *id, Pkcs12Params *params,
    STACK_OF(PKCS7) **safeBags)
{
    STACK_OF(PKCS12_SAFEBAG) *p12 = NULL;
    PKCS12_SAFEBAG *bag = NULL;
    // Add cert
    if (cert != NULL) {
        bag = PKCS12_add_cert(&p12, cert);
        if (bag == NULL) {
            LOGE("Failed to add cert to cert bag!");
            sk_PKCS12_SAFEBAG_pop_free(p12, PKCS12_SAFEBAG_free);
            return false;
        }
        if (id->keyidLen > 0) {
            if (PKCS12_add_localkeyid(bag, id->keyid, id->keyidLen) != CF_OPENSSL_SUCCESS) {
                LOGE("Failed to add local key ID to cert bag!");
                sk_PKCS12_SAFEBAG_pop_free(p12, PKCS12_SAFEBAG_free);
                return false;
            }
        }
    }
    // Add CA certs
    int caCount = (ca != NULL) ? sk_X509_num(ca) : 0;
    for (int i = 0; i < caCount; i++) {
        if (PKCS12_add_cert(&p12, sk_X509_value(ca, i)) == NULL) {
            LOGE("Failed to add CA cert to p12!");
            sk_PKCS12_SAFEBAG_pop_free(p12, PKCS12_SAFEBAG_free);
            return false;
        }
    }
    if (p12 == NULL) {
        LOGI("No certs to add to PKCS12 structure.");
        return true; // no certs to add
    }
    if (!Pkcs12AddSafeBags(safeBags, p12, id->nidCert, params)) {
        LOGE("Failed to add p12 to safeBags!");
        sk_PKCS12_SAFEBAG_pop_free(p12, PKCS12_SAFEBAG_free);
        return false;
    }
    sk_PKCS12_SAFEBAG_pop_free(p12, PKCS12_SAFEBAG_free);
    p12 = NULL;
    return true;
}

static bool AddKeyToBags(EVP_PKEY *pkey, Pkcs12KeyId *id, Pkcs12Params *params, STACK_OF(PKCS7) **safes)
{
    STACK_OF(PKCS12_SAFEBAG) *p12 = NULL;
    if (pkey != NULL) {
        PKCS12_SAFEBAG *bag = AddKeyToPkcs12(&p12, pkey, id->nidKey, params);
        if (bag == NULL) {
            LOGE("Failed to add key to p12!");
            sk_PKCS12_SAFEBAG_pop_free(p12, PKCS12_SAFEBAG_free);
            return false;
        }
        if (id->keyidLen > 0) {
            if (PKCS12_add_localkeyid(bag, id->keyid, id->keyidLen) != CF_OPENSSL_SUCCESS) {
                LOGE("Failed to add local key ID to key bag!");
                sk_PKCS12_SAFEBAG_pop_free(p12, PKCS12_SAFEBAG_free);
                return false;
            }
        }
    }
    if (p12 == NULL) {
        LOGI("No key to add to PKCS12 structure.");
        return true; // no key to add
    }
    if (PKCS12_add_safe(safes, p12, -1, 0, NULL) != CF_OPENSSL_SUCCESS) {
        LOGE("Failed to add safe with key to safes!");
        sk_PKCS12_SAFEBAG_pop_free(p12, PKCS12_SAFEBAG_free);
        return false;
    }
    sk_PKCS12_SAFEBAG_pop_free(p12, PKCS12_SAFEBAG_free);
    p12 = NULL;
    return true;
}

static bool FillPkcs12KeyId(Pkcs12KeyId *id, Pkcs12Params *params, unsigned char *data, unsigned int dataLen)
{
    int nidCert = (params->nidCert == NID_undef) ? NID_aes_256_cbc : params->nidCert;
    int nidKey = (params->nidKey == NID_undef) ? NID_aes_256_cbc : params->nidKey;
    if (!params->encryptCert) {
        nidCert = -1;  // do not encrypt certificate
    }
    if (memcpy_s(id->keyid, sizeof(id->keyid), data, dataLen) != EOK) {
        LOGE("memcpy_s data to buffer failed!");
        return false;
    }
    id->keyidLen = dataLen;
    id->nidCert = nidCert;
    id->nidKey = nidKey;
    return true;
}

static PKCS12 *CreatePkcs12(EVP_PKEY *pkey, X509 *cert, STACK_OF(X509) *ca, Pkcs12Params *params)
{
    PKCS12 *p12 = NULL;
    STACK_OF(PKCS7) *bags = NULL;
    unsigned char data[EVP_MAX_MD_SIZE] = { 0 };
    unsigned int dataLen = 0;
    Pkcs12KeyId id = {0};
    // Check parameters and get cert digest
    if (!CheckPkcs12ParamsAndDigest(cert, pkey, ca, data, &dataLen)) {
        LOGE("Invalid PKCS12 parameters or digest!");
        return NULL;
    }
    bool result = FillPkcs12KeyId(&id, params, data, dataLen);
    if (!result) {
        LOGE("FillPkcs12KeyId failed!");
        return NULL;
    }
    // Add certs to bags
    if (!AddCertsToBags(cert, ca, &id, params, &bags)) {
        LOGE("AddCertsToBags failed!");
        sk_PKCS7_pop_free(bags, PKCS7_free);
        return NULL;
    }
    // Add key to bags
    if (!AddKeyToBags(pkey, &id, params, &bags)) {
        LOGE("AddKeyToBags failed!");
        sk_PKCS7_pop_free(bags, PKCS7_free);
        return NULL;
    }
    // Create PKCS12 structure
    p12 = PKCS12_add_safes_ex(bags, 0, NULL, NULL);
    sk_PKCS7_pop_free(bags, PKCS7_free);
    bags = NULL;
    if (p12 == NULL) {
        LOGE("PKCS12_add_safes_ex failed!");
        return NULL;
    }
    // Set MAC
    int ret = PKCS12_set_mac(p12, params->pass, -1, NULL, params->macSaltLen, params->macIter, params->md);
    if (ret != CF_OPENSSL_SUCCESS) {
        LOGE("Failed to set MAC for PKCS12 structure!");
        PKCS12_free(p12);
        return NULL;
    }
    return p12;
}

static CfConvertAlgToNidMap g_pkcs12AlgMap[] = {
    { AES_128_CBC, "AES-128-CBC", NID_aes_128_cbc },
    { AES_192_CBC, "AES-192-CBC", NID_aes_192_cbc },
    { AES_256_CBC, "AES-256-CBC", NID_aes_256_cbc },
    { -1, NULL, NID_undef }
};

static const char *PbesAlgEnumToStr(CfPbesEncryptionAlgorithm algEnum)
{
    for (int i = 0; g_pkcs12AlgMap[i].alg != NULL; i++) {
        if (g_pkcs12AlgMap[i].algEnum == algEnum) {
            return g_pkcs12AlgMap[i].alg;
        }
    }
    return NULL;
}

static int PbesAlgStrToNid(const char *alg)
{
    for (int i = 0; g_pkcs12AlgMap[i].alg != NULL; i++) {
        if (strcmp(g_pkcs12AlgMap[i].alg, alg) == 0) {
            return g_pkcs12AlgMap[i].nid;
        }
    }
    return NID_undef;
}

static int PbesAlgEnumToNid(CfPbesEncryptionAlgorithm algEnum)
{
    const char *algStr = PbesAlgEnumToStr(algEnum);
    if (algStr == NULL) {
        return NID_undef;
    }
    return PbesAlgStrToNid(algStr);
}

static const EVP_MD *MacDigestEnumToEvpMd(CfPkcs12MacDigestAlgorithm alg)
{
    switch (alg) {
        case CF_MAC_SHA256:
            return EVP_sha256();
        case CF_MAC_SHA384:
            return EVP_sha384();
        case CF_MAC_SHA512:
            return EVP_sha512();
        default:
            return NULL;
    }
}

static void FillPkcs12Params(HcfPkcs12CreatingConfig *conf, Pkcs12Params *params)
{
    params->nidKey = PbesAlgEnumToNid(conf->keyEncParams.alg);
    params->nidCert = PbesAlgEnumToNid(conf->certEncParams.alg);
    params->keyIter = conf->keyEncParams.iteration;
    params->certIter = conf->certEncParams.iteration;
    params->keySaltLen = conf->keyEncParams.saltLen;
    params->certSaltLen = conf->certEncParams.saltLen;
    params->macSaltLen = conf->macSaltLen;
    params->macIter = conf->macIteration;
    params->md = MacDigestEnumToEvpMd(conf->macAlg);
    params->encryptCert = conf->encryptCert;
    params->pass = (const char *)conf->pwd->data;
    return;
}

static CfResult LoadPrivateKeyFromCollection(const HcfX509P12Collection *p12Collection, EVP_PKEY **pkey)
{
    BIO *bio = BIO_new_mem_buf(p12Collection->prikey->data, p12Collection->prikey->size);
    if (bio == NULL) {
        LOGE("BIO_new_mem_buf failed!");
        return CF_ERR_MALLOC;
    }
    if (p12Collection->isPem) {
        *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    } else {
        *pkey = d2i_PrivateKey_bio(bio, NULL);
    }
    BIO_free(bio);
    if (*pkey == NULL) {
        LOGE("Read private key failed!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    return CF_SUCCESS;
}

static CfResult LoadPkcs12CertsAndPrivateKey(HcfX509P12Collection *p12Collection, X509 **cert, EVP_PKEY **pkey,
    STACK_OF(X509) **ca)
{
    if (p12Collection->cert != NULL) {
        *cert = GetX509FromHcfX509Certificate((HcfCertificate *)p12Collection->cert);
        if (*cert == NULL) {
            LOGE("GetX509FromHcfX509Certificate failed!");
            return CF_ERR_CRYPTO_OPERATION;
        }
    }
    if (p12Collection->prikey != NULL && p12Collection->prikey->data != NULL) {
        CfResult ret = LoadPrivateKeyFromCollection(p12Collection, pkey);
        if (ret != CF_SUCCESS) {
            LOGE("LoadPrivateKeyFromCollection failed!");
            return ret;
        }
    }
    if (p12Collection->otherCerts != NULL && p12Collection->otherCertsCount > 0) {
        *ca = sk_X509_new_null();
        if (*ca == NULL) {
            LOGE("sk_X509_new_null failed!");
            EVP_PKEY_free(*pkey);
            return CF_ERR_MALLOC;
        }
        for (uint32_t i = 0; i < p12Collection->otherCertsCount; i++) {
            X509 *caCert = GetX509FromHcfX509Certificate((HcfCertificate *)p12Collection->otherCerts[i]);
            if (caCert == NULL) {
                LOGE("GetX509FromHcfX509Certificate (CA) failed!");
                sk_X509_pop_free(*ca, X509_free);
                EVP_PKEY_free(*pkey);
                return CF_ERR_CRYPTO_OPERATION;
            }
            X509 *dupCert = X509_dup(caCert);
            if (dupCert == NULL) {
                LOGE("X509_dup failed!");
                sk_X509_pop_free(*ca, X509_free);
                EVP_PKEY_free(*pkey);
                return CF_ERR_MALLOC;
            }
            sk_X509_push(*ca, dupCert);
        }
    }
    return CF_SUCCESS;
}

static CfResult CopyPkcs12ToBlob(PKCS12 *p12, CfBlob *blob)
{
    int len = i2d_PKCS12(p12, NULL);
    if (len <= 0) {
        LOGE("i2d_PKCS12 get length failed!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    uint8_t *buf = (uint8_t *)CfMalloc(len, 0);
    if (buf == NULL) {
        LOGE("CfMalloc failed!");
        return CF_ERR_MALLOC;
    }
    uint8_t *p = buf;
    if (i2d_PKCS12(p12, &p) != len) {
        LOGE("i2d_PKCS12 encode failed!");
        CfFree(buf);
        return CF_ERR_CRYPTO_OPERATION;
    }

    blob->data = buf;
    blob->size = (uint32_t)len;
    return CF_SUCCESS;
}

static CfResult HcfPkcs12CreatingConfigCheck(const HcfPkcs12CreatingConfig *conf)
{
    if (conf == NULL || conf->pwd == NULL || conf->pwd->data == NULL || conf->pwd->size <= 0) {
        LOGE("Invalid config or password!");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (conf->keyEncParams.saltLen < CERT_PKCS12_MININUM_SALTLEN ||
        conf->certEncParams.saltLen < CERT_PKCS12_MININUM_SALTLEN ||
        conf->macSaltLen < CERT_PKCS12_MININUM_SALTLEN) {
        LOGE("Salt length is too short! Minimum is %{public}d", CERT_PKCS12_MININUM_SALTLEN);
        return CF_ERR_PARAMETER_CHECK;
    }
    if ((conf->pwd->size) - 1 < CERT_PKCS12_MININUM_PASSWORD) {
        LOGE("Password length is too short! Minimum is %{public}d!", CERT_PKCS12_MININUM_PASSWORD);
        return CF_ERR_PARAMETER_CHECK;
    }
    if (conf->keyEncParams.iteration < 0 || conf->certEncParams.iteration < 0 || conf->macIteration < 0) {
        LOGE("Iteration count is invalid!");
        return CF_ERR_PARAMETER_CHECK;
    }

    if (conf->keyEncParams.alg < AES_128_CBC || conf->keyEncParams.alg > AES_256_CBC ||
        conf->certEncParams.alg < AES_128_CBC || conf->certEncParams.alg > AES_256_CBC ||
        conf->macAlg < CF_MAC_SHA256 || conf->macAlg > CF_MAC_SHA512) {
        LOGE("Invalid encryption algorithm!");
        return CF_ERR_PARAMETER_CHECK;
    }
    return CF_SUCCESS;
}

CfResult HcfCreatePkcs12Func(HcfX509P12Collection *p12Collection, HcfPkcs12CreatingConfig *conf, CfBlob *blob)
{
    CfResult ret = HcfPkcs12CreatingConfigCheck(conf);
    if (ret != CF_SUCCESS) {
        LOGE("HcfPkcs12CreatingConfigCheck failed!");
        return ret;
    }
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    STACK_OF(X509) *otherCerts = NULL;
    ret = LoadPkcs12CertsAndPrivateKey(p12Collection, &cert, &pkey, &otherCerts);
    if (ret != CF_SUCCESS) {
        LOGE("LoadPkcs12CertsAndPrivateKey failed!");
        return ret;
    }

    Pkcs12Params *params = (Pkcs12Params *)CfMalloc(sizeof(Pkcs12Params), 0);
    if (params == NULL) {
        LOGE("Failed to malloc Pkcs12Params!");
        EVP_PKEY_free(pkey);
        sk_X509_pop_free(otherCerts, X509_free);
        return CF_ERR_MALLOC;
    }
    FillPkcs12Params(conf, params);
    PKCS12 *p12 = CreatePkcs12(pkey, cert, otherCerts, params);
    CfFree(params);
    params = NULL;
    if (p12 == NULL) {
        LOGE("CreatePkcs12 failed!");
        CfPrintOpensslError();
        EVP_PKEY_free(pkey);
        sk_X509_pop_free(otherCerts, X509_free);
        return CF_ERR_CRYPTO_OPERATION;
    }

    EVP_PKEY_free(pkey);
    sk_X509_pop_free(otherCerts, X509_free);

    ret = CopyPkcs12ToBlob(p12, blob);
    if (ret != CF_SUCCESS) {
        LOGE("CopyPkcs12ToBlob failed!");
        PKCS12_free(p12);
        return ret;
    }
    PKCS12_free(p12);
    return ret;
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

static CfResult GetCertIssuerFromChain(STACK_OF(X509) *x509CertChain, X509 *leafCert, X509 **issuerCert)
{
    X509_STORE *store = NULL;
    X509_STORE_CTX *storeCtx = NULL;
    CfResult ret = CF_SUCCESS;

    store = X509_STORE_new();
    if (store == NULL) {
        LOGE("Unable to create store.");
        return CF_ERR_MALLOC;
    }

    for (int i = 1; i < sk_X509_num(x509CertChain); i++) {
        X509 *tmpCert = sk_X509_value(x509CertChain, i);
        if (X509_STORE_add_cert(store, tmpCert) != 1) {
            LOGE("Add cert to store failed.");
            X509_STORE_free(store);
            return CF_ERR_CRYPTO_OPERATION;
        }
    }

    storeCtx = X509_STORE_CTX_new();
    if (storeCtx == NULL) {
        LOGE("Unable to create storeCtx.");
        X509_STORE_free(store);
        return CF_ERR_MALLOC;
    }

    if (X509_STORE_CTX_init(storeCtx, store, NULL, NULL) != CF_OPENSSL_SUCCESS) {
        LOGE("Unable to init STORE_CTX.");
        ret = CF_ERR_CRYPTO_OPERATION;
        goto end;
    }

    if (X509_STORE_CTX_get1_issuer(issuerCert, storeCtx, leafCert) != CF_OPENSSL_SUCCESS) {
        LOGE("Some other error occurred when getting issuer.");
        ret = CF_ERR_CRYPTO_OPERATION;
        goto end;
    }

end:
    X509_STORE_free(store);
    X509_STORE_CTX_free(storeCtx);
    return ret;
}

CfResult CfGetCertIdInfo(STACK_OF(X509) *x509CertChain, const CfBlob *ocspDigest, OcspCertIdInfo *certIdInfo,
    int index)
{
    X509 *issuerCert = NULL;
    X509 *cert = NULL;
    CfResult ret = CF_INVALID_PARAMS;
    cert = sk_X509_value(x509CertChain, index);
    if (cert == NULL) {
        LOGE("Get the cert is null.");
        return CF_INVALID_PARAMS;
    }

    ret = GetCertIssuerFromChain(x509CertChain, cert, &issuerCert);
    if (ret != CF_SUCCESS) {
        LOGE("Get cert issuer from chain failed.");
        return ret;
    }
    if (X509_up_ref(cert) != 1) {
        LOGE("Unable to up ref cert.");
        X509_free(issuerCert);
        return CF_ERR_CRYPTO_OPERATION;
    }
    certIdInfo->md = GetHashDigest(ocspDigest);
    certIdInfo->subjectCert = cert;
    certIdInfo->issuerCert = issuerCert;
    return CF_SUCCESS;
}

bool ContainsOption(HcfRevChkOpArray *options, HcfRevChkOption op)
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

CfResult IgnoreNetworkError(CfResult res, HcfRevChkOpArray *options)
{
    if (res == CF_ERR_CONNECT_TIMEOUT) {
        if (ContainsOption(options, REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR)) {
            LOGW("Online verify timeout, but ignore network error option is set!");
            return CF_SUCCESS;
        } else {
            return CF_ERR_CRYPTO_OPERATION;
        }
    }
    return res;
}

