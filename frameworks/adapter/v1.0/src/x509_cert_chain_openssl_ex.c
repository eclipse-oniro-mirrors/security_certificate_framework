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
#include "x509_cert_chain_spi.h"

#define X509_CERT_CHAIN_OPENSSL_CLASS "X509CertChainOpensslClass"

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
