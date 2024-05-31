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

CfResult ToString(HcfX509CertChainSpi *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertChainClass())) {
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
        if (len < 0) {
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

CfResult HashCode(HcfX509CertChainSpi *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertChainClass())) {
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
