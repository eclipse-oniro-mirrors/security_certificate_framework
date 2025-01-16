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

#include "x509_csr_openssl.h"

#include "cf_log.h"
#include "cf_blob.h"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/decoder.h>
#include "certificate_openssl_common.h"
#include "x509_distinguished_name.h"
#include "x509_distinguished_name_openssl.h"

static void FreeResources(X509_REQ *req, EVP_PKEY *pkey, BIO *out)
{
    if (req != NULL) {
        X509_REQ_free(req);
    }
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
    if (out != NULL) {
        BIO_free(out);
    }
}

static CfResult InitializeRequest(X509_REQ **req, const HcfGenCsrConf *conf)
{
    *req = X509_REQ_new();
    if (*req == NULL) {
        CfPrintOpensslError();
        LOGE("X509_REQ_new failed");
        return CF_ERR_MALLOC;
    }

    if (X509_REQ_set_version(*req, 0L) != 1) {
        LOGE("X509_REQ_set_version failed");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    HcfX509DistinguishedNameImpl *realName = (HcfX509DistinguishedNameImpl *)(conf->subject);
    if (realName == NULL) {
        LOGE("realName is NULL!");
        return CF_ERR_MALLOC;
    }
    HcfX509DistinguishedNameOpensslImpl *opensslName = (HcfX509DistinguishedNameOpensslImpl *)(realName->spiObj);
    if (opensslName == NULL) {
        LOGE("opensslName is NULL!");
        return CF_ERR_MALLOC;
    }
    X509_NAME *name = opensslName->name;
    if (name == NULL) {
        LOGE("name is NULL!");
        return CF_ERR_MALLOC;
    }

    if (!X509_REQ_set_subject_name(*req, name)) {
        LOGE("X509_REQ_set_subject_name failed");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    if (conf->attribute.array != NULL && conf->attribute.attributeSize > 0) {
        for (uint32_t i = 0; i < conf->attribute.attributeSize; i++) {
            if (X509_REQ_add1_attr_by_txt(*req,
                conf->attribute.array[i].attributeName,
                MBSTRING_FLAG,
                (const unsigned char *)conf->attribute.array[i].attributeValue,
                -1) != 1) {
                LOGE("Failed to add attribute to request");
                CfPrintOpensslError();
                return CF_ERR_CRYPTO_OPERATION;
            }
        }
    }
    return CF_SUCCESS;
}

static CfResult LoadPrivateKey(EVP_PKEY **pkey, PrivateKeyInfo *privateKeyInfo)
{
    const char *keytype = "RSA";
    const char *inputType = (privateKeyInfo->privateKey->encodingFormat == CF_FORMAT_PEM) ? "PEM" : "DER";
    OSSL_DECODER_CTX *ctx = OSSL_DECODER_CTX_new_for_pkey(pkey, inputType, NULL, keytype,
        OSSL_KEYMGMT_SELECT_PRIVATE_KEY, NULL, NULL);
    if (ctx == NULL) {
        LOGE("OSSL_DECODER_CTX_new_for_pkey fail.");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    if (privateKeyInfo->privateKeyPassword != NULL) {
        const unsigned char *passWd = (const unsigned char *)privateKeyInfo->privateKeyPassword;
        if (OSSL_DECODER_CTX_set_passphrase(ctx, passWd,
            strlen(privateKeyInfo->privateKeyPassword)) != CF_OPENSSL_SUCCESS) {
            LOGE("OSSL_DECODER_CTX_set_passphrase failed");
            CfPrintOpensslError();
            OSSL_DECODER_CTX_free(ctx);
            return CF_ERR_CRYPTO_OPERATION;
        }
    }
    size_t pdataLen = privateKeyInfo->privateKey->len;
    const unsigned char *pdata = (const unsigned char *)privateKeyInfo->privateKey->data;
    int ret = OSSL_DECODER_from_data(ctx, &pdata, &pdataLen);
    OSSL_DECODER_CTX_free(ctx);
    if (ret != CF_OPENSSL_SUCCESS) {
        LOGE("OSSL_DECODER_from_data failed.");
        CfPrintOpensslError();
        EVP_PKEY_free(*pkey);
        *pkey = NULL;
        return CF_ERR_CRYPTO_OPERATION;
    }
    return CF_SUCCESS;
}

static CfResult WriteCsrToString(BIO *out, bool isPem, X509_REQ *req, CfBlob *csrBlob)
{
    int ret = isPem ? PEM_write_bio_X509_REQ(out, req) : i2d_X509_REQ_bio(out, req);
    if (ret != 1) {
        LOGE("PEM_write_bio_X509_REQ or i2d_X509_REQ_bio failed");
        return CF_ERR_CRYPTO_OPERATION;
    }

    int csrLen = BIO_pending(out);
    if (csrLen <= 0) {
        LOGE("BIO_pending failed");
        return CF_INVALID_PARAMS;
    }
    csrBlob->data = (uint8_t *)OPENSSL_malloc(csrLen);
    if (csrBlob->data == NULL) {
        LOGE("OPENSSL_malloc failed");
        return CF_ERR_MALLOC;
    }

    if (BIO_read(out, csrBlob->data, csrLen) != csrLen) {
        OPENSSL_free(csrBlob->data);
        csrBlob->data = NULL;
        LOGE("BIO_read failed");
        return CF_ERR_CRYPTO_OPERATION;
    }
    csrBlob->size = csrLen;
    return CF_SUCCESS;
}

static CfResult SetupCsrPubKeyAndSign(X509_REQ *req, EVP_PKEY *pkey, const HcfGenCsrConf *conf)
{
    if (X509_REQ_set_pubkey(req, pkey) != 1) {
        LOGE("X509_REQ_set_pubkey failed");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    const EVP_MD *md = EVP_get_digestbyname(conf->mdName);
    if (md == NULL) {
        LOGE("Unsupported digest algorithm: %s", conf->mdName);
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
        if (!X509_REQ_sign(req, pkey, md)) {
        LOGE("X509_REQ_sign failed");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    return CF_SUCCESS;
}

CfResult GenerateX509Csr(PrivateKeyInfo *privateKeyInfo, const HcfGenCsrConf *conf, CfBlob *csrBlob)
{
    if (privateKeyInfo == NULL || conf == NULL || csrBlob == NULL) {
        return CF_INVALID_PARAMS;
    }

    X509_REQ *req = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *out = NULL;
    CfResult result = CF_SUCCESS;

    do {
        result = InitializeRequest(&req, conf);
        if (result != CF_SUCCESS) {
            break;
        }
        result = LoadPrivateKey(&pkey, privateKeyInfo);
        if (result != CF_SUCCESS) {
            LOGE("load prikey failed");
            break;
        }

        result = SetupCsrPubKeyAndSign(req, pkey, conf);
        if (result != CF_SUCCESS) {
            break;
        }

        out = BIO_new(BIO_s_mem());
        if (out == NULL) {
            CfPrintOpensslError();
            LOGE("BIO_new failed");
            result = CF_ERR_MALLOC;
            break;
        }

        result = WriteCsrToString(out, conf->isPem, req, csrBlob);
    } while (0);
    FreeResources(req, pkey, out);
    if (result != CF_SUCCESS) {
        LOGE("Write csr toString failed.");
        OPENSSL_free(csrBlob->data);
        csrBlob->data = NULL;
    }
    return result;
}
