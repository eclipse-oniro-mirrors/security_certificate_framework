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

#include "x509_cert_cms_generator_openssl.h"

#include "cf_blob.h"
#include "config.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "utils.h"
#include "cf_result.h"
#include "certificate_openssl_common.h"
#include "fwk_class.h"
#include "certificate_openssl_class.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/pem.h>
#include <openssl/cms.h>

#define MAX_SIGNER_NUM 20
#define MAX_CERT_NUM 60

#define ERR_PRIVATE_KEY_PASSWORD_PKCS8 0x11800074
#define ERR_PRIVATE_KEY_PASSWORD_PKCS1 0x4800065

typedef struct {
    HcfCmsGeneratorSpi base;
    CMS_ContentInfo *cms;
} HcfCmsGeneratorOpensslImpl;

#define X509_CERT_CMS_GENERATOR_OPENSSL_CLASS "X509CertCmsGeneratorOpensslClass"

static const char *GetCmsGeneratorClass(void)
{
    return X509_CERT_CMS_GENERATOR_OPENSSL_CLASS;
}

static void DestroyCmsGenerator(CfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Invalid params!");
        return;
    }
    if (!CfIsClassMatch(self, GetCmsGeneratorClass())) {
        LOGE("Class is not match.");
        return;
    }
    HcfCmsGeneratorOpensslImpl *impl = (HcfCmsGeneratorOpensslImpl *)self;
    if (impl->cms != NULL) {
        CMS_ContentInfo_free(impl->cms);
    }
    CfFree(impl);
}

static CfResult GetHashDigest(const char *mdName, const EVP_MD **md)
{
    if (mdName == NULL) {
        LOGE("Invalid params, mdName is null!");
        return CF_INVALID_PARAMS;
    }
    if (strcmp(mdName, "SHA1") == 0) {
        *md = EVP_sha1();
    } else if (strcmp(mdName, "SHA256") == 0) {
        *md = EVP_sha256();
    } else if (strcmp(mdName, "SHA384") == 0) {
        *md = EVP_sha384();
    } else if (strcmp(mdName, "SHA512") == 0) {
        *md = EVP_sha512();
    } else {
        LOGE("Invalid digest algorithm.");
        return CF_INVALID_PARAMS;
    }

    return CF_SUCCESS;
}

static void GetSignerFlags(const HcfCmsSignerOptions *options, int *tflags)
{
    if (!(options->addCert)) {
        *tflags |= SMIME_NOCERTS;
    }
    if (!(options->addAttr)) {
        *tflags |= SMIME_NOATTR;
    }
    if (!(options->addSmimeCapAttr)) {
        *tflags |= CMS_NOSMIMECAP;
    }
}

static CfResult IsInvalidPrivateKeyPassword(const PrivateKeyInfo *privateKey)
{
    unsigned long err = ERR_peek_last_error();
    if ((err == ERR_PRIVATE_KEY_PASSWORD_PKCS8 || err == ERR_PRIVATE_KEY_PASSWORD_PKCS1)
        && privateKey->privateKeyPassword != NULL) {
        return CF_ERR_CERT_INVALID_PRIVATE_KEY;
    }
    return CF_ERR_CRYPTO_OPERATION;
}

static CfResult ConvertPemToKey(const PrivateKeyInfo *privateKey, EVP_PKEY **pkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        LOGE("Failed to init bio.");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    if (BIO_write(bio, privateKey->privateKey->data, privateKey->privateKey->len) <= 0) {
        BIO_free(bio);
        LOGE("Failed to write pem private key to bio");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    EVP_PKEY *pkeyRet = NULL;
    const char *priPassword = privateKey->privateKeyPassword;
    if (priPassword == NULL) {
        priPassword = "";
    }
    ERR_clear_error();
    pkeyRet = PEM_read_bio_PrivateKey(bio, pkey, NULL, (char *)priPassword);
    BIO_free(bio);
    if (pkeyRet == NULL) {
        LOGE("Failed to read private key from bio");
        CfResult ret = IsInvalidPrivateKeyPassword(privateKey);
        CfPrintOpensslError();
        return ret;
    }
    return CF_SUCCESS;
}

static CfResult ConvertDerToKey(const PrivateKeyInfo *privateKey, EVP_PKEY **pkey)
{
    OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(pkey, "DER", NULL, "RSA", EVP_PKEY_KEYPAIR, NULL, NULL);
    if (dctx == NULL) {
        LOGE("Failed to init decoder context.");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    const char *priPassword = privateKey->privateKeyPassword;
    if (priPassword == NULL) {
        priPassword = "";
    }

    if (OSSL_DECODER_CTX_set_passphrase(dctx, (const unsigned char *)priPassword, strlen(priPassword)) != 1) {
        LOGE("Failed to set passphrase.");
        CfPrintOpensslError();
        OSSL_DECODER_CTX_free(dctx);
        EVP_PKEY_free(*pkey);
        return CF_ERR_CRYPTO_OPERATION;
    }
    const unsigned char *pdata = privateKey->privateKey->data;
    size_t pdataLen = privateKey->privateKey->len;
    ERR_clear_error();
    if (OSSL_DECODER_from_data(dctx, &pdata, &pdataLen) != 1) {
        LOGE("Failed to decode private key.");
        CfResult ret = IsInvalidPrivateKeyPassword(privateKey);
        CfPrintOpensslError();
        OSSL_DECODER_CTX_free(dctx);
        EVP_PKEY_free(*pkey);
        return ret;
    }
    OSSL_DECODER_CTX_free(dctx);
    return CF_SUCCESS;
}

static CfResult GetPrivateKey(const PrivateKeyInfo *privateKey, EVP_PKEY **pkey)
{
    if (privateKey->privateKey->encodingFormat == CF_FORMAT_PEM) {
        return ConvertPemToKey(privateKey, pkey);
    } else if (privateKey->privateKey->encodingFormat == CF_FORMAT_DER) {
        return ConvertDerToKey(privateKey, pkey);
    }
    return CF_INVALID_PARAMS;
}

static CfResult CheckSignerParam(HcfCmsGeneratorSpi *self, const HcfCertificate *x509Cert,
                                 const PrivateKeyInfo *privateKey, const HcfCmsSignerOptions *options)
{
    if ((self == NULL) || (x509Cert == NULL) || (privateKey == NULL) || (options == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCmsGeneratorClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    HcfCmsGeneratorOpensslImpl *impl = (HcfCmsGeneratorOpensslImpl *)self;
    if (impl->cms == NULL) {
        LOGE("Cms_ContentInfo is NULL.");
        return CF_ERR_CRYPTO_OPERATION;
    }

    int numSigners = CMS_get0_SignerInfos(impl->cms) ? sk_CMS_SignerInfo_num(CMS_get0_SignerInfos(impl->cms)) : 0;
    if (numSigners >= MAX_SIGNER_NUM) {
        LOGE("Maximum number of signers (20) exceeded.");
        return CF_ERR_CRYPTO_OPERATION;
    }
    return CF_SUCCESS;
}

static CfResult AddSignerOpenssl(HcfCmsGeneratorSpi *self, const HcfCertificate *x509Cert,
                                 const PrivateKeyInfo *privateKey, const HcfCmsSignerOptions *options)
{
    CfResult ret = CheckSignerParam(self, x509Cert, privateKey, options);
    if (ret != CF_SUCCESS) {
        return ret;
    }
    HcfCmsGeneratorOpensslImpl *impl = (HcfCmsGeneratorOpensslImpl *)self;
    HcfX509CertificateImpl *CertImpl = (HcfX509CertificateImpl *)x509Cert;
    if (!CfIsClassMatch((CfObjectBase *)(CertImpl->spiObj), X509_CERT_OPENSSL_CLASS)) {
        LOGE("Input wrong openssl class type!");
        return CF_INVALID_PARAMS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)(CertImpl->spiObj);
    X509 *x509 = realCert->x509;
    if (x509 == NULL) {
        LOGE("x509 is NULL.");
        return CF_ERR_CRYPTO_OPERATION;
    }
    const EVP_MD *md = NULL;
    ret = GetHashDigest(options->mdName, &md);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    int tflags = 0;
    GetSignerFlags(options, &tflags);

    EVP_PKEY *pkey = NULL;
    ret = GetPrivateKey(privateKey, &pkey);
    if (ret != CF_SUCCESS || pkey == NULL) {
        return ret;
    }
    // Add RSA key type check
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
        LOGE("Only RSA keys are supported.");
        EVP_PKEY_free(pkey);
        return CF_NOT_SUPPORT;
    }
    if (!CMS_add1_signer(impl->cms, x509, pkey, md, tflags)) {
        LOGE("CMS_add1_signer fail.");
        CfPrintOpensslError();
        EVP_PKEY_free(pkey);
        return CF_ERR_CRYPTO_OPERATION;
    }
    EVP_PKEY_free(pkey);
    return CF_SUCCESS;
}

static X509 *GetX509FromCertificate(const HcfCertificate *cert)
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

static CfResult AddCertOpenssl(HcfCmsGeneratorSpi *self, const HcfCertificate *cert)
{
    if ((self == NULL) || (cert == NULL)) {
        LOGE("Invalid params!");
        return CF_INVALID_PARAMS;  // Changed from false to proper error code
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCmsGeneratorClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;  // Changed from false to proper error code
    }

    HcfCmsGeneratorOpensslImpl *impl = (HcfCmsGeneratorOpensslImpl *)self;
    if (impl->cms == NULL) {
        LOGE("impl->cms is NULL.");
        return CF_INVALID_PARAMS;
    }

    // Add check for maximum number of certificates
    STACK_OF(X509) *certs = CMS_get1_certs(impl->cms);
    int numCerts = certs ? sk_X509_num(certs) : 0;
    sk_X509_pop_free(certs, X509_free);  // Free the cert stack after counting
    if (numCerts >= MAX_CERT_NUM) {
        LOGE("Maximum number of certificates (60) exceeded.");
        return CF_ERR_CRYPTO_OPERATION;
    }

    X509 *certOpenssl = GetX509FromCertificate(cert);
    if (certOpenssl == NULL) {
        LOGE("Input Cert is wrong!");
        return CF_INVALID_PARAMS;  // Changed from false to proper error code
    }

    if (!CMS_add1_cert(impl->cms, certOpenssl)) {
        LOGE("CMS_add1_cert fail.");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    return CF_SUCCESS;
}

static CfResult WriteBioToCms(CMS_ContentInfo *cms, const HcfCmsGeneratorOptions *options, CfBlob *out)
{
    BIO *outBio = BIO_new(BIO_s_mem());
    if (outBio == NULL) {
        LOGE("BIO_new error");
        return CF_ERR_MALLOC;
    }
    if (options->outFormat == CMS_PEM) {
        if (!PEM_write_bio_CMS(outBio, cms)) {
            LOGE("PEM_write_bio_CMS fail.");
            CfPrintOpensslError();
            BIO_free(outBio);
            return CF_ERR_CRYPTO_OPERATION;
        }
    } else if (options->outFormat == CMS_DER) {
        if (!i2d_CMS_bio(outBio, cms)) {
            LOGE("i2d_CMS_bio fail.");
            CfPrintOpensslError();
            BIO_free(outBio);
            return CF_ERR_CRYPTO_OPERATION;
        }
    } else {
        LOGE("Invalid outFormat.");
        BIO_free(outBio);
        return CF_INVALID_PARAMS;
    }
    BUF_MEM *bufMem = NULL;
    if (BIO_get_mem_ptr(outBio, &bufMem) <= 0 || bufMem == NULL) {
        LOGE("BIO_get_mem_ptr fail.");
        BIO_free(outBio);
        return CF_ERR_CRYPTO_OPERATION;
    }
    CfResult res = DeepCopyDataToOut(bufMem->data, bufMem->length, out);
    BIO_free(outBio);
    return res;
}

static CfResult DoFinalOpenssl(HcfCmsGeneratorSpi *self, const CfBlob *content, const HcfCmsGeneratorOptions *options,
                               CfBlob *out)
{
    if ((self == NULL) || (content == NULL) || (out == NULL) || (options == NULL)) {
        LOGE("Invalid params!");
        return CF_INVALID_PARAMS;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCmsGeneratorClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    HcfCmsGeneratorOpensslImpl *impl = (HcfCmsGeneratorOpensslImpl *)self;
    if (impl->cms == NULL) {
        LOGE("impl->cms is NULL.");
        return CF_INVALID_PARAMS;
    }
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        LOGE("Failed to new memory for bio.");
        return CF_INVALID_PARAMS;
    }
    if (BIO_write(bio, content->data, content->size) <= 0) {
        BIO_free(bio);
        LOGE("Failed to write content to bio");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    int flags = 0;
    if (options->dataFormat == BINARY) {
        flags |= SMIME_BINARY;
    } else if (options->dataFormat == TEXT) {
        flags |= SMIME_TEXT;
    } else {
        LOGE("Invalid dataFormat.");
        BIO_free(bio);
        return CF_INVALID_PARAMS;
    }
    int detached = options->isDetachedContent ? true : false;
    if (detached) {
        CMS_set_detached(impl->cms, detached);
    }
    int ret = CMS_final(impl->cms, bio, NULL, flags);
    BIO_free(bio);
    if (ret != 1) {
        LOGE("CMS_final fail.");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    return WriteBioToCms(impl->cms, options, out);
}

CfResult HcfCmsGeneratorSpiCreate(HcfCmsContentType type, HcfCmsGeneratorSpi **spi)
{
    if (spi == NULL) {
        LOGE("Invalid params, spi is null!");
        return CF_INVALID_PARAMS;
    }
    if (type != SIGNED_DATA) {
        LOGE("Invalid params,type is not supported!");
        return CF_INVALID_PARAMS;
    }
    HcfCmsGeneratorOpensslImpl *cmsGenerator =
        (HcfCmsGeneratorOpensslImpl *)CfMalloc(sizeof(HcfCmsGeneratorOpensslImpl), 0);
    if (cmsGenerator == NULL) {
        LOGE("Failed to allocate cmsGenerator memory!");
        return CF_ERR_MALLOC;
    }
    CMS_ContentInfo *cms = NULL;
    cms = CMS_sign_ex(NULL, NULL, NULL, NULL, CMS_PARTIAL, NULL, NULL);
    if (cms == NULL) {
        LOGE("Cms_sign_ex fail.");
        CfPrintOpensslError();
        CfFree(cmsGenerator);
        return CF_ERR_CRYPTO_OPERATION;
    }
    cmsGenerator->cms = cms;
    cmsGenerator->base.base.getClass = GetCmsGeneratorClass;
    cmsGenerator->base.base.destroy = DestroyCmsGenerator;
    cmsGenerator->base.engineAddSigner = AddSignerOpenssl;
    cmsGenerator->base.engineAddCert = AddCertOpenssl;
    cmsGenerator->base.engineDoFinal = DoFinalOpenssl;
    *spi = (HcfCmsGeneratorSpi *)cmsGenerator;
    return CF_SUCCESS;
}