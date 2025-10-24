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
#include "securec.h"
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
#include "securec.h"
#include "x509_cert_chain_openssl_ex.h"

#define MAX_SIGNER_NUM 20
#define MAX_CERT_NUM 60
#define MAX_RECIPIENT_NUM 20

#define ERR_PRIVATE_KEY_PASSWORD_PKCS8 0x11800074
#define ERR_PRIVATE_KEY_PASSWORD_PKCS1 0x4800065

typedef struct {
    HcfCmsGeneratorSpi base;
    CMS_ContentInfo *cms;
    BIO *encryptedContentBio;  // BIO to store encrypted content data from CMS_final
} HcfCmsGeneratorOpensslImpl;

typedef struct {
    HcfCmsParserSpi base;
    CMS_ContentInfo *cms;
} HcfCmsParserOpensslImpl;

#define X509_CERT_CMS_GENERATOR_OPENSSL_CLASS "X509CertCmsGeneratorOpensslClass"
#define X509_CERT_CMS_PARSER_OPENSSL_CLASS "X509CertCmsParserOpensslClass"

static const char *GetCmsGeneratorClass(void)
{
    return X509_CERT_CMS_GENERATOR_OPENSSL_CLASS;
}

static const char *GetCmsParserClass(void)
{
    return X509_CERT_CMS_PARSER_OPENSSL_CLASS;
}

static void DestroyCmsParser(CfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Invalid params!");
        return;
    }
    if (!CfIsClassMatch(self, GetCmsParserClass())) {
        LOGE("Class is not match.");
        return;
    }
    HcfCmsParserOpensslImpl *impl = (HcfCmsParserOpensslImpl *)self;
    if (impl->cms != NULL) {
        CMS_ContentInfo_free(impl->cms);
    }
    CfFree(impl);
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
    if (impl->encryptedContentBio != NULL) {
        BIO_free(impl->encryptedContentBio);
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

static void GetSignerFlags(const HcfCmsSignerOptions *options, unsigned int *tflags, int keyType)
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
    if (keyType == EVP_PKEY_RSA) {
        *tflags |= CMS_KEY_PARAM;
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

static CfResult ValidateRsaPssParams(int keyType, const HcfCmsSignerOptions *options)
{
    if (keyType == EVP_PKEY_RSA && options->padding == PKCS1_PSS_PADDING) {
        if (strcmp(options->mdName, "SHA256") != 0 &&
            strcmp(options->mdName, "SHA384") != 0 &&
            strcmp(options->mdName, "SHA512") != 0) {
            LOGE("RSA PSS only supports SHA256, SHA384, SHA512.");
            return CF_ERR_PARAMETER_CHECK;
        }
    }
    return CF_SUCCESS;
}

static CfResult ConfigureRsaPadding(CMS_SignerInfo *signer, const HcfCmsSignerOptions *options)
{
    if (options->padding != PKCS1_PADDING && options->padding != PKCS1_PSS_PADDING) {
        LOGE("Only PKCS1 and PKCS1_PSS padding are supported.");
        return CF_ERR_PARAMETER_CHECK;
    }

    int padMode = 0;
    if (options->padding == PKCS1_PSS_PADDING) {
        padMode = RSA_PKCS1_PSS_PADDING;
    } else {
        padMode = RSA_PKCS1_PADDING;
    }

    EVP_PKEY_CTX *pctx = CMS_SignerInfo_get0_pkey_ctx(signer);
    if (pctx == NULL) {
        LOGE("CMS_SignerInfo_get0_pkey_ctx failed.");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, padMode) != CF_OPENSSL_SUCCESS) {
        LOGE("Failed to set RSA padding mode.");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    return CF_SUCCESS;
}

static CfResult PrepareSignerData(const PrivateKeyInfo *privateKey, const HcfCmsSignerOptions *options, EVP_PKEY **pkey,
                                  const EVP_MD **md, unsigned int *tflags)
{
    CfResult ret = GetPrivateKey(privateKey, pkey);
    if (ret != CF_SUCCESS) {
        LOGE("Failed to get private key.");
        return ret;
    }
    // Add RSA and EC key type check
    int keyType = EVP_PKEY_base_id(*pkey);
    if (keyType != EVP_PKEY_RSA && keyType != EVP_PKEY_EC) {
        LOGE("Only RSA and EC keys are supported.");
        EVP_PKEY_free(*pkey);
        return CF_NOT_SUPPORT;
    }

    // Validate RSA PSS parameters
    ret = ValidateRsaPssParams(keyType, options);
    if (ret != CF_SUCCESS) {
        EVP_PKEY_free(*pkey);
        LOGE ("ValidateRsaPssParams failed.");
        return ret;
    }
    // Get digest
    ret = GetHashDigest(options->mdName, md);
    if (ret != CF_SUCCESS) {
        EVP_PKEY_free(*pkey);
        LOGE ("GetHashDigest failed.");
        return ret;
    }

    // Get signer flags
    GetSignerFlags(options, tflags, keyType);
    return CF_SUCCESS;
}

static CfResult CheckCmsType(HcfCmsGeneratorOpensslImpl *impl, HcfCmsContentType type)
{
    if (impl->cms == NULL) {
        LOGE("impl->cms is NULL.");
        return CF_ERR_PARAMETER_CHECK;
    }
    const ASN1_OBJECT *contentType = CMS_get0_type(impl->cms);
    if (contentType == NULL) {
        LOGE("Failed to get CMS content type.");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    int nid = OBJ_obj2nid(contentType);
    if (type == SIGNED_DATA) {
        if (nid != NID_pkcs7_signed) {
            LOGE("CMS is not of signed type.");
            return CF_ERR_CRYPTO_OPERATION;
        }
    } else if (type == ENVELOPED_DATA) {
        if (nid != NID_id_smime_ct_authEnvelopedData && nid != NID_pkcs7_enveloped) {
            LOGE("CMS is not of EnvelopedData type.");
            return CF_ERR_CRYPTO_OPERATION;
        }
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
    ret = CheckCmsType(impl, SIGNED_DATA);
    if (ret != CF_SUCCESS) {
        return ret;
    }
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
    EVP_PKEY *pkey = NULL;
    const EVP_MD *md = NULL;
    unsigned int tflags = 0;
    ret = PrepareSignerData(privateKey, options, &pkey, &md, &tflags);
    if (ret != CF_SUCCESS) {
        LOGE("PrepareSignerData failed.");
        return ret;
    }
    CMS_SignerInfo *signer = CMS_add1_signer(impl->cms, x509, pkey, md, tflags);
    if (signer == NULL) {
        LOGE("CMS_add1_signer fail.");
        CfPrintOpensslError();
        EVP_PKEY_free(pkey);
        return CF_ERR_CRYPTO_OPERATION;
    }
    if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA) {
        ret = ConfigureRsaPadding(signer, options);
        if (ret != CF_SUCCESS) {
            EVP_PKEY_free(pkey);
            LOGE("RSA padding configuration failed.");
            return ret;
        }
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
    CfResult ret = CheckCmsType(impl, SIGNED_DATA);
    if (ret != CF_SUCCESS) {
        LOGE("CheckCmsType failed.");
        return ret;
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
        if (PEM_write_bio_CMS(outBio, cms) != CF_OPENSSL_SUCCESS) {
            LOGE("PEM_write_bio_CMS fail.");
            CfPrintOpensslError();
            BIO_free(outBio);
            return CF_ERR_CRYPTO_OPERATION;
        }
    } else if (options->outFormat == CMS_DER) {
        if (i2d_CMS_bio(outBio, cms) <= 0) {
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
    CfResult res = DeepCopyDataToOutEx(bufMem->data, bufMem->length, out);
    BIO_free(outBio);
    return res;
}

static bool ValidateDoFinalParams(HcfCmsGeneratorSpi *self, const CfBlob *content,
                                  const HcfCmsGeneratorOptions *options, CfBlob *out)
{
    if ((self == NULL) || (content == NULL) || (out == NULL) || (options == NULL)) {
        LOGE("Invalid params!");
        return false;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCmsGeneratorClass())) {
        LOGE("Class is not match.");
        return false;
    }
    return true;
}

static CfResult CreateAndWriteBio(const CfBlob *content, BIO **bio)
{
    *bio = BIO_new(BIO_s_mem());
    if (*bio == NULL) {
        LOGE("Failed to new memory for bio.");
        return CF_ERR_MALLOC;
    }
    if (BIO_write(*bio, content->data, content->size) <= 0) {
        BIO_free(*bio);
        LOGE("Failed to write content to bio");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    return CF_SUCCESS;
}

static CfResult SetupEncryptedContentBio(HcfCmsGeneratorOpensslImpl *impl, BIO **encryptedContentBio)
{
    *encryptedContentBio = BIO_new(BIO_s_mem());
    if (*encryptedContentBio == NULL) {
        LOGE("Failed to create encrypted content BIO.");
        CfPrintOpensslError();
        return CF_ERR_MALLOC;
    }
    // Clean up any existing encrypted content BIO
    if (impl->encryptedContentBio != NULL) {
        BIO_free(impl->encryptedContentBio);
    }
    impl->encryptedContentBio = *encryptedContentBio;
    return CF_SUCCESS;
}

static CfResult GetCmsFlags(const HcfCmsGeneratorOptions *options, unsigned int *flags)
{
    *flags = 0;
    if (options->dataFormat == BINARY) {
        *flags |= SMIME_BINARY;
    } else if (options->dataFormat == TEXT) {
        *flags |= SMIME_TEXT;
    } else {
        LOGE("Invalid dataFormat.");
        return CF_INVALID_PARAMS;
    }
    return CF_SUCCESS;
}

// Helper function for BIO creation, flag setup, and CMS finalization
static CfResult CmsFinal(HcfCmsGeneratorOpensslImpl *impl, const CfBlob *content, const HcfCmsGeneratorOptions *options,
                         BIO *encryptedContentBio)
{
    BIO *bio = NULL;
    CfResult res = CreateAndWriteBio(content, &bio);
    if (res != CF_SUCCESS) {
        return res;
    }
    unsigned int flags = 0;
    res = GetCmsFlags(options, &flags);
    if (res != CF_SUCCESS) {
        BIO_free(bio);
        return res;
    }
    int detached = options->isDetachedContent ? 1 : 0;
    int result = CMS_set_detached(impl->cms, detached);
    if (result != CF_OPENSSL_SUCCESS) {
        LOGE("CMS_set_detached fail.");
        CfPrintOpensslError();
        BIO_free(bio);
        return CF_ERR_CRYPTO_OPERATION;
    }
    int ret = CMS_final(impl->cms, bio, encryptedContentBio, flags);
    BIO_free(bio);
    if (ret != CF_OPENSSL_SUCCESS) {
        LOGE("CMS_final fail.");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    return CF_SUCCESS;
}

static CfResult DoFinalOpenssl(HcfCmsGeneratorSpi *self, const CfBlob *content, const HcfCmsGeneratorOptions *options,
                               CfBlob *out)
{
    CfResult res;
    BIO *encryptedContentBio = NULL;
    if (!ValidateDoFinalParams(self, content, options, out)) {
        return CF_INVALID_PARAMS;
    }
    HcfCmsGeneratorOpensslImpl *impl = (HcfCmsGeneratorOpensslImpl *)self;
    if (impl->cms == NULL) {
        LOGE("impl->cms is NULL.");
        return CF_INVALID_PARAMS;
    }
    const ASN1_OBJECT *contentType = CMS_get0_type(impl->cms);
    if (contentType == NULL) {
        LOGE("contentType is null.");
        return CF_ERR_CRYPTO_OPERATION;
    }
    int nid = OBJ_obj2nid(contentType);
    if (nid == NID_pkcs7_signed) {
        STACK_OF(CMS_SignerInfo) *signers = CMS_get0_SignerInfos(impl->cms);
        if (signers == NULL) {
            LOGE("CMS_get0_SignerInfos failed");
            return CF_ERR_CRYPTO_OPERATION;
        }
        int numSigners = sk_CMS_SignerInfo_num(signers);
        if (numSigners == 0) {
            LOGI("No signers found, outputting cert-only CMS structure without signature.");
            return WriteBioToCms(impl->cms, options, out);
        }
    } else if (nid == NID_id_smime_ct_authEnvelopedData || nid == NID_pkcs7_enveloped) {
        res = SetupEncryptedContentBio(impl, &encryptedContentBio);
        if (res != CF_SUCCESS) {
            return res;
        }
    } else {
        LOGE("Unsupported CMS type for DoFinal: NID %{public}d", nid);
        return CF_ERR_CRYPTO_OPERATION;
    }
    res = CmsFinal(impl, content, options, encryptedContentBio);
    if (res != CF_SUCCESS) {
        return res;
    }

    return WriteBioToCms(impl->cms, options, out);
}

static int GetCipherNidByAlg(CfCmsRecipientEncryptionAlgorithm alg)
{
    switch (alg) {
        case CMS_AES_128_CBC:
            return NID_aes_128_cbc;
        case CMS_AES_192_CBC:
            return NID_aes_192_cbc;
        case CMS_AES_256_CBC:
            return NID_aes_256_cbc;
        case CMS_AES_128_GCM:
            return NID_aes_128_gcm;
        case CMS_AES_192_GCM:
            return NID_aes_192_gcm;
        case CMS_AES_256_GCM:
            return NID_aes_256_gcm;
        default:
            return NID_undef;
    }
}

static CfResult CreateCmsWithCipher(HcfCmsGeneratorOpensslImpl *impl, int cipherNid)
{
    const EVP_CIPHER *cipher = EVP_get_cipherbynid(cipherNid);
    if (cipher == NULL) {
        LOGE("Failed to get cipher by NID.");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    CMS_ContentInfo *newCms = NULL;
    if (cipherNid == NID_aes_128_gcm || cipherNid == NID_aes_192_gcm || cipherNid == NID_aes_256_gcm) {
        newCms = CMS_AuthEnvelopedData_create(cipher);
    } else {
        newCms = CMS_EnvelopedData_create(cipher);
    }
    if (newCms == NULL) {
        LOGE("Failed to create CMS with new encryption algorithm.");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    CMS_ContentInfo_free(impl->cms);
    impl->cms = newCms;
    return CF_SUCCESS;
}

static CfResult SetRecipientEncryptionAlgorithmOpenssl(HcfCmsGeneratorSpi *self, CfCmsRecipientEncryptionAlgorithm alg)
{
    if (self == NULL) {
        LOGE("Invalid params!");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCmsGeneratorClass())) {
        LOGE("Class is not match.");
        return CF_ERR_PARAMETER_CHECK;
    }
    HcfCmsGeneratorOpensslImpl *impl = (HcfCmsGeneratorOpensslImpl *)self;
    CfResult ret = CheckCmsType(impl, ENVELOPED_DATA);
    if (ret != CF_SUCCESS) {
        LOGE("CheckCmsType failed.");
        return ret;
    }
    int cipherNid = GetCipherNidByAlg(alg);
    if (cipherNid == NID_undef) {
        LOGE("Unsupported recipient encryption algorithm.");
        return CF_ERR_PARAMETER_CHECK;
    }
    return CreateCmsWithCipher(impl, cipherNid);
}

static CfResult ValidateCertificateKeyType(X509 *cert, int expectedKeyType)
{
    EVP_PKEY *pubKey = X509_get0_pubkey(cert);
    if (pubKey == NULL) {
        LOGE("Failed to extract public key from certificate.");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    int keyType = EVP_PKEY_base_id(pubKey);
    if (keyType != expectedKeyType) {
        LOGE("Requires certificate of key type %{public}d. Found key type: %{public}d", expectedKeyType, keyType);
        return CF_ERR_PARAMETER_CHECK;
    }
    return CF_SUCCESS;
}

static CfResult AddKeyAgreementRecipient(CMS_ContentInfo *cms, X509 *recipientCert, const EVP_MD *kdfDigest)
{
    // Step 1: Use CMS_add1_recipient_cert to create KeyAgreeRecipientInfo structure
    CMS_RecipientInfo *recInfo = CMS_add1_recipient_cert(cms, recipientCert, CMS_RECIPINFO_AGREE);
    if (recInfo == NULL) {
        LOGE("Failed to add key agreement recipient.");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    // Step 2: Retrieve the internal EVP_PKEY_CTX using CMS_RecipientInfo_get0_pkey_ctx
    EVP_PKEY_CTX *pctx = CMS_RecipientInfo_get0_pkey_ctx(recInfo);
    if (pctx == NULL) {
        LOGE("Failed to get EVP_PKEY_CTX from RecipientInfo.");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    // Step 3: Configure KDF digest algorithm using the CMS internal EVP_PKEY_CTX
    if (EVP_PKEY_CTX_set_ecdh_kdf_md(pctx, kdfDigest) != CF_OPENSSL_SUCCESS) {
        LOGE("Failed to set KDF digest algorithm via EVP_PKEY_CTX_set_ecdh_kdf_md.");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    return CF_SUCCESS;
}

static CfResult AddKeyTransRecipientCert(HcfCmsGeneratorOpensslImpl *impl, CmsRecipientInfo *recipientInfo)
{
    if (recipientInfo->keyTransInfo->recipientCert == NULL) {
        LOGE("recipientCert is required for keyTransInfo.");
        return CF_ERR_PARAMETER_CHECK;
    }

    X509 *recipientX509 = GetX509FromCertificate(recipientInfo->keyTransInfo->recipientCert);
    if (recipientX509 == NULL) {
        LOGE("Failed to get X509 certificate from keyTransInfo.");
        return CF_ERR_PARAMETER_CHECK;
    }

    // Validate that the certificate is suitable for RSA key transport
    CfResult validateResult = ValidateCertificateKeyType(recipientX509, EVP_PKEY_RSA);
    if (validateResult != CF_SUCCESS) {
        LOGE("ValidateCertificateKeyType failed.");
        return validateResult;
    }

    // Add the key transport recipient with RSA PKCS1 padding (default)
    CMS_RecipientInfo *recInfo = CMS_add1_recipient_cert(impl->cms, recipientX509, CMS_RECIPINFO_TRANS);
    if (recInfo == NULL) {
        LOGE("Failed to add key transport recipient.");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    return CF_SUCCESS;
}

static CfResult AddKeyAgreeRecipientCert(HcfCmsGeneratorOpensslImpl *impl, CmsRecipientInfo *recipientInfo)
{
    if (recipientInfo->keyAgreeInfo->recipientCert == NULL) {
        LOGE("recipientCert is required for keyAgreeInfo.");
        return CF_ERR_PARAMETER_CHECK;
    }

    X509 *recipientX509 = GetX509FromCertificate(recipientInfo->keyAgreeInfo->recipientCert);
    if (recipientX509 == NULL) {
        LOGE("Failed to get X509 certificate from keyAgreeInfo.");
        return CF_ERR_PARAMETER_CHECK;
    }
    const EVP_MD *kdfDigest = NULL;
    switch (recipientInfo->keyAgreeInfo->digestAlgorithm) {
        case CMS_SHA256:
            kdfDigest = EVP_sha256();
            break;
        case CMS_SHA384:
            kdfDigest = EVP_sha384();
            break;
        case CMS_SHA512:
            kdfDigest = EVP_sha512();
            break;
        default:
            LOGE("Invalid digest algorithm for key agreement recipient: %{public}d",
                recipientInfo->keyAgreeInfo->digestAlgorithm);
            return CF_ERR_PARAMETER_CHECK;
    }
    // Validate that the certificate is suitable for EC key agreement
    CfResult validateResult = ValidateCertificateKeyType(recipientX509, EVP_PKEY_EC);
    if (validateResult != CF_SUCCESS) {
        LOGE("ValidateCertificateKeyType failed.");
        return validateResult;
    }
    // Add the key agreement recipient with KDF digest configuration
    return AddKeyAgreementRecipient(impl->cms, recipientX509, kdfDigest);
}

static CfResult AddRecipientInfoOpenssl(HcfCmsGeneratorSpi *self, CmsRecipientInfo *recipientInfo)
{
    if (self == NULL || recipientInfo == NULL) {
        LOGE("Invalid params!");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCmsGeneratorClass())) {
        LOGE("Class is not match.");
        return CF_ERR_PARAMETER_CHECK;
    }
    HcfCmsGeneratorOpensslImpl *impl = (HcfCmsGeneratorOpensslImpl *)self;
    CfResult ret = CheckCmsType(impl, ENVELOPED_DATA);
    if (ret != CF_SUCCESS) {
        LOGE("CheckCmsType failed.");
        return ret;
    }
    // Check if at least one recipient info is provided
    if (recipientInfo->keyTransInfo == NULL && recipientInfo->keyAgreeInfo == NULL) {
        LOGE("At least one recipient info (keyTransInfo or keyAgreeInfo) must be provided.");
        return CF_ERR_PARAMETER_CHECK;
    }

    // Check maximum number of recipients
    STACK_OF(CMS_RecipientInfo) *recipients = CMS_get0_RecipientInfos(impl->cms);
    int numRecipients = recipients ? sk_CMS_RecipientInfo_num(recipients) : 0;
    if (numRecipients >= MAX_RECIPIENT_NUM) {
        LOGE("Maximum number of recipients (%{public}d) exceeded.", MAX_RECIPIENT_NUM);
        return CF_ERR_CRYPTO_OPERATION;
    }

    CfResult result = CF_SUCCESS;
    // Handle Key Transport Recipient Info
    if (recipientInfo->keyTransInfo != NULL) {
        result = AddKeyTransRecipientCert(impl, recipientInfo);
        if (result != CF_SUCCESS) {
            LOGE("Failed to add key transport recipient.");
            return result;
        }
    }

    // Handle Key Agreement Recipient Info
    if (recipientInfo->keyAgreeInfo != NULL) {
        result = AddKeyAgreeRecipientCert(impl, recipientInfo);
        if (result != CF_SUCCESS) {
            LOGE("Failed to add key agreement recipient.");
            return result;
        }
    }
    return CF_SUCCESS;
}

static CfResult GetEncryptedContentDataOpenssl(HcfCmsGeneratorSpi *self, CfBlob *out)
{
    if (self == NULL || out == NULL) {
        LOGE("Invalid params!");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCmsGeneratorClass())) {
        LOGE("Class is not match.");
        return CF_ERR_PARAMETER_CHECK;
    }
    HcfCmsGeneratorOpensslImpl *impl = (HcfCmsGeneratorOpensslImpl *)self;
    CfResult ret = CheckCmsType(impl, ENVELOPED_DATA);
    if (ret != CF_SUCCESS) {
        LOGE("CheckCmsType failed.");
        return ret;
    }
    // Check if encrypted content BIO is available
    if (impl->encryptedContentBio == NULL) {
        LOGE("No encrypted content data available. Call doFinal first to generate encrypted content.");
        return CF_ERR_CRYPTO_OPERATION;
    }

    // Get the encrypted data from the BIO
    BUF_MEM *bufMem = NULL;
    if (BIO_get_mem_ptr(impl->encryptedContentBio, &bufMem) <= 0 || bufMem == NULL) {
        LOGE("Failed to get encrypted data from BIO.");
        return CF_ERR_CRYPTO_OPERATION;
    }

    if (bufMem->length == 0) {
        LOGE("No encrypted content data found in BIO.");
        return CF_ERR_CRYPTO_OPERATION;
    }

    // Copy the encrypted data to the output blob
    CfResult res = DeepCopyDataToOutEx(bufMem->data, bufMem->length, out);
    if (res != CF_SUCCESS) {
        LOGE("Failed to copy encrypted content data to output blob.");
        return res;
    }
    return CF_SUCCESS;
}

static CfResult GetRawDataType(HcfCmsParserSpi *self, HcfCmsContentType *contentType)
{
    HcfCmsParserOpensslImpl *impl = (HcfCmsParserOpensslImpl *)self;
    const ASN1_OBJECT *type = CMS_get0_type(impl->cms);
    if (type == NULL) {
        LOGE("Failed to get CMS content type");
        CMS_ContentInfo_free(impl->cms);
        impl->cms = NULL;
        return CF_ERR_CRYPTO_OPERATION;
    }
    int typeNid = OBJ_obj2nid(type);
    if (typeNid == NID_pkcs7_signed) {
        *contentType = SIGNED_DATA;
    } else if (typeNid == NID_pkcs7_enveloped) {
        *contentType = ENVELOPED_DATA;
    } else if (typeNid == NID_id_smime_ct_authEnvelopedData) {
        *contentType = ENVELOPED_DATA;
    } else {
        LOGE("Unsupported CMS content type: %d", typeNid);
        CMS_ContentInfo_free(impl->cms);
        impl->cms = NULL;
        return CF_ERR_CRYPTO_OPERATION;
    }
    return CF_SUCCESS;
}

static CfResult SetRawDataOpenssl(HcfCmsParserSpi *self, const CfBlob *rawData, HcfCmsFormat cmsFormat)
{
    if (self == NULL || rawData == NULL) {
        LOGE("Invalid input parameter.");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCmsParserClass())) {
        LOGE("Class is not match.");
        return CF_ERR_PARAMETER_CHECK;
    }
    HcfCmsParserOpensslImpl *impl = (HcfCmsParserOpensslImpl *)self;
    if (impl->cms != NULL) {
        CMS_ContentInfo_free(impl->cms);
        impl->cms = NULL;
    }
    BIO *bio = BIO_new_mem_buf(rawData->data, rawData->size);
    if (bio == NULL) {
        LOGE("Failed to new memory for bio.");
        return CF_ERR_CRYPTO_OPERATION;
    }
    CMS_ContentInfo *cms = NULL;
    if (cmsFormat == CMS_PEM) {
        if (!PEM_read_bio_CMS(bio, &cms, NULL, NULL)) {
            LOGE("PEM_read_bio_CMS fail.");
            CfPrintOpensslError();
            BIO_free(bio);
            return CF_ERR_CRYPTO_OPERATION;
        }
    } else if (cmsFormat == CMS_DER) {
        cms = d2i_CMS_bio(bio, NULL);
        if (cms == NULL) {
            LOGE("i2d_CMS_bio fail.");
            CfPrintOpensslError();
            BIO_free(bio);
            return CF_ERR_CRYPTO_OPERATION;
        }
    } else {
        LOGE("Invalid cmsFormat.");
        BIO_free(bio);
        return CF_ERR_PARAMETER_CHECK;
    }
    BIO_free(bio);
    impl->cms = cms;
    return CF_SUCCESS;
}

static CfResult GetContentTypeOpenssl(HcfCmsParserSpi *self, HcfCmsContentType *contentType)
{
    if (self == NULL || contentType == NULL) {
        LOGE("Invalid input parameter.");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCmsParserClass())) {
        LOGE("Class is not match.");
        return CF_ERR_PARAMETER_CHECK;
    }
    HcfCmsParserOpensslImpl *impl = (HcfCmsParserOpensslImpl *)self;
    if (impl->cms == NULL) {
        LOGE("cms is null.");
        return CF_ERR_SHOULD_NOT_CALL;
    }
    CfResult res = GetRawDataType(self, contentType);
    if (res != CF_SUCCESS) {
        LOGE("GetRawDataType fail.");
        CMS_ContentInfo_free(impl->cms);
        impl->cms = NULL;
        return res;
    }
    return CF_SUCCESS;
}

static CfResult  CmsVerifyGetTrustCert(const HcfCmsParserSignedDataOptions *options, X509_STORE **caStore)
{
    X509_STORE *tmpCaStore = X509_STORE_new();
    if (tmpCaStore == NULL) {
        LOGE("Failed to create X509_STORE");
        return CF_ERR_CRYPTO_OPERATION;
    }
    if (options->trustCerts != NULL && options->trustCerts->data != NULL && options->trustCerts->count > 0) {
        for (uint32_t i = 0; i < options->trustCerts->count; i++) {
            X509 *trustCert = GetX509FromHcfX509Certificate((HcfCertificate *)options->trustCerts->data[i]);
            if (trustCert == NULL) {
                LOGE("Failed to get X509 from trust certificate");
                X509_STORE_free(tmpCaStore);
                return CF_ERR_CRYPTO_OPERATION;
            }
            int result = X509_STORE_add_cert(tmpCaStore, trustCert);
            if (result != 1) {
                LOGE("Failed to add trust certificate to store");
                X509_STORE_free(tmpCaStore);
                return CF_ERR_CRYPTO_OPERATION;
            }
        }
    }
    *caStore = tmpCaStore;
    return CF_SUCCESS;
}

static CfResult CmsVerifyGetSignerCertStack(const HcfCmsParserSignedDataOptions *options, STACK_OF(X509) **signerCerts)
{
    STACK_OF(X509) *tmpSignerCerts = sk_X509_new_null();
    if (tmpSignerCerts == NULL) {
        LOGE("Failed to create STACK_OF(X509)");
        return CF_ERR_CRYPTO_OPERATION;
    }
    if (options->signerCerts != NULL && options->signerCerts->data != NULL && options->signerCerts->count > 0) {
        for (uint32_t i = 0; i < options->signerCerts->count; i++) {
            X509 *signerCert = GetX509FromHcfX509Certificate((HcfCertificate *)options->signerCerts->data[i]);
            if (signerCert == NULL) {
                LOGE("Failed to get X509 from signer certificate");
                sk_X509_free(tmpSignerCerts);
                return CF_ERR_CRYPTO_OPERATION;
            }
            int result = sk_X509_push(tmpSignerCerts, signerCert);
            if (result <= 0) {
                LOGE("Failed to add signer certificate to stack");
                sk_X509_free(tmpSignerCerts);
                return CF_ERR_CRYPTO_OPERATION;
            }
        }
    }
    *signerCerts = tmpSignerCerts;
    return CF_SUCCESS;
}

static int CmsCertErrorCb(const char *errStr, size_t len, void *u)
{
    (void)len;
    if (errStr == NULL || u == NULL) {
        return 0;
    }
    LOGE("cert check error: %{public}s", errStr);
    CfResult result = CF_ERR_CRYPTO_OPERATION;
    if (strstr(errStr, "certificate is not yet valid") != NULL) {
        result = CF_ERR_CERT_NOT_YET_VALID;
    } else if (strstr(errStr, "certificate has expired") != NULL) {
        result = CF_ERR_CERT_HAS_EXPIRED;
    } else if (strstr(errStr, "unable to get issuer certificate") != NULL) {
        result = CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
    }
    *((CfResult *)u) = result;
    return 1;
}

static CfResult CmsVerifyGetContentData(bool hasCmsContent, const HcfCmsParserSignedDataOptions *options,
    BIO **contentBio)
{
    BIO *tmpContentBio = NULL;
    if (hasCmsContent) {
        LOGD("CMS contains attached content data, using content from CMS");
        tmpContentBio = NULL;
    } else {
        LOGD("CMS is detached, using manually provided content data");
        if (options->contentData == NULL || options->contentData->data == NULL || options->contentData->size == 0) {
            LOGD("content data is empty, skip verification");
            unsigned char emptyData[] = {};
            tmpContentBio = BIO_new_mem_buf(emptyData, sizeof(emptyData));
            if (tmpContentBio == NULL) {
                LOGE("Failed to create BIO for empty content data");
                CfPrintOpensslError();
                return CF_ERR_CRYPTO_OPERATION;
            }
            *contentBio = tmpContentBio;
            return CF_SUCCESS;
        }
        tmpContentBio = BIO_new_mem_buf(options->contentData->data, options->contentData->size);
        if (tmpContentBio == NULL) {
            LOGE("Failed to create BIO for manual content data");
            CfPrintOpensslError();
            return CF_ERR_CRYPTO_OPERATION;
        }
    }
    *contentBio = tmpContentBio;
    return CF_SUCCESS;
}

static CfResult BuildVerifyParams(CMS_ContentInfo *cms, const HcfCmsParserSignedDataOptions *options,
    STACK_OF(X509) **signerCerts, X509_STORE **caStore, BIO **contentBio)
{
    if (options->contentDataFormat != BINARY && options->contentDataFormat != TEXT) {
        LOGE("contentDataFormat is not valid, it should be BINARY or TEXT.");
        return CF_ERR_PARAMETER_CHECK;
    }

    bool hasCmsContent = false;
    ASN1_OCTET_STRING **cmsContent = CMS_get0_content(cms);
    if (cmsContent != NULL && *cmsContent != NULL) {
        hasCmsContent = true;
    }
    CfResult res = CmsVerifyGetTrustCert(options, caStore);
    if (res != CF_SUCCESS) {
        LOGE("Failed to get trust cert");
        return res;
    }

    res = CmsVerifyGetSignerCertStack(options, signerCerts);
    if (res != CF_SUCCESS) {
        LOGE("Failed to get signer cert stack");
        return res;
    }

    res = CmsVerifyGetContentData(hasCmsContent, options, contentBio);
    if (res != CF_SUCCESS) {
        LOGE("Failed to get content data");
        return res;
    }
    return CF_SUCCESS;
}

static CfResult CmsContentTypeCheck(HcfCmsParserSpi *self, HcfCmsContentType contentType)
{
    HcfCmsContentType type;
    CfResult res = GetRawDataType(self, &type);
    if (res != CF_SUCCESS) {
        LOGE("GetRawDataType fail.");
        return res;
    }
    if (type != contentType) {
        LOGE("CMS content type is not SIGNED_DATA");
        return CF_ERR_PARAMETER_CHECK;
    }
    return CF_SUCCESS;
}

CfResult VerifySignedDataOpenssl(HcfCmsParserSpi *self, const HcfCmsParserSignedDataOptions *options)
{
    if (self == NULL || options == NULL) {
        LOGE("Invalid input parameter.");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCmsParserClass())) {
        LOGE("Class is not match.");
        return CF_ERR_PARAMETER_CHECK;
    }
    HcfCmsParserOpensslImpl *impl = (HcfCmsParserOpensslImpl *)self;
    if (impl->cms == NULL) {
        LOGE("cms is null.");
        return CF_ERR_SHOULD_NOT_CALL;
    }

    CfResult res = CmsContentTypeCheck(self, SIGNED_DATA);
    if (res != CF_SUCCESS) {
        LOGE("CMS content type is not SIGNED_DATA");
        return res;
    }

    STACK_OF(X509) *signerCerts = NULL;
    X509_STORE *caStore = NULL;
    BIO *contentBio = NULL;

    res = BuildVerifyParams(impl->cms, options, &signerCerts, &caStore, &contentBio);
    if (res != CF_SUCCESS) {
        sk_X509_free(signerCerts);
        X509_STORE_free(caStore);
        BIO_free(contentBio);
        LOGE("Failed to build verify params");
        return res;
    }
    int result = CMS_verify(impl->cms, signerCerts, caStore, contentBio, NULL, 0);
    if (result != CF_OPENSSL_SUCCESS) {
        LOGE("Failed to verify CMS");
        CfResult certResult = CF_ERR_CRYPTO_OPERATION;
        ERR_print_errors_cb(CmsCertErrorCb, &certResult);
        sk_X509_free(signerCerts);
        X509_STORE_free(caStore);
        BIO_free(contentBio);
        CfPrintOpensslError();
        return certResult;
    }
    BIO_free(contentBio);
    sk_X509_free(signerCerts);
    X509_STORE_free(caStore);
    LOGD("verify signed data success");
    return CF_SUCCESS;
}

static CfResult GetCmsAllCerts(HcfCmsParserOpensslImpl *impl, int32_t certsNum, STACK_OF(X509) *certsStack,
    HcfX509CertificateArray *certs)
{
    if (certsNum <= 0) {
        LOGE("certsNum is less than 0, failed!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    certs->data = (HcfX509Certificate **)CfMalloc(certsNum * sizeof(HcfX509Certificate *), 0);
    if (certs->data == NULL) {
        LOGE("malloc failed");
        sk_X509_pop_free(certsStack, X509_free);
        return CF_ERR_MALLOC;
    }
    CfResult res = CF_SUCCESS;

    certs->count = (uint32_t)certsNum;
    for (int32_t i = 0; i < certsNum; ++i) {
        X509 *cert = sk_X509_value(certsStack, i);
        if (cert == NULL) {
            LOGE("sk X509 value is null, failed!");
            sk_X509_pop_free(certsStack, X509_free);
            CfPrintOpensslError();
            FreeCertificateArray(certs);
            return CF_ERR_CRYPTO_OPERATION;
        }
        HcfX509Certificate *x509Cert = NULL;
        res = X509ToHcfX509Certificate(cert, &x509Cert);
        if (res != CF_SUCCESS) {
            LOGE("convert x509 to HcfX509Certificate failed!");
            sk_X509_pop_free(certsStack, X509_free);
            FreeCertificateArray(certs);
            return res;
        }
        certs->data[i] = x509Cert;
    }
    sk_X509_pop_free(certsStack, X509_free);
    return res;
}

static CfResult GetCmsSignerCert(HcfCmsParserOpensslImpl *impl, CMS_SignerInfo *si, int32_t allCertsNum,
    STACK_OF(X509) *allCertsStack, HcfX509Certificate **cert)
{
    if (impl == NULL || si == NULL || cert == NULL) {
        LOGE("Invalid input parameter.");
        return CF_ERR_PARAMETER_CHECK;
    }
    CfResult res = CF_SUCCESS;
    for (int j = 0; j < allCertsNum; j++) {
        X509 *x509 = sk_X509_value(allCertsStack, j);
        if (x509 == NULL) {
            continue;
        }
        if (CMS_SignerInfo_cert_cmp(si, x509) == 0) {
            HcfX509Certificate *x509Cert = NULL;
            res = X509ToHcfX509Certificate(x509, &x509Cert);
            if (res != CF_SUCCESS) {
                LOGE("convert x509 to HcfX509Certificate failed!");
            } else {
                *cert = x509Cert;
                LOGD("Found signer certificate at index %d", j);
            }
            break;
        }
    }
    return res;
}

static CfResult GetCmsSignerCerts(HcfCmsParserOpensslImpl *impl, int32_t allCertsNum, STACK_OF(X509) *allCertsStack,
    HcfX509CertificateArray *certs)
{
    STACK_OF(CMS_SignerInfo) *signerInfos = CMS_get0_SignerInfos(impl->cms);
    if (signerInfos == NULL) {
        LOGE("CMS_get0_SignerInfos returned NULL");
        CfPrintOpensslError();
        sk_X509_pop_free(allCertsStack, X509_free);
        return CF_ERR_CRYPTO_OPERATION;
    }
    int32_t signerCount = sk_CMS_SignerInfo_num(signerInfos);
    if (signerCount <= 0) {
        LOGE("sk CMS_SignerInfo num : 0, failed!");
        CfPrintOpensslError();
        sk_X509_pop_free(allCertsStack, X509_free);
        return CF_ERR_CRYPTO_OPERATION;
    }

    certs->count = (uint32_t)signerCount;
    certs->data = (HcfX509Certificate **)CfMalloc(certs->count * sizeof(HcfX509Certificate *), 0);
    if (certs->data == NULL) {
        LOGE("malloc failed");
        sk_X509_pop_free(allCertsStack, X509_free);
        return CF_ERR_MALLOC;
    }

    for (uint32_t i = 0; i < certs->count; i++) {
        certs->data[i] = NULL;
    }

    CfResult res = CF_SUCCESS;
    int32_t successCount = 0;
    for (int32_t i = 0; i < signerCount; i++) {
        CMS_SignerInfo *si = sk_CMS_SignerInfo_value(signerInfos, i);
        if (si == NULL) {
            continue;
        }
        CfResult currentRes = GetCmsSignerCert(impl, si, allCertsNum, allCertsStack, &certs->data[i]);
        if (currentRes == CF_SUCCESS) {
            successCount++;
        } else {
            LOGE("Failed to get signer certificate at index %d", i);
        }
    }

    if (successCount == 0) {
        LOGE("All signer certificates failed to match");
        FreeCertificateArray(certs);
        sk_X509_pop_free(allCertsStack, X509_free);
        return CF_SUCCESS;
    }
    sk_X509_pop_free(allCertsStack, X509_free);
    return res;
}

static CfResult GetContentFromBio(CMS_ContentInfo *cms, CfBlob *out)
{
    ASN1_OCTET_STRING **content = CMS_get0_content(cms);
    if (content == NULL || *content == NULL) {
        LOGE("Failed to get content data");
        return CF_ERR_CRYPTO_OPERATION;
    }

    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        LOGE("Failed to create BIO");
        return CF_ERR_CRYPTO_OPERATION;
    }
    
    if (BIO_write(bio, (*content)->data, (*content)->length) <= 0) {
        LOGE("Failed to write content to BIO");
        BIO_free(bio);
        return CF_ERR_CRYPTO_OPERATION;
    }
    
    BUF_MEM *buf = NULL;
    BIO_get_mem_ptr(bio, &buf);
    if (buf == NULL || buf->data == NULL || buf->length == 0) {
        LOGE("No content data available");
        BIO_free(bio);
        return CF_ERR_CRYPTO_OPERATION;
    }
    out->data = (uint8_t *)CfMalloc(buf->length, 0);
    if (out->data == NULL) {
        LOGE("Failed to allocate memory for content data");
        BIO_free(bio);
        return CF_ERR_MALLOC;
    }
    if (memcpy_s(out->data, buf->length, buf->data, buf->length) != EOK) {
        LOGE("Failed to copy content data");
        CfFree(out->data);
        out->data = NULL;
        BIO_free(bio);
        return CF_ERR_COPY;
    }
    out->size = buf->length;
    BIO_free(bio);
    return CF_SUCCESS;
}

static CfResult GetContentDataOpenssl(HcfCmsParserSpi *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCmsParserClass())) {
        LOGE("Class is not match.");
        return CF_ERR_PARAMETER_CHECK;
    }
    HcfCmsParserOpensslImpl *impl = (HcfCmsParserOpensslImpl *)self;
    if (impl->cms == NULL) {
        LOGE("cms is null.");
        return CF_ERR_SHOULD_NOT_CALL;
    }
    HcfCmsContentType contentType;
    CfResult res = GetRawDataType(self, &contentType);
    if (res != CF_SUCCESS) {
        LOGE("Get contentType fail.");
        return res;
    }
    if (contentType != SIGNED_DATA) {
        LOGE("CMS content type is not SIGNED_DATA");
        return CF_ERR_PARAMETER_CHECK;
    }
    res = GetContentFromBio(impl->cms, out);
    if (res != CF_SUCCESS) {
        LOGE("Failed to get content from bio");
        return res;
    }

    return CF_SUCCESS;
}

static CfResult GetCertsOpenssl(HcfCmsParserSpi *self, HcfCmsCertType cmsCertType, HcfX509CertificateArray *certs)
{
    if (self == NULL || certs == NULL) {
        LOGE("Invalid input parameter.");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCmsParserClass())) {
        LOGE("Class is not match.");
        return CF_ERR_PARAMETER_CHECK;
    }
    HcfCmsParserOpensslImpl *impl = (HcfCmsParserOpensslImpl *)self;
    if (impl->cms == NULL) {
        LOGE("cms is null.");
        return CF_ERR_SHOULD_NOT_CALL;
    }
    CfResult res = CmsContentTypeCheck(self, SIGNED_DATA);
    if (res != CF_SUCCESS) {
        LOGE("CMS content type is not SIGNED_DATA");
        return res;
    }

    STACK_OF(X509) *certsStack = CMS_get1_certs(impl->cms);
    if (certsStack == NULL) {
        LOGE("CMS_get1_certs returned NULL");
        CfPrintOpensslError();
        certs = NULL;
        return CF_SUCCESS;
    }
    int32_t certsNum = sk_X509_num(certsStack);
    if (certsNum <= 0) {
        LOGE("sk X509 num : 0, failed!");
        sk_X509_pop_free(certsStack, X509_free);
        certs = NULL;
        return CF_SUCCESS;
    }
    if (cmsCertType == CMS_CERT_ALL_CERTS) {
        return GetCmsAllCerts(impl, certsNum, certsStack, certs);
    } else if (cmsCertType == CMS_CERT_SIGNER_CERTS) {
        return GetCmsSignerCerts(impl, certsNum, certsStack, certs);
    } else {
        LOGE("Invalid cmsCertType.");
        return CF_ERR_PARAMETER_CHECK;
    }
}

static CfResult CmsDecryptGetContentData(bool hasCmsContent, const HcfCmsParserDecryptEnvelopedDataOptions *options,
    BIO **contentBio)
{
    BIO *tmpContentBio = NULL;
    if (hasCmsContent) {
        LOGD("CMS contains attached content data, using content from CMS");
        *contentBio = tmpContentBio;
        return CF_SUCCESS;
    }

    LOGD("CMS is detached, using manually provided content data");
    if (options->encryptedContentData == NULL || options->encryptedContentData->data == NULL ||
            options->encryptedContentData->size == 0) {
        tmpContentBio = BIO_new(BIO_s_null());
        if (tmpContentBio == NULL) {
            LOGE("Failed to create BIO for empty content data");
            CfPrintOpensslError();
            return CF_ERR_CRYPTO_OPERATION;
        }
    } else {
        tmpContentBio = BIO_new_mem_buf(options->encryptedContentData->data, options->encryptedContentData->size);
        if (tmpContentBio == NULL) {
            LOGE("Failed to create BIO for manual content data");
            CfPrintOpensslError();
            return CF_ERR_CRYPTO_OPERATION;
        }
    }

    *contentBio = tmpContentBio;
    return CF_SUCCESS;
}

static CfResult CmsDecryptEnvelopedData(CMS_ContentInfo *cms, BIO *encryptedContentBio, EVP_PKEY *pkey,
    X509 *cert, CfBlob *out)
{
    if (cms == NULL || pkey == NULL || out == NULL) {
        LOGE("Invalid input parameter.");
        return CF_ERR_PARAMETER_CHECK;
    }
    BIO *outBio = BIO_new(BIO_s_mem());
    if (outBio == NULL) {
        LOGE("Failed to create output BIO");
        return CF_ERR_CRYPTO_OPERATION;
    }

    if (CMS_decrypt(cms, pkey, cert, encryptedContentBio, outBio, 0) != CF_OPENSSL_SUCCESS) {
        CfPrintOpensslError();
        LOGE("Failed to decrypt CMS");
        BIO_free(outBio);
        return CF_ERR_CRYPTO_OPERATION;
    }

    BUF_MEM *buf = NULL;
    BIO_get_mem_ptr(outBio, &buf);
    if (buf == NULL || buf->data == NULL || buf->length == 0) {
        LOGE("No decrypted data available");
        BIO_free(outBio);
        return CF_ERR_CRYPTO_OPERATION;
    }

    out->data = (uint8_t *)CfMalloc(buf->length, 0);
    if (out->data == NULL) {
        LOGE("Failed to allocate memory for decrypted data");
        BIO_free(outBio);
        return CF_ERR_MALLOC;
    }

    if (memcpy_s(out->data, buf->length, buf->data, buf->length) != EOK) {
        LOGE("Failed to copy decrypted data");
        CfFree(out->data);
        out->data = NULL;
        BIO_free(outBio);
        return CF_ERR_COPY;
    }
    out->size = buf->length;
    BIO_free(outBio);
    return CF_SUCCESS;
}

static CfResult GetCertAndPkey(CMS_ContentInfo *cms, const HcfCmsParserDecryptEnvelopedDataOptions *options,
    EVP_PKEY **pkey, X509 **cert)
{
    if (cms == NULL || options == NULL || pkey == NULL || cert == NULL) {
        LOGE("Invalid input parameter.");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (options->privateKey == NULL) {
        *pkey = NULL;
    } else {
        CfResult res = GetPrivateKey(options->privateKey, pkey);
        if (res != CF_SUCCESS) {
            LOGE("Failed to get EVP_PKEY from private key info");
            return CF_ERR_CRYPTO_OPERATION;
        }
    }

    if (options->cert != NULL) {
        *cert = GetX509FromHcfX509Certificate((HcfCertificate *)options->cert);
        if (*cert != NULL) {
            X509_up_ref(*cert);
            LOGD("Using certificate from options");
            return CF_SUCCESS;
        }
    }
    *cert = NULL;
    return CF_SUCCESS;
}

static CfResult DecryptEnvelopedCheckParams(HcfCmsParserSpi *self,
    const HcfCmsParserDecryptEnvelopedDataOptions *options)
{
    if ((self == NULL) || (options == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (options->contentDataFormat != BINARY && options->contentDataFormat != TEXT) {
        LOGE("contentDataFormat is not valid, it should be BINARY or TEXT.");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCmsParserClass())) {
        LOGE("Class is not match.");
        return CF_ERR_PARAMETER_CHECK;
    }
    CfResult res = CmsContentTypeCheck(self, ENVELOPED_DATA);
    if (res != CF_SUCCESS) {
        LOGE("CMS content type is not ENVELOPED_DATA");
        return res;
    }
    return res;
}

static CfResult DecryptEnvelopedDataOpenssl(HcfCmsParserSpi *self,
    const HcfCmsParserDecryptEnvelopedDataOptions *options, CfBlob *out)
{
    CfResult res = DecryptEnvelopedCheckParams(self, options);
    if (res != CF_SUCCESS) {
        LOGE("DecryptEnvelopedCheckParams fail.");
        return res;
    }
    HcfCmsParserOpensslImpl *impl = (HcfCmsParserOpensslImpl *)self;
    if (impl->cms == NULL) {
        LOGE("cms is null.");
        return CF_ERR_SHOULD_NOT_CALL;
    }
    bool hasCmsContent = false;
    ASN1_OCTET_STRING **cmsContent = CMS_get0_content(impl->cms);
    if (cmsContent != NULL && *cmsContent != NULL) {
        hasCmsContent = true;
    }
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    res = GetCertAndPkey(impl->cms, options, &pkey, &cert);
    if (res != CF_SUCCESS) {
        EVP_PKEY_free(pkey);
        X509_free(cert);
        LOGE("Failed to get cert and pkey");
        return res;
    }
    BIO *encryptedContentBio = NULL;
    res = CmsDecryptGetContentData(hasCmsContent, options, &encryptedContentBio);
    if (res != CF_SUCCESS) {
        LOGE("Failed to get encrypted content data from bio");
        return res;
    }

    res = CmsDecryptEnvelopedData(impl->cms, encryptedContentBio, pkey, cert, out);
    if (res != CF_SUCCESS) {
        EVP_PKEY_free(pkey);
        X509_free(cert);
        LOGE("Failed to decrypt CMS");
        BIO_free(encryptedContentBio);
        return res;
    }
    EVP_PKEY_free(pkey);
    X509_free(cert);
    BIO_free(encryptedContentBio);
    return CF_SUCCESS;
}

CfResult HcfCmsGeneratorSpiCreate(HcfCmsContentType type, HcfCmsGeneratorSpi **spi)
{
    if (spi == NULL) {
        LOGE("Invalid params, spi is null!");
        return CF_INVALID_PARAMS;
    }
    if (type != SIGNED_DATA && type != ENVELOPED_DATA) {
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
    if (type == SIGNED_DATA) {
        cms = CMS_sign_ex(NULL, NULL, NULL, NULL, CMS_PARTIAL, NULL, NULL);
    } else if (type == ENVELOPED_DATA) {
        cms = CMS_AuthEnvelopedData_create(EVP_aes_256_gcm());
    }
    if (cms == NULL) {
        LOGE("CMS creation fail.");
        CfPrintOpensslError();
        CfFree(cmsGenerator);
        cmsGenerator = NULL;
        return CF_ERR_CRYPTO_OPERATION;
    }
    cmsGenerator->cms = cms;
    cmsGenerator->encryptedContentBio = NULL;  // Initialize to NULL
    cmsGenerator->base.base.getClass = GetCmsGeneratorClass;
    cmsGenerator->base.base.destroy = DestroyCmsGenerator;
    cmsGenerator->base.engineAddSigner = AddSignerOpenssl;
    cmsGenerator->base.engineAddCert = AddCertOpenssl;
    cmsGenerator->base.engineDoFinal = DoFinalOpenssl;
    cmsGenerator->base.engineSetRecipientEncryptionAlgorithm = SetRecipientEncryptionAlgorithmOpenssl;
    cmsGenerator->base.engineAddRecipientInfo = AddRecipientInfoOpenssl;
    cmsGenerator->base.engineGetEncryptedContentData = GetEncryptedContentDataOpenssl;
    *spi = (HcfCmsGeneratorSpi *)cmsGenerator;
    return CF_SUCCESS;
}

CfResult HcfCmsParserSpiCreate(HcfCmsParserSpi **spi)
{
    if (spi == NULL) {
        LOGE("Invalid params, spi is null!");
        return CF_ERR_PARAMETER_CHECK;
    }
    HcfCmsParserOpensslImpl *cmsParser = (HcfCmsParserOpensslImpl *)CfMalloc(sizeof(HcfCmsParserOpensslImpl), 0);
    if (cmsParser == NULL) {
        LOGE("Failed to allocate cmsParser memory!");
        return CF_ERR_MALLOC;
    }
    cmsParser->cms = NULL;
    cmsParser->base.base.getClass = GetCmsParserClass;
    cmsParser->base.base.destroy = DestroyCmsParser;
    cmsParser->base.engineSetRawData = SetRawDataOpenssl;
    cmsParser->base.engineGetContentType = GetContentTypeOpenssl;
    cmsParser->base.engineVerifySignedData = VerifySignedDataOpenssl;
    cmsParser->base.engineGetContentData = GetContentDataOpenssl;
    cmsParser->base.engineGetCerts = GetCertsOpenssl;
    cmsParser->base.engineDecryptEnvelopedData = DecryptEnvelopedDataOpenssl;
    *spi = (HcfCmsParserSpi *)cmsParser;
    return CF_SUCCESS;
}
