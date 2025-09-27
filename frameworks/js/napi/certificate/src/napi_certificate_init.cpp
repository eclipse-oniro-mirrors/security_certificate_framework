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

#include <string>
#include "cf_log.h"
#include "cf_type.h"
#include "napi_cert_chain_validator.h"
#include "napi_cert_defines.h"
#include "napi_cert_extension.h"
#include "napi_cert_utils.h"
#include "napi_pub_key.h"
#include "napi_x509_cert_chain.h"
#include "napi_x509_certificate.h"
#include "napi_x509_crl.h"
#include "napi_x509_crl_entry.h"
#include "napi_cert_crl_collection.h"
#include "napi_x509_distinguished_name.h"
#include "napi_cert_cms_generator.h"
#include "securec.h"

namespace OHOS {
namespace CertFramework {
static napi_value CreateEncodingFormat(napi_env env)
{
    napi_value encodingFormat = nullptr;
    napi_create_object(env, &encodingFormat);

    CertAddUint32Property(env, encodingFormat, "FORMAT_DER", CF_FORMAT_DER);
    CertAddUint32Property(env, encodingFormat, "FORMAT_PEM", CF_FORMAT_PEM);
    CertAddUint32Property(env, encodingFormat, "FORMAT_PKCS7", CF_FORMAT_PKCS7);

    return encodingFormat;
}

static void DefineEncodingFormatProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("EncodingFormat", CreateEncodingFormat(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

static napi_value CreateCertResultCode(napi_env env)
{
    napi_value resultCode = nullptr;
    napi_create_object(env, &resultCode);

    CertAddUint32Property(env, resultCode, "INVALID_PARAMS", JS_ERR_CERT_INVALID_PARAMS);
    CertAddUint32Property(env, resultCode, "NOT_SUPPORT", JS_ERR_CERT_NOT_SUPPORT);
    CertAddUint32Property(env, resultCode, "ERR_OUT_OF_MEMORY", JS_ERR_CERT_OUT_OF_MEMORY);
    CertAddUint32Property(env, resultCode, "ERR_RUNTIME_ERROR", JS_ERR_CERT_RUNTIME_ERROR);
    CertAddUint32Property(env, resultCode, "ERR_PARAMETER_CHECK_FAILED", JS_ERR_CERT_PARAMETER_CHECK);
    CertAddUint32Property(env, resultCode, "ERR_CRYPTO_OPERATION", JS_ERR_CERT_CRYPTO_OPERATION);
    CertAddUint32Property(env, resultCode, "ERR_CERT_SIGNATURE_FAILURE", JS_ERR_CERT_SIGNATURE_FAILURE);
    CertAddUint32Property(env, resultCode, "ERR_CERT_NOT_YET_VALID", JS_ERR_CERT_NOT_YET_VALID);
    CertAddUint32Property(env, resultCode, "ERR_CERT_HAS_EXPIRED", JS_ERR_CERT_HAS_EXPIRED);
    CertAddUint32Property(env, resultCode, "ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
        JS_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
    CertAddUint32Property(env, resultCode, "ERR_KEYUSAGE_NO_CERTSIGN", JS_ERR_KEYUSAGE_NO_CERTSIGN);
    CertAddUint32Property(env, resultCode, "ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE", JS_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE);
    CertAddUint32Property(env, resultCode, "ERR_MAYBE_WRONG_PASSWORD", JS_ERR_CERT_INVALID_PRIVATE_KEY);
    return resultCode;
}

static void DefineResultCodeProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("CertResult", CreateCertResultCode(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

static napi_value CreateCertItemType(napi_env env)
{
    napi_value certItemType = nullptr;
    napi_create_object(env, &certItemType);

    CertAddUint32Property(env, certItemType, "CERT_ITEM_TYPE_TBS", CF_ITEM_TBS);
    CertAddUint32Property(env, certItemType, "CERT_ITEM_TYPE_PUBLIC_KEY", CF_ITEM_PUBLIC_KEY);
    CertAddUint32Property(env, certItemType, "CERT_ITEM_TYPE_ISSUER_UNIQUE_ID", CF_ITEM_ISSUER_UNIQUE_ID);
    CertAddUint32Property(env, certItemType, "CERT_ITEM_TYPE_SUBJECT_UNIQUE_ID", CF_ITEM_SUBJECT_UNIQUE_ID);
    CertAddUint32Property(env, certItemType, "CERT_ITEM_TYPE_EXTENSIONS", CF_ITEM_EXTENSIONS);

    return certItemType;
}

static void DefineCertItemTypeProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("CertItemType", CreateCertItemType(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

static napi_value CreateExtensionOidType(napi_env env)
{
    napi_value extensionOidType = nullptr;
    napi_create_object(env, &extensionOidType);

    CertAddUint32Property(env, extensionOidType, "EXTENSION_OID_TYPE_ALL", CF_EXT_TYPE_ALL_OIDS);
    CertAddUint32Property(env, extensionOidType, "EXTENSION_OID_TYPE_CRITICAL", CF_EXT_TYPE_CRITICAL_OIDS);
    CertAddUint32Property(env, extensionOidType, "EXTENSION_OID_TYPE_UNCRITICAL", CF_EXT_TYPE_UNCRITICAL_OIDS);

    return extensionOidType;
}

static void DefineExtensionOidTypeProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("ExtensionOidType", CreateExtensionOidType(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

static napi_value CreateExtensionEntryType(napi_env env)
{
    napi_value extensionEntryType  = nullptr;
    napi_create_object(env, &extensionEntryType);

    CertAddUint32Property(env, extensionEntryType, "EXTENSION_ENTRY_TYPE_ENTRY", CF_EXT_ENTRY_TYPE_ENTRY);
    CertAddUint32Property(env, extensionEntryType, "EXTENSION_ENTRY_TYPE_ENTRY_CRITICAL",
        CF_EXT_ENTRY_TYPE_ENTRY_CRITICAL);
    CertAddUint32Property(env, extensionEntryType, "EXTENSION_ENTRY_TYPE_ENTRY_VALUE", CF_EXT_ENTRY_TYPE_ENTRY_VALUE);

    return extensionEntryType;
}

static void DefineExtensionEntryTypeProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("ExtensionEntryType", CreateExtensionEntryType(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

static napi_value CreateGeneralNameTypeType(napi_env env)
{
    napi_value generalNameType = nullptr;
    napi_create_object(env, &generalNameType);

    CertAddUint32Property(env, generalNameType, "GENERAL_NAME_TYPE_OTHER_NAME", CF_GENERAL_NAME_TYPE_OTHER_NAME);
    CertAddUint32Property(env, generalNameType, "GENERAL_NAME_TYPE_RFC822_NAME", CF_GENERAL_NAME_TYPE_RFC822_NAME);
    CertAddUint32Property(env, generalNameType, "GENERAL_NAME_TYPE_DNS_NAME", CF_GENERAL_NAME_TYPE_DNS_NAME);
    CertAddUint32Property(env, generalNameType, "GENERAL_NAME_TYPE_X400_ADDRESS", CF_GENERAL_NAME_TYPE_X400_ADDRESS);
    CertAddUint32Property(
        env, generalNameType, "GENERAL_NAME_TYPE_DIRECTORY_NAME", CF_GENERAL_NAME_TYPE_DIRECTORY_NAME);
    CertAddUint32Property(
        env, generalNameType, "GENERAL_NAME_TYPE_EDI_PARTY_NAME", CF_GENERAL_NAME_TYPE_EDI_PARTY_NAME);
    CertAddUint32Property(
        env, generalNameType, "GENERAL_NAME_TYPE_UNIFORM_RESOURCE_ID", CF_GENERAL_NAME_TYPE_UNIFORM_RESOURCE_ID);
    CertAddUint32Property(env, generalNameType, "GENERAL_NAME_TYPE_IP_ADDRESS", CF_GENERAL_NAME_TYPE_IP_ADDRESS);
    CertAddUint32Property(env, generalNameType, "GENERAL_NAME_TYPE_REGISTERED_ID", CF_GENERAL_NAME_TYPE_REGISTERED_ID);

    return generalNameType;
}

static void DefineGeneralNameTypeProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("GeneralNameType", CreateGeneralNameTypeType(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

static napi_value CreateRevocationCheckOptions(napi_env env)
{
    napi_value revocationCheckOptions = nullptr;
    napi_create_object(env, &revocationCheckOptions);

    CertAddUint32Property(
        env, revocationCheckOptions, "REVOCATION_CHECK_OPTION_PREFER_OCSP", CF_REVOCATION_CHECK_OPTION_PREFER_OCSP);
    CertAddUint32Property(env, revocationCheckOptions, "REVOCATION_CHECK_OPTION_ACCESS_NETWORK",
        CF_REVOCATION_CHECK_OPTION_ACCESS_NETWORK);
    CertAddUint32Property(env, revocationCheckOptions, "REVOCATION_CHECK_OPTION_FALLBACK_NO_PREFER",
        CF_REVOCATION_CHECK_OPTION_FALLBACK_NO_PREFER);
    CertAddUint32Property(env, revocationCheckOptions, "REVOCATION_CHECK_OPTION_FALLBACK_LOCAL",
        CF_REVOCATION_CHECK_OPTION_FALLBACK_LOCAL);
    CertAddUint32Property(env, revocationCheckOptions, "REVOCATION_CHECK_OPTION_LOCAL_CRL_ONLY_CHECK_END_ENTITY_CERT",
        CF_REVOCATION_CHECK_OPTION_LOCAL_CRL_ONLY_CHECK_END_ENTITY_CERT);

    return revocationCheckOptions;
}

static napi_value CreateValidationPolicyType(napi_env env)
{
    napi_value ValidationPolicyType = nullptr;
    napi_create_object(env, &ValidationPolicyType);

    CertAddUint32Property(env, ValidationPolicyType, "VALIDATION_POLICY_TYPE_X509", CF_VALIDATION_POLICY_TYPE_X509);
    CertAddUint32Property(env, ValidationPolicyType, "VALIDATION_POLICY_TYPE_SSL", CF_VALIDATION_POLICY_TYPE_SSL);

    return ValidationPolicyType;
}

static napi_value CreateValidationKeyUsageType(napi_env env)
{
    napi_value ValidationKeyUsageType = nullptr;
    napi_create_object(env, &ValidationKeyUsageType);

    CertAddUint32Property(env, ValidationKeyUsageType, "KEYUSAGE_DIGITAL_SIGNATURE", CF_KEYUSAGE_DIGITAL_SIGNATURE);
    CertAddUint32Property(env, ValidationKeyUsageType, "KEYUSAGE_NON_REPUDIATION", CF_KEYUSAGE_NON_REPUDIATION);
    CertAddUint32Property(env, ValidationKeyUsageType, "KEYUSAGE_KEY_ENCIPHERMENT", CF_KEYUSAGE_KEY_ENCIPHERMENT);
    CertAddUint32Property(env, ValidationKeyUsageType, "KEYUSAGE_DATA_ENCIPHERMENT", CF_KEYUSAGE_DATA_ENCIPHERMENT);
    CertAddUint32Property(env, ValidationKeyUsageType, "KEYUSAGE_KEY_AGREEMENT", CF_KEYUSAGE_KEY_AGREEMENT);
    CertAddUint32Property(env, ValidationKeyUsageType, "KEYUSAGE_KEY_CERT_SIGN", CF_KEYUSAGE_KEY_CERT_SIGN);
    CertAddUint32Property(env, ValidationKeyUsageType, "KEYUSAGE_CRL_SIGN", CF_KEYUSAGE_CRL_SIGN);
    CertAddUint32Property(env, ValidationKeyUsageType, "KEYUSAGE_ENCIPHER_ONLY", CF_KEYUSAGE_ENCIPHER_ONLY);
    CertAddUint32Property(env, ValidationKeyUsageType, "KEYUSAGE_DECIPHER_ONLY", CF_KEYUSAGE_DECIPHER_ONLY);

    return ValidationKeyUsageType;
}

static void DefineOcspCheckOptionTypeProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("RevocationCheckOptions", CreateRevocationCheckOptions(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

static void DefineValidationPolicyTypeProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("ValidationPolicyType", CreateValidationPolicyType(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

static void DefineValidationKeyUsageTypeProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("KeyUsageType", CreateValidationKeyUsageType(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

static napi_value CreateEncodingType(napi_env env)
{
    napi_value encodingType = nullptr;
    napi_create_object(env, &encodingType);

    CertAddUint32Property(env, encodingType, "ENCODING_UTF8", CF_ENCODING_UTF8);

    return encodingType;
}

static void DefineEncodingTypeProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("EncodingType", CreateEncodingType(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

static napi_value CreateEncodingBaseFormat(napi_env env)
{
    napi_value encodingBaseFormat = nullptr;
    napi_create_object(env, &encodingBaseFormat);

    CertAddUint32Property(env, encodingBaseFormat, "PEM", PEM);
    CertAddUint32Property(env, encodingBaseFormat, "DER", DER);

    return encodingBaseFormat;
}

static napi_value CreatePbesEncAlg(napi_env env)
{
    napi_value pbesEncryptionAlgorithm = nullptr;
    napi_create_object(env, &pbesEncryptionAlgorithm);

    CertAddUint32Property(env, pbesEncryptionAlgorithm, "AES_128_CBC", AES_128_CBC);
    CertAddUint32Property(env, pbesEncryptionAlgorithm, "AES_192_CBC", AES_192_CBC);
    CertAddUint32Property(env, pbesEncryptionAlgorithm, "AES_256_CBC", AES_256_CBC);

    return pbesEncryptionAlgorithm;
}

static napi_value CreatePkcs12MacDigestAlg(napi_env env)
{
    napi_value pkcs12MacDigestAlgorithm = nullptr;
    napi_create_object(env, &pkcs12MacDigestAlgorithm);

    CertAddUint32Property(env, pkcs12MacDigestAlgorithm, "SHA256", CF_MAC_SHA256);
    CertAddUint32Property(env, pkcs12MacDigestAlgorithm, "SHA384", CF_MAC_SHA384);
    CertAddUint32Property(env, pkcs12MacDigestAlgorithm, "SHA512", CF_MAC_SHA512);

    return pkcs12MacDigestAlgorithm;
}

static void DefinePkcs12TypeProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("EncodingBaseFormat", CreateEncodingBaseFormat(env)),
        DECLARE_NAPI_PROPERTY("PbesEncryptionAlgorithm", CreatePbesEncAlg(env)),
        DECLARE_NAPI_PROPERTY("Pkcs12MacDigestAlgorithm", CreatePkcs12MacDigestAlg(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

static napi_value CreateCmsContentType(napi_env env)
{
    napi_value cmsContentType = nullptr;
    napi_create_object(env, &cmsContentType);

    CertAddUint32Property(env, cmsContentType, "SIGNED_DATA", SIGNED_DATA);
    CertAddUint32Property(env, cmsContentType, "ENVELOPED_DATA", ENVELOPED_DATA);
    return cmsContentType;
}

static napi_value CreateCmsContentDataFormat(napi_env env)
{
    napi_value cmsContentDataFormat = nullptr;
    napi_create_object(env, &cmsContentDataFormat);

    CertAddUint32Property(env, cmsContentDataFormat, "BINARY", BINARY);
    CertAddUint32Property(env, cmsContentDataFormat, "TEXT", TEXT);

    return cmsContentDataFormat;
}

static napi_value CreateCmsFormat(napi_env env)
{
    napi_value cmsFormat = nullptr;
    napi_create_object(env, &cmsFormat);

    CertAddUint32Property(env, cmsFormat, "PEM", CMS_PEM);
    CertAddUint32Property(env, cmsFormat, "DER", CMS_DER);

    return cmsFormat;
}

static napi_value CreateCmsRecEncAlg(napi_env env)
{
    napi_value cmsRecEncAlg = nullptr;
    napi_create_object(env, &cmsRecEncAlg);

    CertAddUint32Property(env, cmsRecEncAlg, "AES_128_CBC", CMS_AES_128_CBC);
    CertAddUint32Property(env, cmsRecEncAlg, "AES_192_CBC", CMS_AES_192_CBC);
    CertAddUint32Property(env, cmsRecEncAlg, "AES_256_CBC", CMS_AES_256_CBC);
    CertAddUint32Property(env, cmsRecEncAlg, "AES_128_GCM", CMS_AES_128_GCM);
    CertAddUint32Property(env, cmsRecEncAlg, "AES_192_GCM", CMS_AES_192_GCM);
    CertAddUint32Property(env, cmsRecEncAlg, "AES_256_GCM", CMS_AES_256_GCM);
    return cmsRecEncAlg;
}

static napi_value CreateCmsKeyAgreeRecDigAlg(napi_env env)
{
    napi_value cmsKeyAgreeRecDigAlg = nullptr;
    napi_create_object(env, &cmsKeyAgreeRecDigAlg);

    CertAddUint32Property(env, cmsKeyAgreeRecDigAlg, "SHA256", CMS_SHA256);
    CertAddUint32Property(env, cmsKeyAgreeRecDigAlg, "SHA384", CMS_SHA384);
    CertAddUint32Property(env, cmsKeyAgreeRecDigAlg, "SHA512", CMS_SHA512);
    return cmsKeyAgreeRecDigAlg;
}

static napi_value CreateCmsRsaSignaturePadding(napi_env env)
{
    napi_value cmsRsaSignaturePadding = nullptr;
    napi_create_object(env, &cmsRsaSignaturePadding);

    CertAddUint32Property(env, cmsRsaSignaturePadding, "PKCS1_PADDING", PKCS1_PADDING);
    CertAddUint32Property(env, cmsRsaSignaturePadding, "PKCS1_PSS_PADDING", PKCS1_PSS_PADDING);
    return cmsRsaSignaturePadding;
}

static void DefineCertCmsGeneratorProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("CmsContentType", CreateCmsContentType(env)),
        DECLARE_NAPI_PROPERTY("CmsContentDataFormat", CreateCmsContentDataFormat(env)),
        DECLARE_NAPI_PROPERTY("CmsFormat", CreateCmsFormat(env)),
        DECLARE_NAPI_PROPERTY("CmsRecipientEncryptionAlgorithm", CreateCmsRecEncAlg(env)),
        DECLARE_NAPI_PROPERTY("CmsKeyAgreeRecipientDigestAlgorithm", CreateCmsKeyAgreeRecDigAlg(env)),
        DECLARE_NAPI_PROPERTY("CmsRsaSignaturePadding", CreateCmsRsaSignaturePadding(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

/***********************************************
 * Module export and register
 ***********************************************/
static napi_value CertModuleExport(napi_env env, napi_value exports)
{
    DefineEncodingFormatProperties(env, exports);
    DefineResultCodeProperties(env, exports);
    DefineCertItemTypeProperties(env, exports);
    DefineExtensionOidTypeProperties(env, exports);
    DefineExtensionEntryTypeProperties(env, exports);
    DefineGeneralNameTypeProperties(env, exports);
    DefineOcspCheckOptionTypeProperties(env, exports);
    DefineValidationPolicyTypeProperties(env, exports);
    DefineValidationKeyUsageTypeProperties(env, exports);
    DefineEncodingTypeProperties(env, exports);
    DefinePkcs12TypeProperties(env, exports);
    DefineCertCmsGeneratorProperties(env, exports);

    NapiKey::DefineHcfKeyJSClass(env);
    NapiPubKey::DefinePubKeyJSClass(env);
    NapiCertChainValidator::DefineCertChainValidatorJSClass(env, exports);
    NapiX509Certificate::DefineX509CertJSClass(env, exports);
    NapiX509CrlEntry::DefineX509CrlEntryJSClass(env, std::string("X509CrlEntry"));
    NapiX509CrlEntry::DefineX509CrlEntryJSClass(env, std::string("X509CRLEntry"));
    NapiX509Crl::DefineX509CrlJSClass(env, exports, std::string("X509Crl"));
    NapiX509Crl::DefineX509CrlJSClass(env, exports, std::string("X509CRL"));
    NapiX509DistinguishedName::DefineX509DistinguishedNameJSClass(env, exports);
    NapiCertExtension::DefineCertExtensionJsClass(env, exports);
    NapiX509CertChain::DefineX509CertChainJsClass(env, exports);
    NapiX509CertChainBulidResult::DefineX509CertChainBuildResultJsClass(env, exports);
    NapiCertCRLCollection::DefineCertCRLCollectionJSClass(env, exports);
    NapiCertCmsGenerator::DefineCertCmsGeneratorJSClass(env, exports);
    return exports;
}

extern "C" __attribute__((constructor)) void RegisterCertModule(void)
{
    static napi_module cryptoFrameworkCertModule = {
        .nm_version = 1,
        .nm_flags = 0,
        .nm_filename = nullptr,
        .nm_register_func = CertModuleExport,
        .nm_modname = "security.cert",
        .nm_priv = nullptr,
        .reserved = { nullptr },
    };
    napi_module_register(&cryptoFrameworkCertModule);
}
}  // namespace CertFramework
}  // namespace OHOS
