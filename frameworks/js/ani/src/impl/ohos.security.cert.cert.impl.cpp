/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ohos.security.cert.cert.proj.hpp"
#include "ohos.security.cert.cert.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

using namespace taihe;
using namespace ohos::security::cert::cert;

namespace {
// To be implemented.

class X509CertImpl {
public:
    X509CertImpl() {
        // Don't forget to implement the constructor.
    }

    void VerifySync(::ohos::security::cryptoFramework::cryptoFramework::weak::PubKey key) {
        TH_THROW(std::runtime_error, "VerifySync not implemented");
    }

    EncodingBlob GetEncodedSync() {
        TH_THROW(std::runtime_error, "GetEncodedSync not implemented");
    }

    ::ohos::security::cryptoFramework::cryptoFramework::PubKey GetPublicKey() {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<PubKeyImpl, ::ohos::security::cryptoFramework::cryptoFramework::PubKey>();
    }

    void CheckValidityWithDate(string_view date) {
        TH_THROW(std::runtime_error, "CheckValidityWithDate not implemented");
    }

    int32_t GetVersion() {
        TH_THROW(std::runtime_error, "GetVersion not implemented");
    }

    int64_t GetSerialNumber() {
        TH_THROW(std::runtime_error, "GetSerialNumber not implemented");
    }

    array<uint8_t> GetCertSerialNumber() {
        TH_THROW(std::runtime_error, "GetCertSerialNumber not implemented");
    }

    DataBlob GetIssuerName() {
        TH_THROW(std::runtime_error, "GetIssuerName not implemented");
    }

    string GetIssuerNameEx(EncodingType encodingType) {
        TH_THROW(std::runtime_error, "GetIssuerNameEx not implemented");
    }

    DataBlob GetSubjectName(optional_view<EncodingType> encodingType) {
        TH_THROW(std::runtime_error, "GetSubjectName not implemented");
    }

    string GetNotBeforeTime() {
        TH_THROW(std::runtime_error, "GetNotBeforeTime not implemented");
    }

    string GetNotAfterTime() {
        TH_THROW(std::runtime_error, "GetNotAfterTime not implemented");
    }

    DataBlob GetSignature() {
        TH_THROW(std::runtime_error, "GetSignature not implemented");
    }

    string GetSignatureAlgName() {
        TH_THROW(std::runtime_error, "GetSignatureAlgName not implemented");
    }

    string GetSignatureAlgOid() {
        TH_THROW(std::runtime_error, "GetSignatureAlgOid not implemented");
    }

    DataBlob GetSignatureAlgParams() {
        TH_THROW(std::runtime_error, "GetSignatureAlgParams not implemented");
    }

    DataBlob GetKeyUsage() {
        TH_THROW(std::runtime_error, "GetKeyUsage not implemented");
    }

    DataArray GetExtKeyUsage() {
        TH_THROW(std::runtime_error, "GetExtKeyUsage not implemented");
    }

    int32_t GetBasicConstraints() {
        TH_THROW(std::runtime_error, "GetBasicConstraints not implemented");
    }

    DataArray GetSubjectAltNames() {
        TH_THROW(std::runtime_error, "GetSubjectAltNames not implemented");
    }

    DataArray GetIssuerAltNames() {
        TH_THROW(std::runtime_error, "GetIssuerAltNames not implemented");
    }

    DataBlob GetItem(CertItemType itemType) {
        TH_THROW(std::runtime_error, "GetItem not implemented");
    }

    bool Match(X509CertMatchParameters const& param) {
        TH_THROW(std::runtime_error, "Match not implemented");
    }

    DataArray GetCRLDistributionPoint() {
        TH_THROW(std::runtime_error, "GetCRLDistributionPoint not implemented");
    }

    X500DistinguishedName GetIssuerX500DistinguishedName() {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
    }

    X500DistinguishedName GetSubjectX500DistinguishedName() {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
    }

    string ToString() {
        TH_THROW(std::runtime_error, "ToString not implemented");
    }

    string ToStringEx(EncodingType encodingType) {
        TH_THROW(std::runtime_error, "ToStringEx not implemented");
    }

    array<uint8_t> HashCode() {
        TH_THROW(std::runtime_error, "HashCode not implemented");
    }

    CertExtension GetExtensionsObject() {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<CertExtensionImpl, CertExtension>();
    }
};

class CertExtensionImpl {
public:
    CertExtensionImpl() {
        // Don't forget to implement the constructor.
    }

    EncodingBlob GetEncoded() {
        TH_THROW(std::runtime_error, "GetEncoded not implemented");
    }

    DataArray GetOidList(ExtensionOidType valueType) {
        TH_THROW(std::runtime_error, "GetOidList not implemented");
    }

    DataBlob GetEntry(ExtensionEntryType valueType, DataBlob const& oid) {
        TH_THROW(std::runtime_error, "GetEntry not implemented");
    }

    int32_t CheckCA() {
        TH_THROW(std::runtime_error, "CheckCA not implemented");
    }

    bool HasUnsupportedCriticalExtension() {
        TH_THROW(std::runtime_error, "HasUnsupportedCriticalExtension not implemented");
    }
};

class X509CRLEntryImpl {
public:
    X509CRLEntryImpl() {
        // Don't forget to implement the constructor.
    }

    EncodingBlob GetEncodedSync() {
        TH_THROW(std::runtime_error, "GetEncodedSync not implemented");
    }

    array<uint8_t> GetSerialNumber() {
        TH_THROW(std::runtime_error, "GetSerialNumber not implemented");
    }

    DataBlob GetCertIssuer() {
        TH_THROW(std::runtime_error, "GetCertIssuer not implemented");
    }

    string GetCertIssuerEx(EncodingType encodingType) {
        TH_THROW(std::runtime_error, "GetCertIssuerEx not implemented");
    }

    string GetRevocationDate() {
        TH_THROW(std::runtime_error, "GetRevocationDate not implemented");
    }

    DataBlob GetExtensions() {
        TH_THROW(std::runtime_error, "GetExtensions not implemented");
    }

    bool HasExtensions() {
        TH_THROW(std::runtime_error, "HasExtensions not implemented");
    }

    X500DistinguishedName GetCertIssuerX500DistinguishedName() {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
    }

    string ToString() {
        TH_THROW(std::runtime_error, "ToString not implemented");
    }

    array<uint8_t> HashCode() {
        TH_THROW(std::runtime_error, "HashCode not implemented");
    }

    CertExtension GetExtensionsObject() {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<CertExtensionImpl, CertExtension>();
    }
};

class X509CRLImpl {
public:
    X509CRLImpl() {
        // Don't forget to implement the constructor.
    }

    bool IsRevoked(weak::X509Cert cert) {
        TH_THROW(std::runtime_error, "IsRevoked not implemented");
    }

    string GetType() {
        TH_THROW(std::runtime_error, "GetType not implemented");
    }

    EncodingBlob GetEncodedSync() {
        TH_THROW(std::runtime_error, "GetEncodedSync not implemented");
    }

    void VerifySync(::ohos::security::cryptoFramework::cryptoFramework::weak::PubKey key) {
        TH_THROW(std::runtime_error, "VerifySync not implemented");
    }

    int32_t GetVersion() {
        TH_THROW(std::runtime_error, "GetVersion not implemented");
    }

    DataBlob GetIssuerName() {
        TH_THROW(std::runtime_error, "GetIssuerName not implemented");
    }

    string GetIssuerNameEx(EncodingType encodingType) {
        TH_THROW(std::runtime_error, "GetIssuerNameEx not implemented");
    }

    string GetLastUpdate() {
        TH_THROW(std::runtime_error, "GetLastUpdate not implemented");
    }

    string GetNextUpdate() {
        TH_THROW(std::runtime_error, "GetNextUpdate not implemented");
    }

    X509CRLEntry GetRevokedCert(array_view<uint8_t> serialNumber) {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<X509CRLEntryImpl, X509CRLEntry>();
    }

    X509CRLEntry GetRevokedCertWithCert(weak::X509Cert cert) {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<X509CRLEntryImpl, X509CRLEntry>();
    }

    array<X509CRLEntry> GetRevokedCertsSync() {
        TH_THROW(std::runtime_error, "GetRevokedCertsSync not implemented");
    }

    DataBlob GetTBSInfo() {
        TH_THROW(std::runtime_error, "GetTBSInfo not implemented");
    }

    DataBlob GetSignature() {
        TH_THROW(std::runtime_error, "GetSignature not implemented");
    }

    string GetSignatureAlgName() {
        TH_THROW(std::runtime_error, "GetSignatureAlgName not implemented");
    }

    string GetSignatureAlgOid() {
        TH_THROW(std::runtime_error, "GetSignatureAlgOid not implemented");
    }

    DataBlob GetSignatureAlgParams() {
        TH_THROW(std::runtime_error, "GetSignatureAlgParams not implemented");
    }

    DataBlob GetExtensions() {
        TH_THROW(std::runtime_error, "GetExtensions not implemented");
    }

    bool Match(X509CRLMatchParameters const& param) {
        TH_THROW(std::runtime_error, "Match not implemented");
    }

    X500DistinguishedName GetIssuerX500DistinguishedName() {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
    }

    string ToString() {
        TH_THROW(std::runtime_error, "ToString not implemented");
    }

    string ToStringEx(EncodingType encodingType) {
        TH_THROW(std::runtime_error, "ToStringEx not implemented");
    }

    array<uint8_t> HashCode() {
        TH_THROW(std::runtime_error, "HashCode not implemented");
    }

    CertExtension GetExtensionsObject() {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<CertExtensionImpl, CertExtension>();
    }
};

class CertChainValidatorImpl {
public:
    CertChainValidatorImpl() {
        // Don't forget to implement the constructor.
    }

    void ValidateSync(CertChainData const& certChain) {
        TH_THROW(std::runtime_error, "ValidateSync not implemented");
    }

    string GetAlgorithm() {
        TH_THROW(std::runtime_error, "GetAlgorithm not implemented");
    }
};

class CertCRLCollectionImpl {
public:
    CertCRLCollectionImpl() {
        // Don't forget to implement the constructor.
    }

    array<X509Cert> SelectCertsSync(X509CertMatchParameters const& param) {
        TH_THROW(std::runtime_error, "SelectCertsSync not implemented");
    }

    array<X509CRL> SelectCRLsSync(X509CRLMatchParameters const& param) {
        TH_THROW(std::runtime_error, "SelectCRLsSync not implemented");
    }
};

class X509CertChainImpl {
public:
    X509CertChainImpl() {
        // Don't forget to implement the constructor.
    }

    array<X509Cert> GetCertList() {
        TH_THROW(std::runtime_error, "GetCertList not implemented");
    }

    CertChainValidationResult ValidateSync(CertChainValidationParameters const& param) {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<CertChainValidationResultImpl, CertChainValidationResult>();
    }

    string ToString() {
        TH_THROW(std::runtime_error, "ToString not implemented");
    }

    array<uint8_t> HashCode() {
        TH_THROW(std::runtime_error, "HashCode not implemented");
    }
};

class X500DistinguishedNameImpl {
public:
    X500DistinguishedNameImpl() {
        // Don't forget to implement the constructor.
    }

    string GetName() {
        TH_THROW(std::runtime_error, "GetName not implemented");
    }

    string GetNameByEnum(EncodingType encodingType) {
        TH_THROW(std::runtime_error, "GetNameByEnum not implemented");
    }

    array<string> GetNameByStr(string_view type) {
        TH_THROW(std::runtime_error, "GetNameByStr not implemented");
    }

    EncodingBlob GetEncoded() {
        TH_THROW(std::runtime_error, "GetEncoded not implemented");
    }
};

class CertChainValidationResultImpl {
public:
    CertChainValidationResultImpl() {
        // Don't forget to implement the constructor.
    }

    X509TrustAnchor GetTrustAnchor() {
        TH_THROW(std::runtime_error, "GetTrustAnchor not implemented");
    }

    X509Cert GetEntityCert() {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<X509CertImpl, X509Cert>();
    }
};

class CertChainBuildResultImpl {
public:
    CertChainBuildResultImpl() {
        // Don't forget to implement the constructor.
    }

    X509CertChain GetCertChain() {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<X509CertChainImpl, X509CertChain>();
    }

    CertChainValidationResult GetValidationResult() {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<CertChainValidationResultImpl, CertChainValidationResult>();
    }
};

class CmsGeneratorImpl {
public:
    CmsGeneratorImpl() {
        // Don't forget to implement the constructor.
    }

    void AddSigner(weak::X509Cert cert, PrivateKeyInfo const& keyInfo, CmsSignerConfig const& config) {
        TH_THROW(std::runtime_error, "AddSigner not implemented");
    }

    void AddCert(weak::X509Cert cert) {
        TH_THROW(std::runtime_error, "AddCert not implemented");
    }

    OptStrUint8Arr DoFinalSync(array_view<uint8_t> data, optional_view<CmsGeneratorOptions> options) {
        TH_THROW(std::runtime_error, "DoFinalSync not implemented");
    }
};

X509Cert CreateX509CertSync(EncodingBlob const& inStream) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<X509CertImpl, X509Cert>();
}

CertExtension CreateCertExtensionSync(EncodingBlob const& inStream) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<CertExtensionImpl, CertExtension>();
}

X509CRL CreateX509CRLSync(EncodingBlob const& inStream) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<X509CRLImpl, X509CRL>();
}

CertChainValidator CreateCertChainValidator(string_view algorithm) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<CertChainValidatorImpl, CertChainValidator>();
}

CertCRLCollection CreateCertCRLCollection(array_view<X509Cert> certs, optional_view<array<X509CRL>> crls) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<CertCRLCollectionImpl, CertCRLCollection>();
}

X509CertChain CreateX509CertChainSync(EncodingBlob const& inStream) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<X509CertChainImpl, X509CertChain>();
}

X509CertChain CreateX509CertChain(array_view<X509Cert> certs) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<X509CertChainImpl, X509CertChain>();
}

CertChainBuildResult BuildX509CertChainSync(CertChainBuildParameters const& param) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<CertChainBuildResultImpl, CertChainBuildResult>();
}

Pkcs12Data ParsePkcs12(array_view<uint8_t> data, Pkcs12ParsingConfig const& config) {
    TH_THROW(std::runtime_error, "ParsePkcs12 not implemented");
}

array<X509TrustAnchor> CreateTrustAnchorsWithKeyStoreSync(array_view<uint8_t> keystore, string_view pwd) {
    TH_THROW(std::runtime_error, "CreateTrustAnchorsWithKeyStoreSync not implemented");
}

X500DistinguishedName CreateX500DistinguishedNameByStrSync(string_view nameStr) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
}

X500DistinguishedName CreateX500DistinguishedNameByDerSync(array_view<uint8_t> nameDer) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
}

CmsGenerator CreateCmsGenerator(CmsContentType contentType) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<CmsGeneratorImpl, CmsGenerator>();
}

OptStrUint8Arr GenerateCsr(PrivateKeyInfo const& keyInfo, CsrGenerationConfig const& config) {
    TH_THROW(std::runtime_error, "GenerateCsr not implemented");
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateX509CertSync(CreateX509CertSync);
TH_EXPORT_CPP_API_CreateCertExtensionSync(CreateCertExtensionSync);
TH_EXPORT_CPP_API_CreateX509CRLSync(CreateX509CRLSync);
TH_EXPORT_CPP_API_CreateCertChainValidator(CreateCertChainValidator);
TH_EXPORT_CPP_API_CreateCertCRLCollection(CreateCertCRLCollection);
TH_EXPORT_CPP_API_CreateX509CertChainSync(CreateX509CertChainSync);
TH_EXPORT_CPP_API_CreateX509CertChain(CreateX509CertChain);
TH_EXPORT_CPP_API_BuildX509CertChainSync(BuildX509CertChainSync);
TH_EXPORT_CPP_API_ParsePkcs12(ParsePkcs12);
TH_EXPORT_CPP_API_CreateTrustAnchorsWithKeyStoreSync(CreateTrustAnchorsWithKeyStoreSync);
TH_EXPORT_CPP_API_CreateX500DistinguishedNameByStrSync(CreateX500DistinguishedNameByStrSync);
TH_EXPORT_CPP_API_CreateX500DistinguishedNameByDerSync(CreateX500DistinguishedNameByDerSync);
TH_EXPORT_CPP_API_CreateCmsGenerator(CreateCmsGenerator);
TH_EXPORT_CPP_API_GenerateCsr(GenerateCsr);
// NOLINTEND
