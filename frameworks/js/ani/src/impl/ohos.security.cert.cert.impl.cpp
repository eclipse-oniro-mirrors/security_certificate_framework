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

class X509CertChainImpl {
public:
    X509CertChainImpl() {
        // Don't forget to implement the constructor.
    }

    array<X509Cert> GetCertList() {
        TH_THROW(std::runtime_error, "GetCertList not implemented");
    }

    CertChainValidationResult ValidateSync() {
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

CertChainValidator CreateCertChainValidator(string_view algorithm) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<CertChainValidatorImpl, CertChainValidator>();
}

X509Cert CreateX509CertSync(EncodingBlob const& inStream) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<X509CertImpl, X509Cert>();
}

X509CertChain createX509CertChainSync(EncodingBlob const& inStream) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<X509CertChainImpl, X509CertChain>();
}

X509CertChain CreateX509CertChain(array_view<X509Cert> certs) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<X509CertChainImpl, X509CertChain>();
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateCertChainValidator(CreateCertChainValidator);
TH_EXPORT_CPP_API_CreateX509CertSync(CreateX509CertSync);
TH_EXPORT_CPP_API_createX509CertChainSync(createX509CertChainSync);
TH_EXPORT_CPP_API_CreateX509CertChain(CreateX509CertChain);
// NOLINTEND
