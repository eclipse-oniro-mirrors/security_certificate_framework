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

#include "ani_x509_cert.h"
#include "cf_type.h"

using namespace taihe;
using namespace ohos::security::cert::cert;
using namespace ANI::CertFramework;

namespace ANI::CertFramework {
X509CertImpl::X509CertImpl() {}

X509CertImpl::X509CertImpl(HcfX509Certificate *cert) : cert_(cert) {}

X509CertImpl::~X509CertImpl()
{
    CfObjDestroy(cert_);
    cert_ = nullptr;
}

void X509CertImpl::VerifySync()
{
    TH_THROW(std::runtime_error, "VerifySync not implemented");
}

EncodingBlob X509CertImpl::GetEncodedSync()
{
    TH_THROW(std::runtime_error, "GetEncodedSync not implemented");
}

void X509CertImpl::GetPublicKey()
{
    TH_THROW(std::runtime_error, "GetPublicKey not implemented");
}
} // namespace ANI::CertFramework

X509Cert CreateX509CertSync(EncodingBlob const& inStream)
{
    CfEncodingBlob encodingBlob = { 
        .data = inStream.data.data(),
        .len = inStream.data.size(),
        .encodingFormat = static_cast<CfEncodingFormat>(inStream.encodingFormat.get_value()),
    };
    HcfX509Certificate *cert = nullptr;
    CfResult res = HcfX509CertificateCreate(&encodingBlob, &cert);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "create cert obj failed!");
        return make_holder<X509CertImpl, X509Cert>();
    }
    return make_holder<X509CertImpl, X509Cert>(cert);
}

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateX509CertSync(CreateX509CertSync);
// NOLINTEND
