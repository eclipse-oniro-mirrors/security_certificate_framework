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
#include "ani_pub_key.h"
#include "cf_type.h"

namespace ANI::CertFramework {
X509CertImpl::X509CertImpl() {}

X509CertImpl::X509CertImpl(HcfX509Certificate *cert) : cert_(cert) {}

X509CertImpl::~X509CertImpl()
{
    CfObjDestroy(this->cert_);
    this->cert_ = nullptr;
}

void X509CertImpl::VerifySync(cryptoFramework::weak::PubKey key)
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return;
    }
    HcfPubKey *obj = reinterpret_cast<HcfPubKey *>(key->GetPubKeyObj());
    CfResult res = this->cert_->base.verify(&(this->cert_->base), obj);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "verify cert failed!");
        return;
    }
}

EncodingBlob X509CertImpl::GetEncodedSync()
{
    EncodingBlob encodingBlob = { { array<uint8_t>(nullptr, 0) }, EncodingFormat(EncodingFormat::key_t::FORMAT_DER) };
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return encodingBlob;
    }
    CfEncodingBlob outBlob = {};
    CfResult ret = this->cert_->base.getEncoded(&(this->cert_->base), &outBlob);
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, "get cert encoded failed!");
        return encodingBlob;
    }
    array<uint8_t> data(move_data_t{}, outBlob.data, outBlob.len);
    encodingBlob.data = data;
    encodingBlob.encodingFormat = static_cast<EncodingFormat::key_t>(outBlob.encodingFormat);
    CfEncodingBlobDataFree(&outBlob);
    return encodingBlob;
}

cryptoFramework::PubKey X509CertImpl::GetPublicKey()
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return make_holder<PubKeyImpl, cryptoFramework::PubKey>();
    }
    HcfPubKey *pubKey = nullptr;
    CfResult ret = this->cert_->base.getPublicKey(&(this->cert_->base), reinterpret_cast<void **>(&pubKey));
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, "get cert public key failed!");
        return make_holder<PubKeyImpl, cryptoFramework::PubKey>();
    }
    return make_holder<PubKeyImpl, cryptoFramework::PubKey>(pubKey);
}

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
        ANI_LOGE_THROW(res, "create x509cert obj failed!");
        return make_holder<X509CertImpl, X509Cert>();
    }
    return make_holder<X509CertImpl, X509Cert>(cert);
}
} // namespace ANI::CertFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateX509CertSync(ANI::CertFramework::CreateX509CertSync);
// NOLINTEND
