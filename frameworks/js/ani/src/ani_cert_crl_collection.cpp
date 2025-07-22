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

#include "ani_cert_crl_collection.h"
#include "ani_parameters.h"

namespace {
using namespace ANI::CertFramework;

CfResult SelectCerts(HcfCertCrlCollection *collection, X509CertMatchParameters const& param,
    HcfX509CertificateArray *hcfCerts)
{
    HcfX509CertMatchParams matchParam = {};
    if (!BuildX509CertMatchParams(param, matchParam)) {
        return CF_INVALID_PARAMS;
    }
    CfResult res = collection->selectCerts(collection, &matchParam, hcfCerts);
    FreeX509CertMatchParams(matchParam);
    return res;
}

CfResult SelectCRLs(HcfCertCrlCollection *collection, X509CRLMatchParameters const& param, HcfX509CrlArray *hcfCrls)
{
    CfBlobArray issuer = {};
    CfBlob updateDateTime = {};
    CfBlob maxCRL = {};
    CfBlob minCRL = {};
    HcfX509CrlMatchParams matchParam = {};
    bool bigintValid = true;
    array<CfBlob> blobs(param.issuer.has_value() ? param.issuer.value().size() : 0);
    if (param.issuer.has_value()) {
        size_t i = 0;
        for (auto const& blob : param.issuer.value()) {
            ArrayU8ToDataBlob(blob, blobs[i++]);
        }
        issuer.data = blobs.data();
        issuer.count = blobs.size();
        matchParam.issuer = &issuer;
    }
    if (param.x509Cert.has_value()) {
        matchParam.x509Cert = reinterpret_cast<HcfCertificate *>(param.x509Cert.value()->GetX509CertObj());
    }
    if (param.updateDateTime.has_value()) {
        StringToDataBlob(param.updateDateTime.value(), updateDateTime);
        matchParam.updateDateTime = &updateDateTime;
    }
    if (param.maxCRL.has_value()) {
        bigintValid &= ArrayU8ToBigInteger(param.maxCRL.value(), maxCRL);
        matchParam.maxCRL = &maxCRL;
    }
    if (param.minCRL.has_value()) {
        bigintValid &= ArrayU8ToBigInteger(param.minCRL.value(), minCRL);
        matchParam.minCRL = &minCRL;
    }
    if (!bigintValid) {
        return CF_INVALID_PARAMS;
    }
    CfResult res = collection->selectCRLs(collection, &matchParam, hcfCrls);
    return res;
}
} // namespace

namespace ANI::CertFramework {
CertCRLCollectionImpl::CertCRLCollectionImpl() {}

CertCRLCollectionImpl::CertCRLCollectionImpl(HcfCertCrlCollection *collection) : collection_(collection) {}

CertCRLCollectionImpl::~CertCRLCollectionImpl()
{
    CfObjDestroy(this->collection_);
    this->collection_ = nullptr;
}

int64_t CertCRLCollectionImpl::GetCertCrlCollectionObj()
{
    return reinterpret_cast<int64_t>(this->collection_);
}

array<X509Cert> CertCRLCollectionImpl::SelectCertsSync(X509CertMatchParameters const& param)
{
    if (this->collection_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "collection obj is nullptr!");
        return {};
    }
    HcfX509CertificateArray hcfCerts = {};
    CfResult res = SelectCerts(this->collection_, param, &hcfCerts);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "select certs failed!");
        return {};
    }
    array<X509Cert> certs(hcfCerts.count, make_holder<X509CertImpl, X509Cert>());
    for (size_t i = 0; i < hcfCerts.count; i++) {
        certs[i] = make_holder<X509CertImpl, X509Cert>(hcfCerts.data[i]);
    }
    return certs;
}

array<X509CRL> CertCRLCollectionImpl::SelectCRLsSync(X509CRLMatchParameters const& param)
{
    if (this->collection_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "collection obj is nullptr!");
        return {};
    }
    HcfX509CrlArray hcfCrls = {};
    CfResult res = SelectCRLs(this->collection_, param, &hcfCrls);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "select crls failed!");
        return {};
    }
    array<X509CRL> crls(hcfCrls.count, make_holder<X509CRLImpl, X509CRL>());
    for (size_t i = 0; i < hcfCrls.count; i++) {
        crls[i] = make_holder<X509CRLImpl, X509CRL>(hcfCrls.data[i]);
    }
    return crls;
}

CertCRLCollection CreateCertCRLCollection(array_view<X509Cert> certs, optional_view<array<X509CRL>> crls)
{
    HcfX509CertificateArray hcfCerts = {};
    HcfX509CrlArray hcfCrls = {};
    array<HcfX509Certificate *> hcfCertsArray(certs.size());
    array<HcfX509Crl *> hcfCrlsArray(crls.has_value() ? crls.value().size() : 0);
    size_t i = 0;
    for (auto const& cert : certs) {
        hcfCertsArray[i++] = reinterpret_cast<HcfX509Certificate *>(cert->GetX509CertObj());
    }
    hcfCerts.data = hcfCertsArray.data();
    hcfCerts.count = hcfCertsArray.size();
    if (crls.has_value()) {
        i = 0;
        for (auto const& crl : crls.value()) {
            hcfCrlsArray[i++] = reinterpret_cast<HcfX509Crl *>(crl->GetX509CRLObj());
        }
        hcfCrls.data = hcfCrlsArray.data();
        hcfCrls.count = hcfCrlsArray.size();
    }
    HcfCertCrlCollection *collection = nullptr;
    CfResult res = HcfCertCrlCollectionCreate(&hcfCerts, &hcfCrls, &collection);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "create cert crl collection obj failed!");
        return make_holder<CertCRLCollectionImpl, CertCRLCollection>();
    }
    return make_holder<CertCRLCollectionImpl, CertCRLCollection>(collection);
}
} // namespace ANI::CertFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateCertCRLCollection(ANI::CertFramework::CreateCertCRLCollection);
// NOLINTEND
