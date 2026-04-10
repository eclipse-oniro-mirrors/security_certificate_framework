/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "ani_parameters.h"
#include "securec.h"
#include "cert_chain_validator.h"

namespace {
using namespace ANI::CertFramework;

constexpr uint32_t MAX_LEN_OF_ARRAY = 1024;

bool BuildKeyUsage(X509CertMatchParameters const& param, HcfX509CertMatchParams &hcfParam)
{
    if (param.keyUsage.has_value()) {
        uint32_t count = param.keyUsage.value().size();
        if (count == 0) {
            return false;
        }
        hcfParam.keyUsage = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
        if (hcfParam.keyUsage == nullptr) {
            return false;
        }
        hcfParam.keyUsage->data = static_cast<uint8_t *>(CfMalloc(count * sizeof(uint8_t), 0));
        if (hcfParam.keyUsage->data == nullptr) {
            return false;
        }
        hcfParam.keyUsage->size = count;
        for (uint32_t i = 0; i < hcfParam.keyUsage->size; ++i) {
            hcfParam.keyUsage->data[i] = (param.keyUsage.value()[i] ? 1 : 0);
        }
    }
    return true;
}

bool BuildSubjectAlternativeNames(X509CertMatchParameters const& param, HcfX509CertMatchParams &hcfParam)
{
    if (param.subjectAlternativeNames.has_value()) {
        hcfParam.subjectAlternativeNames = static_cast<SubAltNameArray *>
            (CfMalloc(sizeof(SubAltNameArray), 0));
        if (hcfParam.subjectAlternativeNames == nullptr) {
            return false;
        }
        uint32_t count = param.subjectAlternativeNames.value().size();
        hcfParam.subjectAlternativeNames->data = static_cast<SubjectAlternaiveNameData *>
            (CfMalloc(count * sizeof(SubjectAlternaiveNameData), 0));
        if (hcfParam.subjectAlternativeNames->data == nullptr) {
            return false;
        }
        hcfParam.subjectAlternativeNames->count = count;
        for (uint32_t i = 0; i < hcfParam.subjectAlternativeNames->count; ++i) {
            hcfParam.subjectAlternativeNames->data[i].type =
                static_cast<CfGeneralNameType>(param.subjectAlternativeNames.value()[i].type.get_value());
            if (param.subjectAlternativeNames.value()[i].name.has_value()) {
                ArrayU8ToDataBlob(param.subjectAlternativeNames.value()[i].name.value(),
                    hcfParam.subjectAlternativeNames->data[i].name);
            }
        }
    }
    return true;
}

bool BuildExtendedKeyUsage(X509CertMatchParameters const& param, HcfX509CertMatchParams &hcfParam)
{
    if (param.extendedKeyUsage.has_value()) {
        hcfParam.extendedKeyUsage = static_cast<CfArray *>(CfMalloc(sizeof(CfArray), 0));
        if (hcfParam.extendedKeyUsage == nullptr) {
            return false;
        }
        uint32_t count = param.extendedKeyUsage.value().size();
        hcfParam.extendedKeyUsage->data = static_cast<CfBlob *>(CfMalloc(count * sizeof(CfBlob), 0));
        if (hcfParam.extendedKeyUsage->data == nullptr) {
            return false;
        }
        hcfParam.extendedKeyUsage->count = count;
        for (uint32_t i = 0; i < hcfParam.extendedKeyUsage->count; ++i) {
            if (param.extendedKeyUsage.value()[i].empty()) {
                return false;
            }
            StringToDataBlob(param.extendedKeyUsage.value()[i], hcfParam.extendedKeyUsage->data[i]);
        }
    }
    return true;
}

bool BuildCertPolicy(X509CertMatchParameters const& param, HcfX509CertMatchParams &hcfParam)
{
    if (param.certPolicy.has_value()) {
        hcfParam.certPolicy = static_cast<CfArray *>(CfMalloc(sizeof(CfArray), 0));
        if (hcfParam.certPolicy == nullptr) {
            return false;
        }
        uint32_t count = param.certPolicy.value().size();
        hcfParam.certPolicy->data = static_cast<CfBlob *>(CfMalloc(count * sizeof(CfBlob), 0));
        if (hcfParam.certPolicy->data == nullptr) {
            return false;
        }
        hcfParam.certPolicy->count = count;
        for (uint32_t i = 0; i < hcfParam.certPolicy->count; ++i) {
            if (param.certPolicy.value()[i].empty()) {
                return false;
            }
            StringToDataBlob(param.certPolicy.value()[i], hcfParam.certPolicy->data[i]);
        }
    }
    return true;
}

bool BuildPrivateKey(X509CertMatchParameters const& param, HcfX509CertMatchParams &hcfParam)
{
    if (!param.privateKey.has_value()) {
        return true;
    }
    hcfParam.privateKey = static_cast<CfEncodingBlob *>(CfMalloc(sizeof(CfEncodingBlob), 0));
    if (hcfParam.privateKey == nullptr) {
        return false;
    }
    CfBlob keyBlob = {};
    if (param.privateKey.value().get_tag() == OptStrUint8Arr::tag_t::STRING) {
        StringToDataBlob(param.privateKey.value().get_STRING_ref(), keyBlob);
        hcfParam.privateKey->encodingFormat = CF_FORMAT_PEM;
    } else {
        ArrayU8ToDataBlob(param.privateKey.value().get_UINT8ARRAY_ref(), keyBlob);
        hcfParam.privateKey->encodingFormat = CF_FORMAT_DER;
    }
    if (keyBlob.size == 0 || keyBlob.data == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "private key is empty");
        CF_FREE_PTR(hcfParam.privateKey);
        return false;
    }
    hcfParam.privateKey->data = static_cast<uint8_t *>(CfMalloc(keyBlob.size, 0));
    if (hcfParam.privateKey->data == nullptr) {
        CF_FREE_PTR(hcfParam.privateKey);
        return false;
    }
    if (memcpy_s(hcfParam.privateKey->data, keyBlob.size, keyBlob.data, keyBlob.size) != EOK) {
        CF_FREE_PTR(hcfParam.privateKey->data);
        CF_FREE_PTR(hcfParam.privateKey);
        return false;
    }
    hcfParam.privateKey->len = keyBlob.size;
    return true;
}

bool BuildPublicKey(X509CertMatchParameters const& param, HcfX509CertMatchParams &hcfParam)
{
    if (!param.publicKey.has_value()) {
        return true;
    }
    hcfParam.publicKey = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (hcfParam.publicKey == nullptr) {
        return false;
    }
    ArrayU8ToDataBlob(param.publicKey.value().data, *hcfParam.publicKey);
    return true;
}

void FreeX509TrustAnchor(HcfX509TrustAnchor *&trustAnchor, bool freeCert = true)
{
    if (trustAnchor == nullptr) {
        return;
    }
    if (freeCert) {
        CfObjDestroy(trustAnchor->CACert);
    }
    trustAnchor->CACert = nullptr;
    CfBlobFree(&trustAnchor->CAPubKey);
    CfBlobFree(&trustAnchor->CASubject);
    CfBlobFree(&trustAnchor->nameConstraints);
    CF_FREE_PTR(trustAnchor);
}

void FreeHcfRevocationCheckParam(HcfRevocationCheckParam *param)
{
    if (param == nullptr) {
        return;
    }
    if (param->ocspRequestExtension != nullptr) {
        CF_FREE_PTR(param->ocspRequestExtension->data);
        CF_FREE_PTR(param->ocspRequestExtension);
    }
    CfBlobFree(&param->ocspResponderURI);
    CfBlobFree(&param->ocspResponses);
    CfBlobFree(&param->crlDownloadURI);
    if (param->options != nullptr) {
        if (param->options->data != nullptr) {
            CF_FREE_PTR(param->options->data);
        }
        CF_FREE_PTR(param->options);
    }
    CfBlobFree(&param->ocspDigest);
    CF_FREE_PTR(param);
}

bool BuildTrustAnchor(X509TrustAnchor const& param, HcfX509TrustAnchor **anchor)
{
    HcfX509TrustAnchor *tempAnchor = static_cast<HcfX509TrustAnchor *>(CfMalloc(sizeof(HcfX509TrustAnchor), 0));
    if (tempAnchor == nullptr) {
        return false;
    }
    if (param.CACert.has_value()) {
        tempAnchor->CACert = reinterpret_cast<HcfX509Certificate *>(param.CACert.value()->GetX509CertObj());
    }
    if (param.CAPubKey.has_value()) {
        if (!ArrayU8CopyToBlob(param.CAPubKey.value(), &tempAnchor->CAPubKey)) {
            return false;
        }
    }
    if (param.CASubject.has_value()) {
        if (!ArrayU8CopyToBlob(param.CASubject.value(), &tempAnchor->CASubject)) {
            return false;
        }
    }
    if (param.nameConstraints.has_value()) {
        if (!ArrayU8CopyToBlob(param.nameConstraints.value(), &tempAnchor->nameConstraints)) {
            return false;
        }
    }
    *anchor = tempAnchor;
    return true;
}

bool BuildTrustAnchors(array<X509TrustAnchor> const& param, HcfX509CertChainValidateParams &validateParam,
    bool isTrustSystemCa)
{
    uint32_t count = param.size();
    if (count == 0 || count > MAX_LEN_OF_ARRAY) {
        return isTrustSystemCa;
    }
    HcfX509TrustAnchorArray *tempTrustAnchors =
        static_cast<HcfX509TrustAnchorArray *>(CfMalloc(sizeof(HcfX509TrustAnchorArray), 0));
    if (tempTrustAnchors == nullptr) {
        return false;
    }
    tempTrustAnchors->count = count;
    tempTrustAnchors->data =
        static_cast<HcfX509TrustAnchor **>(CfMalloc(sizeof(HcfX509TrustAnchor *) * count, 0));
    if (tempTrustAnchors->data == nullptr) {
        CF_FREE_PTR(tempTrustAnchors);
        return false;
    }
    for (size_t i = 0; i < count; ++i) {
        if (!BuildTrustAnchor(param[i], &tempTrustAnchors->data[i])) {
            FreeTrustAnchorArray(tempTrustAnchors);
            return false;
        }
    }
    validateParam.trustAnchors = tempTrustAnchors;
    return true;
}

bool BuildCertCRLs(optional<array<CertCRLCollection>> const& param, HcfX509CertChainValidateParams &validateParam)
{
    if (!param.has_value()) {
        return true;
    }
    uint32_t length = param.value().size();
    HcfCertCRLCollectionArray *tempCertCRLs =
        static_cast<HcfCertCRLCollectionArray *>(CfMalloc(sizeof(HcfCertCRLCollectionArray), 0));
    if (tempCertCRLs == nullptr) {
        return false;
    }
    tempCertCRLs->data =
        static_cast<HcfCertCrlCollection **>(CfMalloc(sizeof(HcfCertCrlCollection *) * length, 0));
    if (tempCertCRLs->data == nullptr) {
        CF_FREE_PTR(tempCertCRLs);
        return false;
    }
    for (size_t i = 0; i < length; i++) {
        tempCertCRLs->data[i] = reinterpret_cast<HcfCertCrlCollection *>(param.value()[i]->GetCertCrlCollectionObj());
    }
    tempCertCRLs->count = length;
    validateParam.certCRLCollections = tempCertCRLs;
    return true;
}

bool SetStringRevocationCheckParam(optional<RevocationCheckParameter> const& param,
    HcfRevocationCheckParam **revocationCheckParam)
{
    if (!param.has_value()) {
        return true;
    }
    if (param->ocspResponderURI.has_value()) {
        if (!StringCopyToBlob(param->ocspResponderURI.value(), &(*revocationCheckParam)->ocspResponderURI)) {
            return false;
        }
    }
    if (param->crlDownloadURI.has_value()) {
        if (!StringCopyToBlob(param->crlDownloadURI.value(), &(*revocationCheckParam)->crlDownloadURI)) {
            return false;
        }
    }
    string ocspDigest = param->ocspDigest.has_value() ? param->ocspDigest.value() : "SHA256";
    if (!StringCopyToBlob(ocspDigest, &(*revocationCheckParam)->ocspDigest)) {
        return false;
    }
    return true;
}

bool SetOcspRequestExtension(optional<array<array<uint8_t>>> const& param, CfBlobArray **ocspRequestExtension)
{
    if (!param.has_value()) {
        return true;
    }
    CfBlobArray *tempOcspRequestExtension = static_cast<CfBlobArray *>(CfMalloc(sizeof(CfBlobArray), 0));
    if (tempOcspRequestExtension == nullptr) {
        return false;
    }
    tempOcspRequestExtension->data = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob) * param.value().size(), 0));
    if (tempOcspRequestExtension->data == nullptr) {
        CF_FREE_PTR(tempOcspRequestExtension);
        return false;
    }
    for (size_t i = 0; i < param.value().size(); i++) {
        ArrayU8ToDataBlob(param.value()[i], tempOcspRequestExtension->data[i]);
    }
    tempOcspRequestExtension->count = param.value().size();
    *ocspRequestExtension = tempOcspRequestExtension;
    return true;
}

bool SetOptions(optional<array<RevocationCheckOptions>> const& param, HcfRevChkOpArray **options)
{
    if (!param.has_value()) {
        return true;
    }
    uint32_t count = param.value().size();
    if (count == 0) {
        return false;
    }
    HcfRevChkOpArray *tempOptions = static_cast<HcfRevChkOpArray *>(CfMalloc(sizeof(HcfRevChkOpArray), 0));
    if (tempOptions == nullptr) {
        return false;
    }
    tempOptions->data = static_cast<HcfRevChkOption *>(CfMalloc(sizeof(HcfRevChkOption) * count, 0));
    if (tempOptions->data == nullptr) {
        CF_FREE_PTR(tempOptions);
        return false;
    }
    for (uint32_t i = 0; i < count; i++) {
        tempOptions->data[i] = static_cast<HcfRevChkOption>(param.value()[i].get_value());
    }
    tempOptions->count = count;
    *options = tempOptions;
    return true;
}

bool BuildRevocationCheckParam(optional<RevocationCheckParameter> const& param,
    HcfX509CertChainValidateParams &validateParam)
{
    if (!param.has_value()) {
        return true;
    }
    HcfRevocationCheckParam *tempRevocationCheckParam =
        static_cast<HcfRevocationCheckParam *>(CfMalloc(sizeof(HcfRevocationCheckParam), 0));
    if (tempRevocationCheckParam == nullptr) {
        return false;
    }
    if (!SetOcspRequestExtension(param->ocspRequestExtension, &tempRevocationCheckParam->ocspRequestExtension)) {
        return false;
    }
    if (param->ocspResponses.has_value()) {
        if (param->ocspResponses.value().empty()) {
            return false;
        }
        if (!ArrayU8CopyToBlob(param->ocspResponses.value(), &tempRevocationCheckParam->ocspResponses)) {
            return false;
        }
    }
    if (!SetOptions(param->options, &tempRevocationCheckParam->options)) {
        return false;
    }
    if (!SetStringRevocationCheckParam(param, &tempRevocationCheckParam)) {
        return false;
    }
    tempRevocationCheckParam->ocspResponderCert = param->ocspResponderCert.has_value() ?
        reinterpret_cast<HcfX509Certificate *>(param->ocspResponderCert.value()->GetX509CertObj()) : nullptr;
    validateParam.revocationCheckParam = tempRevocationCheckParam;
    return true;
}

bool BuildValidateKeyUsage(optional<array<KeyUsageType>> const& keyUsage, HcfX509CertChainValidateParams &validateParam)
{
    if (!keyUsage.has_value()) {
        return true;
    }
    uint32_t length = keyUsage.has_value() ? keyUsage.value().size() : 0;
    HcfKuArray *tempKeyUsageArray = static_cast<HcfKuArray *>(CfMalloc(sizeof(HcfKuArray), 0));
    if (tempKeyUsageArray == nullptr) {
        return false;
    }
    tempKeyUsageArray->data = static_cast<HcfKeyUsageType *>(CfMalloc(sizeof(HcfKeyUsageType) * length, 0));
    if (tempKeyUsageArray->data == nullptr) {
        CF_FREE_PTR(tempKeyUsageArray);
        return false;
    }
    for (size_t i = 0; i < length; i++) {
        tempKeyUsageArray->data[i] = static_cast<HcfKeyUsageType>(keyUsage.value()[i].get_value());
    }
    tempKeyUsageArray->count = length;
    validateParam.keyUsage = tempKeyUsageArray;
    return true;
}

} // namespace

namespace ANI::CertFramework {
bool BuildX509CertMatchParamsV1(X509CertMatchParameters const& param, HcfX509CertMatchParams &hcfParam)
{
    if (param.x509Cert.has_value()) {
        hcfParam.x509Cert = reinterpret_cast<HcfCertificate *>(param.x509Cert.value()->GetX509CertObj());
    }
    if (param.validDate.has_value()) {
        hcfParam.validDate = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
        if (hcfParam.validDate == nullptr) {
            return false;
        }
        StringToDataBlob(param.validDate.value(), *hcfParam.validDate);
    }
    if (param.issuer.has_value()) {
        hcfParam.issuer = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
        if (hcfParam.issuer == nullptr) {
            return false;
        }
        ArrayU8ToDataBlob(param.issuer.value(), *hcfParam.issuer);
    }
    if (param.serialNumber.has_value()) {
        hcfParam.serialNumber = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
        if (hcfParam.serialNumber == nullptr) {
            return false;
        }
        if (!ArrayU8ToBigInteger(param.serialNumber.value(), *hcfParam.serialNumber, true)) {
            return false;
        }
    }
    if (param.subject.has_value()) {
        hcfParam.subject = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
        if (hcfParam.subject == nullptr) {
            return false;
        }
        ArrayU8ToDataBlob(param.subject.value(), *hcfParam.subject);
    }
    if (!BuildPublicKey(param, hcfParam)) {
        return false;
    }

    if (!BuildPrivateKey(param, hcfParam)) {
        return false;
    }

    if (param.publicKeyAlgID.has_value()) {
        hcfParam.publicKeyAlgID = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
        if (hcfParam.publicKeyAlgID == nullptr) {
            return false;
        }
        StringToDataBlob(param.publicKeyAlgID.value(), *hcfParam.publicKeyAlgID);
    }
    return true;
}

bool BuildX509CertMatchParamsV2(X509CertMatchParameters const& param, HcfX509CertMatchParams &hcfParam)
{
    hcfParam.matchAllSubjectAltNames = param.matchAllSubjectAltNames.has_value() ?
        param.matchAllSubjectAltNames.value() : false;
    hcfParam.minPathLenConstraint = param.minPathLenConstraint.has_value() ?
        param.minPathLenConstraint.value() : -1;
    if (param.authorityKeyIdentifier.has_value()) {
        if (param.authorityKeyIdentifier.value().empty()) {
            return false;
        }
        hcfParam.authorityKeyIdentifier = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
        if (hcfParam.authorityKeyIdentifier == nullptr) {
            return false;
        }
        ArrayU8ToDataBlob(param.authorityKeyIdentifier.value(), *hcfParam.authorityKeyIdentifier);
    }
    if (param.nameConstraints.has_value()) {
        if (param.nameConstraints.value().empty()) {
            return false;
        }
        hcfParam.nameConstraints = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
        if (hcfParam.nameConstraints == nullptr) {
            return false;
        }
        ArrayU8ToDataBlob(param.nameConstraints.value(), *hcfParam.nameConstraints);
    }
    if (param.privateKeyValid.has_value()) {
        if (param.privateKeyValid.value().empty()) {
            return false;
        }
        hcfParam.privateKeyValid = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
        if (hcfParam.privateKeyValid == nullptr) {
            return false;
        }
        StringToDataBlob(param.privateKeyValid.value(), *hcfParam.privateKeyValid);
    }
    if (param.subjectKeyIdentifier.has_value()) {
        if (param.subjectKeyIdentifier.value().empty()) {
            return false;
        }
        hcfParam.subjectKeyIdentifier = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
        if (hcfParam.subjectKeyIdentifier == nullptr) {
            return false;
        }
        ArrayU8ToDataBlob(param.subjectKeyIdentifier.value(), *hcfParam.subjectKeyIdentifier);
    }
    return true;
}

bool BuildX509CertMatchParamsV3(X509CertMatchParameters const& param, HcfX509CertMatchParams &hcfParam)
{
    if (!BuildKeyUsage(param, hcfParam)) {
        return false;
    }
    if (!BuildSubjectAlternativeNames(param, hcfParam)) {
        return false;
    }
    if (!BuildExtendedKeyUsage(param, hcfParam)) {
        return false;
    }
    if (!BuildCertPolicy(param, hcfParam)) {
        return false;
    }
    return true;
}

bool BuildX509CertMatchParams(X509CertMatchParameters const& param, HcfX509CertMatchParams &hcfParam)
{
    if (!BuildX509CertMatchParamsV1(param, hcfParam)) {
        FreeX509CertMatchParams(hcfParam);
        return false;
    }
    if (!BuildX509CertMatchParamsV2(param, hcfParam)) {
        FreeX509CertMatchParams(hcfParam);
        return false;
    }
    if (!BuildX509CertMatchParamsV3(param, hcfParam)) {
        FreeX509CertMatchParams(hcfParam);
        return false;
    }
    return true;
}

void FreeX509CertMatchParams(HcfX509CertMatchParams &hcfParam)
{
    hcfParam.x509Cert = nullptr;
    CF_FREE_PTR(hcfParam.validDate);
    CF_FREE_PTR(hcfParam.issuer);
    CF_FREE_PTR(hcfParam.serialNumber);
    CF_FREE_PTR(hcfParam.subject);
    CF_FREE_PTR(hcfParam.publicKey);
    CF_FREE_PTR(hcfParam.publicKeyAlgID);
    CF_FREE_PTR(hcfParam.authorityKeyIdentifier);
    CF_FREE_PTR(hcfParam.nameConstraints);
    CF_FREE_PTR(hcfParam.privateKeyValid);
    CF_FREE_PTR(hcfParam.subjectKeyIdentifier);
    if (hcfParam.privateKey != nullptr) {
        if (hcfParam.privateKey->data != nullptr && hcfParam.privateKey->len > 0) {
            (void)memset_s(hcfParam.privateKey->data, hcfParam.privateKey->len, 0, hcfParam.privateKey->len);
        }
        CF_FREE_PTR(hcfParam.privateKey->data);
        CF_FREE_PTR(hcfParam.privateKey);
    }
    CfBlobFree(&hcfParam.keyUsage);
    if (hcfParam.extendedKeyUsage != nullptr) {
        CF_FREE_PTR(hcfParam.extendedKeyUsage->data);
    }
    CF_FREE_PTR(hcfParam.extendedKeyUsage);
    if (hcfParam.certPolicy != nullptr) {
        CF_FREE_PTR(hcfParam.certPolicy->data);
    }
    CF_FREE_PTR(hcfParam.certPolicy);
    if (hcfParam.subjectAlternativeNames != nullptr) {
        CF_FREE_PTR(hcfParam.subjectAlternativeNames->data);
    }
    CF_FREE_PTR(hcfParam.subjectAlternativeNames);
}

bool BuildX509CertChainValidateParams1(CertChainValidationParameters const& param,
    HcfX509CertChainValidateParams &validateParam)
{
    if (param.date.has_value()) {
        if (param.date.value().empty()) {
            return false;
        }
        validateParam.date = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
        if (validateParam.date == nullptr) {
            return false;
        }
        StringToDataBlob(param.date.value(), *validateParam.date);
    }
    if (param.sslHostname.has_value()) {
        if (param.sslHostname.value().empty()) {
            return false;
        }
        validateParam.sslHostname = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
        if (validateParam.sslHostname == nullptr) {
            CfBlobFree(&validateParam.date);
            return false;
        }
        StringToDataBlob(param.sslHostname.value(), *validateParam.sslHostname);
    }
    return true;
}

bool BuildX509CertChainValidateParams2(CertChainValidationParameters const& param,
    HcfX509CertChainValidateParams &validateParam)
{
    validateParam.policy = param.policy.has_value() ?
        static_cast<HcfValPolicyType>(param.policy.value().get_value()) : VALIDATION_POLICY_TYPE_X509;
    validateParam.trustSystemCa = param.trustSystemCa.has_value() ?
        param.trustSystemCa.value() : false;
    validateParam.allowDownloadIntermediateCa = param.allowDownloadIntermediateCa.has_value() ?
        param.allowDownloadIntermediateCa.value() : false;
    if (!BuildTrustAnchors(param.trustAnchors, validateParam, validateParam.trustSystemCa)) {
        return false;
    }
    if (!BuildCertCRLs(param.certCRLs, validateParam)) {
        return false;
    }
    if (!BuildRevocationCheckParam(param.revocationCheckParam, validateParam)) {
        return false;
    }
    if (!BuildValidateKeyUsage(param.keyUsage, validateParam)) {
        return false;
    }
    return true;
}

bool BuildX509CertChainValidateParams(CertChainValidationParameters const& param,
    HcfX509CertChainValidateParams &hcfParam)
{
    if (!BuildX509CertChainValidateParams1(param, hcfParam)) {
        FreeX509CertChainValidateParams(hcfParam);
        return false;
    }
    if (!BuildX509CertChainValidateParams2(param, hcfParam)) {
        FreeX509CertChainValidateParams(hcfParam);
        return false;
    }
    return true;
}

void FreeTrustAnchorArray(HcfX509TrustAnchorArray *&trustAnchors)
{
    if (trustAnchors == nullptr) {
        return;
    }
    for (uint32_t i = 0; i < trustAnchors->count; ++i) {
        FreeX509TrustAnchor(trustAnchors->data[i], false);
    }
    CF_FREE_PTR(trustAnchors);
}

void FreeX509CertChainValidateParams(HcfX509CertChainValidateParams &hcfParam)
{
    CF_FREE_PTR(hcfParam.date);
    CF_FREE_PTR(hcfParam.sslHostname);
    if (hcfParam.trustAnchors != nullptr) {
        FreeTrustAnchorArray(hcfParam.trustAnchors);
    }
    if (hcfParam.certCRLCollections != nullptr) {
        CF_FREE_PTR(hcfParam.certCRLCollections->data);
        CF_FREE_PTR(hcfParam.certCRLCollections);
    }
    FreeHcfRevocationCheckParam(hcfParam.revocationCheckParam);
    if (hcfParam.keyUsage != nullptr) {
        CF_FREE_PTR(hcfParam.keyUsage->data);
        CF_FREE_PTR(hcfParam.keyUsage);
    }
}

void FreeCertChainValidateResult(HcfX509CertChainValidateResult *result)
{
    if (result == nullptr) {
        return;
    }
CfObjDestroy(result->entityCert);
    FreeX509TrustAnchor(result->trustAnchor);
}

CfResult BuildCertArrayInner(const AniParamInfo *info, optional<array<X509Cert>> const& certs,
    HcfX509CertificateArray &hcfCerts, char *&errMsg)
{
    if (!certs.has_value()) {
        return CF_SUCCESS;
    }
    uint32_t count = certs.value().size();
    if (count == 0) {
        return CF_SUCCESS;
    }
    if (count < info->min || count > info->max) {
        CfBuildErrorMsg(&errMsg, "%s count %u not in [%u, %u]", info->name, count, info->min, info->max);
        return CF_ERR_PARAMETER_CHECK;
    }
    hcfCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *) * count, 0));
    if (hcfCerts.data == nullptr) {
        CfBuildErrorMsg(&errMsg, "%s malloc %zu bytes failed", info->name, sizeof(HcfX509Certificate *) * count);
        return CF_ERR_MALLOC;
    }
    hcfCerts.count = count;
    for (uint32_t i = 0; i < count; ++i) {
        hcfCerts.data[i] = reinterpret_cast<HcfX509Certificate *>(certs.value()[i]->GetX509CertObj());
    }
    return CF_SUCCESS;
}

CfResult BuildStringArrayInner(const AniParamInfo *info, optional<array<string>> const& strs,
    HcfStringArray &hcfStrs, char *&errMsg)
{
    if (!strs.has_value()) {
        return CF_SUCCESS;
    }
    uint32_t count = strs.value().size();
    if (count == 0) {
        return CF_SUCCESS;
    }
    if (count < info->min || count > info->max) {
        CfBuildErrorMsg(&errMsg, "%s count %u not in [%u, %u]", info->name, count, info->min, info->max);
        return CF_ERR_PARAMETER_CHECK;
    }
    hcfStrs.data = static_cast<char **>(CfMalloc(sizeof(char *) * count, 0));
    if (hcfStrs.data == nullptr) {
        CfBuildErrorMsg(&errMsg, "%s malloc %zu bytes failed", info->name, sizeof(char *) * count);
        return CF_ERR_MALLOC;
    }
    hcfStrs.count = count;
    uint32_t strMin = info->next ? info->next->min : 1;
    uint32_t strMax = info->next ? info->next->max : UINT32_MAX;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t strLen = strs.value()[i].size();
        if (strLen == 0 || strLen < strMin || strLen > strMax) {
            CfBuildErrorMsg(&errMsg, "%s[%u] length %u not in [%u, %u]", info->name, i, strLen, strMin, strMax);
            return CF_ERR_PARAMETER_CHECK;
        }
        hcfStrs.data[i] = strdup(strs.value()[i].c_str());
        if (hcfStrs.data[i] == nullptr) {
            CfBuildErrorMsg(&errMsg, "%s[%u] strdup %u bytes failed", info->name, i, strLen + 1);
            return CF_ERR_MALLOC;
        }
    }
    return CF_SUCCESS;
}

CfResult BuildInt32ArrayInner(const AniParamInfo *info, optional<array<KeyUsageType>> const& vals,
    HcfInt32Array &hcfArr, char *&errMsg)
{
    if (!vals.has_value()) {
        return CF_SUCCESS;
    }
    uint32_t count = vals.value().size();
    if (count == 0) {
        return CF_SUCCESS;
    }
    if (count < info->min || count > info->max) {
        CfBuildErrorMsg(&errMsg, "%s count %u not in [%u, %u]", info->name, count, info->min, info->max);
        return CF_ERR_PARAMETER_CHECK;
    }
    hcfArr.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t) * count, 0));
    if (hcfArr.data == nullptr) {
        CfBuildErrorMsg(&errMsg, "%s malloc %zu bytes failed", info->name, sizeof(int32_t) * count);
        return CF_ERR_MALLOC;
    }
    hcfArr.count = count;
    for (uint32_t i = 0; i < count; ++i) {
        hcfArr.data[i] = vals.value()[i].get_value();
    }
    return CF_SUCCESS;
}

CfResult BuildResultArrayInner(const AniParamInfo *info, optional<array<CertResult>> const& vals,
    HcfInt32Array &hcfArr, char *&errMsg)
{
    if (!vals.has_value()) {
        return CF_SUCCESS;
    }
    uint32_t count = vals.value().size();
    if (count == 0) {
        return CF_SUCCESS;
    }
    if (count < info->min || count > info->max) {
        CfBuildErrorMsg(&errMsg, "%s count %u not in [%u, %u]", info->name, count, info->min, info->max);
        return CF_ERR_PARAMETER_CHECK;
    }
    hcfArr.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t) * count, 0));
    if (hcfArr.data == nullptr) {
        CfBuildErrorMsg(&errMsg, "%s malloc %zu bytes failed", info->name, sizeof(int32_t) * count);
        return CF_ERR_MALLOC;
    }
    hcfArr.count = count;
    for (uint32_t i = 0; i < count; ++i) {
        hcfArr.data[i] = vals.value()[i].get_value();
    }
    return CF_SUCCESS;
}

CfResult BuildRevocationFlagsInner(array<CertRevocationFlag> const& flags, HcfInt32Array &hcfArr, char *&errMsg)
{
    uint32_t count = flags.size();
    if (count == 0 || count > MAX_REVOCATION_FLAG_COUNT) {
        CfBuildErrorMsg(&errMsg, "revocationFlags count %u not in [1, %u]", count, MAX_REVOCATION_FLAG_COUNT);
        return CF_ERR_PARAMETER_CHECK;
    }
    hcfArr.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t) * count, 0));
    if (hcfArr.data == nullptr) {
        CfBuildErrorMsg(&errMsg, "revocationFlags malloc %zu bytes failed", sizeof(int32_t) * count);
        return CF_ERR_MALLOC;
    }
    hcfArr.count = count;
    for (uint32_t i = 0; i < count; ++i) {
        hcfArr.data[i] = flags[i].get_value();
    }
    return CF_SUCCESS;
}

CfResult BuildCrlArrayInner(const AniParamInfo *info, optional<array<X509CRL>> const& crls,
    HcfX509CrlArray &hcfCrls, char *&errMsg)
{
    if (!crls.has_value()) {
        return CF_SUCCESS;
    }
    uint32_t count = crls.value().size();
    if (count == 0) {
        return CF_SUCCESS;
    }
    if (count < info->min || count > info->max) {
        CfBuildErrorMsg(&errMsg, "%s count %u not in [%u, %u]", info->name, count, info->min, info->max);
        return CF_ERR_PARAMETER_CHECK;
    }
    hcfCrls.data = static_cast<HcfX509Crl **>(CfMalloc(sizeof(HcfX509Crl *) * count, 0));
    if (hcfCrls.data == nullptr) {
        CfBuildErrorMsg(&errMsg, "%s malloc %zu bytes failed", info->name, sizeof(HcfX509Crl *) * count);
        return CF_ERR_MALLOC;
    }
    hcfCrls.count = count;
    for (uint32_t i = 0; i < count; ++i) {
        hcfCrls.data[i] = reinterpret_cast<HcfX509Crl *>(crls.value()[i]->GetX509CRLObj());
    }
    return CF_SUCCESS;
}

CfResult BuildOcspResponsesInner(const AniParamInfo *info, optional<array<array<uint8_t>>> const& responses,
    CfBlobArray &hcfArr, char *&errMsg)
{
    if (!responses.has_value()) {
        return CF_SUCCESS;
    }
    uint32_t count = responses.value().size();
    if (count == 0) {
        return CF_SUCCESS;
    }
    if (count < info->min || count > info->max) {
        CfBuildErrorMsg(&errMsg, "%s count %u not in [%u, %u]", info->name, count, info->min, info->max);
        return CF_ERR_PARAMETER_CHECK;
    }
    hcfArr.data = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob) * count, 0));
    if (hcfArr.data == nullptr) {
        CfBuildErrorMsg(&errMsg, "%s malloc %zu bytes failed", info->name, sizeof(CfBlob) * count);
        return CF_ERR_MALLOC;
    }
    hcfArr.count = count;
    for (uint32_t i = 0; i < count; ++i) {
        ArrayU8ToDataBlob(responses.value()[i], hcfArr.data[i]);
    }
    return CF_SUCCESS;
}

CfResult BuildRevokedParamsInner(optional<X509CertRevokedParams> const& params, HcfX509CertRevokedParams *&hcfParams,
    char *&errMsg)
{
    if (!params.has_value()) {
        return CF_SUCCESS;
    }
    hcfParams = static_cast<HcfX509CertRevokedParams *>(CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    if (hcfParams == nullptr) {
        CfBuildErrorMsg(&errMsg, "revokedParams malloc %zu bytes failed", sizeof(HcfX509CertRevokedParams));
        return CF_ERR_MALLOC;
    }
    CfResult ret = BuildRevocationFlagsInner(params->revocationFlags, hcfParams->revocationFlags, errMsg);
    if (ret != CF_SUCCESS) {
        return ret;
    }
    AniParamInfo crlInfo = {"crls", 0, MAX_CRL_COUNT, nullptr};
    ret = BuildCrlArrayInner(&crlInfo, params->crls, hcfParams->crls, errMsg);
    if (ret != CF_SUCCESS) {
        return ret;
    }
    hcfParams->allowDownloadCrl = params->allowDownloadCrl.has_value() ? params->allowDownloadCrl.value() : false;
    hcfParams->allowOcspCheckOnline = params->allowOcspCheckOnline.has_value() ?
        params->allowOcspCheckOnline.value() : false;
    AniParamInfo ocspInfo = {"ocspResponses", 0, MAX_OCSP_RESPONSE_COUNT, nullptr};
    ret = BuildOcspResponsesInner(&ocspInfo, params->ocspResponses, hcfParams->ocspResponses, errMsg);
    if (ret != CF_SUCCESS) {
        return ret;
    }
    hcfParams->ocspDigest = params->ocspDigest.has_value() ? params->ocspDigest.value().get_value() :
        OCSP_DIGEST_SHA256;
    return CF_SUCCESS;
}

void FreeCertArray(HcfX509CertificateArray &hcfCerts)
{
    if (hcfCerts.data != nullptr) {
        CF_FREE_PTR(hcfCerts.data);
        hcfCerts.count = 0;
    }
}

void FreeStringArray(HcfStringArray &hcfStrs)
{
    if (hcfStrs.data != nullptr) {
        for (uint32_t i = 0; i < hcfStrs.count; ++i) {
            CF_FREE_PTR(hcfStrs.data[i]);
        }
        CF_FREE_PTR(hcfStrs.data);
        hcfStrs.count = 0;
    }
}

void FreeInt32Array(HcfInt32Array &hcfArr)
{
    if (hcfArr.data != nullptr) {
        CF_FREE_PTR(hcfArr.data);
        hcfArr.count = 0;
    }
}

void FreeCrlArray(HcfX509CrlArray &hcfCrls)
{
    if (hcfCrls.data != nullptr) {
        CF_FREE_PTR(hcfCrls.data);
        hcfCrls.count = 0;
    }
}

void FreeOcspResponses(CfBlobArray &hcfArr)
{
    if (hcfArr.data != nullptr) {
        CF_FREE_PTR(hcfArr.data);
        hcfArr.count = 0;
    }
}

void FreeRevokedParams(HcfX509CertRevokedParams *&hcfParams)
{
    if (hcfParams == nullptr) {
        return;
    }
    FreeInt32Array(hcfParams->revocationFlags);
    FreeCrlArray(hcfParams->crls);
    FreeOcspResponses(hcfParams->ocspResponses);
    CF_FREE_PTR(hcfParams);
}

CfResult BuildStringInner(optional<string> const& strs, char *&res, uint32_t minLen, uint32_t maxLen,
    char *&errMsg)
{
    if (!strs.has_value()) {
        return CF_SUCCESS;
    }
    uint32_t count = strs.value().size();
    if (count == 0) {
        CfBuildErrorMsg(&errMsg, "date is empty string");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (count < minLen || count > maxLen) {
        CfBuildErrorMsg(&errMsg, "date length %u not in [%u, %u]", count, minLen, maxLen);
        return CF_ERR_PARAMETER_CHECK;
    }
    res = strdup(strs.value().c_str());
    if (res == nullptr) {
        CfBuildErrorMsg(&errMsg, "date strdup %u bytes failed", count + 1);
        return CF_ERR_MALLOC;
    }
    return CF_SUCCESS;
}

CfResult BuildX509CertValidatorParams(X509CertValidatorParams const& param,
    HcfX509CertValidatorParams &hcfParam, char *&errMsg)
{
    AniParamInfo untrustedCertsInfo = {"untrustedCerts", 0, MAX_UNTRUSTED_CERT_COUNT, nullptr};
    CfResult ret = BuildCertArrayInner(&untrustedCertsInfo, param.untrustedCerts, hcfParam.untrustedCerts, errMsg);
    if (ret != CF_SUCCESS) {
        return ret;
    }
    AniParamInfo trustedCertsInfo = {"trustedCerts", 0, MAX_TRUSTED_CERT_COUNT, nullptr};
    ret = BuildCertArrayInner(&trustedCertsInfo, param.trustedCerts, hcfParam.trustedCerts, errMsg);
    if (ret != CF_SUCCESS) {
        return ret;
    }
    hcfParam.trustSystemCa = param.trustSystemCa.has_value() ? param.trustSystemCa.value() : false;
    hcfParam.partialChain = param.partialChain.has_value() ? param.partialChain.value() : false;
    hcfParam.allowDownloadIntermediateCa = param.allowDownloadIntermediateCa.has_value() ?
        param.allowDownloadIntermediateCa.value() : false;
    hcfParam.validateDate = param.validateDate.has_value() ? param.validateDate.value() : true;
    ret = BuildStringInner(param.date, hcfParam.date, MIN_DATE_LEN, MAX_DATE_LEN, errMsg);
    if (ret != CF_SUCCESS) {
        return ret;
    }
    AniParamInfo ignoreErrsInfo = {"ignoreErrs", 0, MAX_IGNORE_ERR_COUNT, nullptr};
    ret = BuildResultArrayInner(&ignoreErrsInfo, param.ignoreErrs, hcfParam.ignoreErrs, errMsg);
    if (ret != CF_SUCCESS) {
        return ret;
    }
    AniParamInfo hostnameElemInfo = {"hostnameElem", 1, MAX_HOSTNAME_LENGTH, nullptr};
    AniParamInfo hostnamesInfo = {"hostnames", 0, MAX_HOSTNAMES_COUNT, &hostnameElemInfo};
    ret = BuildStringArrayInner(&hostnamesInfo, param.hostnames, hcfParam.hostnames, errMsg);
    if (ret != CF_SUCCESS) {
        return ret;
    }
    AniParamInfo emailElemInfo = {"emailAddressesElem", 1, MAX_EMAIL_ADDRESS_LENGTH, nullptr};
    AniParamInfo emailsInfo = {"emailAddresses", 0, MAX_EMAIL_ADDRESS_COUNT, &emailElemInfo};
    ret = BuildStringArrayInner(&emailsInfo, param.emailAddresses, hcfParam.emailAddresses, errMsg);
    if (ret != CF_SUCCESS) {
        return ret;
    }
    AniParamInfo keyUsageInfo = {"keyUsage", 0, MAX_KEYUSAGE_COUNT, nullptr};
    ret = BuildInt32ArrayInner(&keyUsageInfo, param.keyUsage, hcfParam.keyUsage, errMsg);
    if (ret != CF_SUCCESS) {
        return ret;
    }
    if (param.userId.has_value()) {
        ArrayU8ToDataBlob(param.userId.value(), hcfParam.userId);
    }
    return BuildRevokedParamsInner(param.revokedParams, hcfParam.revokedParams, errMsg);
}

void FreeX509CertValidatorParams(HcfX509CertValidatorParams &hcfParam)
{
    FreeCertArray(hcfParam.untrustedCerts);
    FreeCertArray(hcfParam.trustedCerts);
    CF_FREE_PTR(hcfParam.date);
    FreeInt32Array(hcfParam.ignoreErrs);
    FreeStringArray(hcfParam.hostnames);
    FreeStringArray(hcfParam.emailAddresses);
    FreeInt32Array(hcfParam.keyUsage);
    FreeRevokedParams(hcfParam.revokedParams);
}

void FreeVerifyCertResult(HcfVerifyCertResult &result)
{
    if (result.certs.data != nullptr) {
        for (uint32_t i = 0; i < result.certs.count; ++i) {
            CfObjDestroy(result.certs.data[i]);
        }
        CF_FREE_PTR(result.certs.data);
        result.certs.count = 0;
    }
}
} // namespace ANI::CertFramework
