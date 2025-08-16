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

#include "ani_parameters.h"

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
            StringToDataBlob(param.certPolicy.value()[i], hcfParam.certPolicy->data[i]);
        }
    }
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

bool BuildTrustAnchors(array<X509TrustAnchor> const& param, HcfX509CertChainValidateParams &validateParam)
{
    uint32_t count = param.size();
    if (count == 0 || count > MAX_LEN_OF_ARRAY) {
        return false;
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
        if (param->ocspResponses.value().size() == 0) {
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
    if (param.publicKey.has_value()) {
        hcfParam.publicKey = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
        if (hcfParam.publicKey == nullptr) {
            return false;
        }
        ArrayU8ToDataBlob(param.publicKey.value().data, *hcfParam.publicKey);
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
    if (param.matchAllSubjectAltNames.has_value()) {
        hcfParam.matchAllSubjectAltNames = param.matchAllSubjectAltNames.value();
    }
    if (param.authorityKeyIdentifier.has_value()) {
        if (param.authorityKeyIdentifier.value().size() == 0) {
            return false;
        }
        hcfParam.authorityKeyIdentifier = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
        if (hcfParam.authorityKeyIdentifier == nullptr) {
            return false;
        }
        ArrayU8ToDataBlob(param.authorityKeyIdentifier.value(), *hcfParam.authorityKeyIdentifier);
    }
    hcfParam.minPathLenConstraint = param.minPathLenConstraint.has_value() ?
        param.minPathLenConstraint.value() : -1;
    if (param.nameConstraints.has_value()) {
        if (param.nameConstraints.value().size() == 0) {
            return false;
        }
        hcfParam.nameConstraints = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
        if (hcfParam.nameConstraints == nullptr) {
            return false;
        }
        ArrayU8ToDataBlob(param.nameConstraints.value(), *hcfParam.nameConstraints);
    }
    if (param.privateKeyValid.has_value()) {
        if (param.privateKeyValid.value().size() == 0) {
            return false;
        }
        hcfParam.privateKeyValid = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
        if (hcfParam.privateKeyValid == nullptr) {
            return false;
        }
        StringToDataBlob(param.privateKeyValid.value(), *hcfParam.privateKeyValid);
    }
    if (param.subjectKeyIdentifier.has_value()) {
        if (param.subjectKeyIdentifier.value().size() == 0) {
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
    if (!BuildTrustAnchors(param.trustAnchors, validateParam)) {
        return false;
    }
    if (!BuildCertCRLs(param.certCRLs, validateParam)) {
        return false;
    }
    if (!BuildRevocationCheckParam(param.revocationCheckParam, validateParam)) {
        return false;
    }
    validateParam.policy = static_cast<HcfValPolicyType>(param.policy.has_value() ?
        param.policy.value() : VALIDATION_POLICY_TYPE_X509);

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
} // namespace ANI::CertFramework
