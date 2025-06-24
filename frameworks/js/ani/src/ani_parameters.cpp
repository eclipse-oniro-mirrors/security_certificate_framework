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

bool BuildKeyUsage(X509CertMatchParameters const& param, HcfX509CertMatchParams &hcfParam)
{
    if (param.keyUsage.has_value()) {
        hcfParam.keyUsage = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
        if (hcfParam.keyUsage == nullptr) {
            return false;
        }
        uint32_t count = param.keyUsage.value().size();
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
        ArrayU8ToBigInteger(param.serialNumber.value(), *hcfParam.serialNumber, true);
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
        hcfParam.authorityKeyIdentifier = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
        if (hcfParam.authorityKeyIdentifier == nullptr) {
            return false;
        }
        ArrayU8ToDataBlob(param.authorityKeyIdentifier.value(), *hcfParam.authorityKeyIdentifier);
    }
    if (param.minPathLenConstraint.has_value()) {
        hcfParam.minPathLenConstraint = param.minPathLenConstraint.value();
    }
    if (param.nameConstraints.has_value()) {
        hcfParam.nameConstraints = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
        if (hcfParam.nameConstraints == nullptr) {
            return false;
        }
        ArrayU8ToDataBlob(param.nameConstraints.value(), *hcfParam.nameConstraints);
    }
    if (param.privateKeyValid.has_value()) {
        hcfParam.privateKeyValid = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
        if (hcfParam.privateKeyValid == nullptr) {
            return false;
        }
        StringToDataBlob(param.privateKeyValid.value(), *hcfParam.privateKeyValid);
    }
    if (param.subjectKeyIdentifier.has_value()) {
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
    CfFree(hcfParam.validDate);
    CfFree(hcfParam.issuer);
    CfFree(hcfParam.serialNumber);
    CfFree(hcfParam.subject);
    CfFree(hcfParam.publicKey);
    CfFree(hcfParam.publicKeyAlgID);
    CfFree(hcfParam.authorityKeyIdentifier);
    CfFree(hcfParam.nameConstraints);
    CfFree(hcfParam.privateKeyValid);
    CfFree(hcfParam.subjectKeyIdentifier);
    CfBlobFree(&hcfParam.keyUsage);
    if (hcfParam.extendedKeyUsage != nullptr) {
        CfFree(hcfParam.extendedKeyUsage->data);
    }
    CfFree(hcfParam.extendedKeyUsage);
    if (hcfParam.certPolicy != nullptr) {
        CfFree(hcfParam.certPolicy->data);
    }
    CfFree(hcfParam.certPolicy);
    if (hcfParam.subjectAlternativeNames != nullptr) {
        CfFree(hcfParam.subjectAlternativeNames->data);
    }
    CfFree(hcfParam.subjectAlternativeNames);
}

bool BuildX509CertChainValidateParams(CertChainValidationParameters const& param,
    HcfX509CertChainValidateParams &hcfParam)
{
    return true;
}

void FreeX509CertChainValidateParams(HcfX509CertChainValidateParams &hcfParam)
{
}
} // namespace ANI::CertFramework
