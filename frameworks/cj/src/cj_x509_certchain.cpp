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

#include "cj_x509_certchain.h"

int32_t FfiCertCjX509CertChainNewInstanceBlob(const CfEncodingBlob *blob, CjX509CertChain *returnObj)
{
    auto chain = static_cast<HcfCertChain *>(malloc(sizeof(HcfCertChain)));
    if (chain == nullptr) {
        return CF_ERR_MALLOC;
    }
    const auto errCode = HcfCertChainCreate(blob, nullptr, &chain);
    if (errCode != CF_SUCCESS) {
        free(chain);
        return errCode;
    }
    returnObj->chain = chain;
    return CF_SUCCESS;
}

int32_t FfiCertCjX509CertChainNewInstanceArray(const HcfX509CertificateArray *inCerts, CjX509CertChain *returnObj)
{
    auto chain = static_cast<HcfCertChain *>(malloc(sizeof(HcfCertChain)));
    if (chain == nullptr) {
        return CF_ERR_MALLOC;
    }
    const auto errCode = HcfCertChainCreate(nullptr, inCerts, &chain);
    if (errCode != CF_SUCCESS) {
        free(chain);
        return errCode;
    }
    returnObj->chain = chain;
    return CF_SUCCESS;
}

void FfiCertCjX509CertChainDeleteInstance(CjX509CertChain self)
{
    CfObjDestroy(self.chain);
}

CfResult FfiCertCjX509CertChainGetCertList(const CjX509CertChain self, HcfX509CertificateArray *out)
{
    return self.chain->getCertList(self.chain, out);
}

CfResult FfiCertCjX509CertChainValidate(const CjX509CertChain self,
                                        const CjX509CertChainValidateParams *params,
                                        CjX509CertChainValidateResult *result)
{
    auto anchors = HcfX509TrustAnchorArray{
        .data = static_cast<HcfX509TrustAnchor **>(malloc(sizeof(HcfX509TrustAnchor *) * (params->trustAnchorCnt))),
        .count = params->trustAnchorCnt,
    };
    if (anchors.data == nullptr) {
        return CF_ERR_MALLOC;
    }
    for (int i = 0; i < params->trustAnchorCnt; ++i) {
        const auto item = static_cast<HcfX509TrustAnchor *>(malloc(sizeof(HcfX509TrustAnchor)));
        if (item == nullptr) {
            free(anchors.data);
            return CF_ERR_MALLOC;
        }
        item->CAPubKey = params->trustAnchors[i].CAPubKey;
        item->CACert = params->trustAnchors[i].CACert;
        item->CASubject = params->trustAnchors[i].CASubject;
        item->nameConstraints = params->trustAnchors[i].nameConstraints;
        anchors.data[i] = item;
    }

    HcfCertCRLCollectionArray *certCRLCollectionsPtr = nullptr;
    HcfCertCRLCollectionArray certCRLCollections;
    if (params->certCRLCollectionCnt != 0) {
        certCRLCollections.data = params->certCRLCollections;
        certCRLCollections.count = params->certCRLCollectionCnt;
        certCRLCollectionsPtr = &certCRLCollections;
    }

    HcfRevChkOpArray *revChkOptionPtr = nullptr;
    HcfRevChkOpArray revChkOption;
    HcfRevocationCheckParam *revocationCheckParamPtr = nullptr;
    HcfRevocationCheckParam revocationCheckParam;
    if (params->revocationCheckParam) {
        if (params->revocationCheckParam->optionCnt != 0) {
            revChkOption = HcfRevChkOpArray{
                .data = params->revocationCheckParam->options,
                .count = params->revocationCheckParam->optionCnt,
            };
            revChkOptionPtr = &revChkOption;
        }
        revocationCheckParam = HcfRevocationCheckParam{
            .ocspRequestExtension = params->revocationCheckParam->ocspRequestExtension,
            .ocspResponderURI = params->revocationCheckParam->ocspResponderURI,
            .ocspResponderCert = params->revocationCheckParam->ocspResponderCert,
            .ocspResponses = params->revocationCheckParam->ocspResponses,
            .crlDownloadURI = params->revocationCheckParam->crlDownloadURI,
            .options = revChkOptionPtr,
            .ocspDigest = params->revocationCheckParam->ocspDigest,
        };
        revocationCheckParamPtr = &revocationCheckParam;
    }

    HcfKuArray *keyUsagePtr = nullptr;
    HcfKuArray keyUsage;
    if(params->keyUsageCnt != 0){
        keyUsage = HcfKuArray {
            .data = params->keyUsage,
            .count = params->keyUsageCnt,
        };
        keyUsagePtr = &keyUsage;
    }

    auto hcfParams = HcfX509CertChainValidateParams{
        .date = params->date,
        .trustAnchors = &anchors,
        .certCRLCollections = certCRLCollectionsPtr,
        .revocationCheckParam = revocationCheckParamPtr,
        .policy = params->policy,
        .sslHostname = params->sslHostname,
        .keyUsage = keyUsagePtr,
    };

    HcfX509CertChainValidateResult hcfResult;
    const CfResult errCode = self.chain->validate(self.chain, &hcfParams, &hcfResult);


    for (int i = 0; i < anchors.count; ++i) {
        free(anchors.data[i]);
    }
    free(anchors.data);


    if (errCode == CF_SUCCESS) {
        result->trustAnchor.CAPubKey = hcfResult.trustAnchor->CAPubKey;
        result->trustAnchor.CACert = hcfResult.trustAnchor->CACert;
        result->trustAnchor.CASubject = hcfResult.trustAnchor->CASubject;
        result->trustAnchor.nameConstraints = hcfResult.trustAnchor->nameConstraints;
        result->entityCert = hcfResult.entityCert;
    }
    return errCode;
}

CfResult FfiCertCjX509CertChainToString(const CjX509CertChain self, CfBlob *out)
{
    return self.chain->toString(self.chain, out);
}

CfResult FfiCertCjX509CertChainHashCode(const CjX509CertChain self, CfBlob *out)
{
    return self.chain->hashCode(self.chain, out);
}

CfResult
FfiCertBuildX509CertChain(const CjX509CertMatchParams &matchParams, const CjX509CertChainValidateParams &validParams,
                          int32_t maxLength, CjX509CertChain *returnObj)
{
    HcfCertificate *certPtr = nullptr;
    if (matchParams.x509Cert != nullptr) {
        certPtr = &matchParams.x509Cert->base;
    }

    SubAltNameArray *subjectAlternativeNamesPtr = nullptr;
    if (matchParams.subjectAlternativeNameCnt > 0) {
        auto subjectAlternativeNames = SubAltNameArray{
            .data = matchParams.subjectAlternativeNames,
            .count = matchParams.subjectAlternativeNameCnt
        };
        subjectAlternativeNamesPtr = &subjectAlternativeNames;
    }


    auto anchors = HcfX509TrustAnchorArray{
        .data = static_cast<HcfX509TrustAnchor **>(malloc(sizeof(HcfX509TrustAnchor *) * (validParams.trustAnchorCnt))),
        .count = validParams.trustAnchorCnt,
    };
    if (anchors.data == nullptr) {
        return CF_ERR_MALLOC;
    }
    for (int i = 0; i < validParams.trustAnchorCnt; ++i) {
        const auto item = static_cast<HcfX509TrustAnchor *>(malloc(sizeof(HcfX509TrustAnchor)));
        if (item == nullptr) {
            free(anchors.data);
            return CF_ERR_MALLOC;
        }
        item->CAPubKey = validParams.trustAnchors[i].CAPubKey;
        item->CACert = validParams.trustAnchors[i].CACert;
        item->CASubject = validParams.trustAnchors[i].CASubject;
        item->nameConstraints = validParams.trustAnchors[i].nameConstraints;
        anchors.data[i] = item;
    }

    HcfCertCRLCollectionArray *certCRLCollectionsPtr = nullptr;
    HcfCertCRLCollectionArray certCRLCollections;
    if (validParams.certCRLCollectionCnt != 0) {
        certCRLCollections.data = validParams.certCRLCollections;
        certCRLCollections.count = validParams.certCRLCollectionCnt;
        certCRLCollectionsPtr = &certCRLCollections;
    }

    HcfRevChkOpArray *revChkOptionPtr = nullptr;
    HcfRevChkOpArray revChkOption;
    HcfRevocationCheckParam *revocationCheckParamPtr = nullptr;
    HcfRevocationCheckParam revocationCheckParam;
    if (validParams.revocationCheckParam) {
        if (validParams.revocationCheckParam->optionCnt != 0) {
            revChkOption = HcfRevChkOpArray{
                .data = validParams.revocationCheckParam->options,
                .count = validParams.revocationCheckParam->optionCnt,
            };
            revChkOptionPtr = &revChkOption;
        }
        revocationCheckParam = HcfRevocationCheckParam{
            .ocspRequestExtension = validParams.revocationCheckParam->ocspRequestExtension,
            .ocspResponderURI = validParams.revocationCheckParam->ocspResponderURI,
            .ocspResponderCert = validParams.revocationCheckParam->ocspResponderCert,
            .ocspResponses = validParams.revocationCheckParam->ocspResponses,
            .crlDownloadURI = validParams.revocationCheckParam->crlDownloadURI,
            .options = revChkOptionPtr,
            .ocspDigest = validParams.revocationCheckParam->ocspDigest,
        };
        revocationCheckParamPtr = &revocationCheckParam;
    }

    HcfKuArray *keyUsagePtr = nullptr;
    HcfKuArray keyUsage;
    if(validParams.keyUsageCnt != 0){
        keyUsage = HcfKuArray {
            .data = validParams.keyUsage,
            .count = validParams.keyUsageCnt,
        };
        keyUsagePtr = &keyUsage;
    }

    const HcfX509CertChainBuildParameters hcfParams = {
        .certMatchParameters = {
            certPtr,
            matchParams.validDate,
            matchParams.issuer,
            matchParams.keyUsage,
            matchParams.serialNumber,
            matchParams.subject,
            matchParams.publicKey,
            matchParams.publicKeyAlgID,
            subjectAlternativeNamesPtr,
            matchParams.matchAllSubjectAltNames,
            matchParams.authorityKeyIdentifier,
            matchParams.minPathLenConstraint,
            matchParams.extendedKeyUsage,
            matchParams.nameConstraints,
            matchParams.certPolicy,
            matchParams.privateKeyValid,
            matchParams.subjectKeyIdentifier,
        },
        .maxlength = maxLength,
        .validateParameters = {
            .date = validParams.date,
            .trustAnchors = &anchors,
            .certCRLCollections = certCRLCollectionsPtr,
            .revocationCheckParam = revocationCheckParamPtr,
            .policy = validParams.policy,
            .sslHostname = validParams.sslHostname,
            .keyUsage = keyUsagePtr,
        }
    };

    HcfX509CertChainBuildResult *buildResult = nullptr;
    const auto errCode = HcfCertChainBuildResultCreate(&hcfParams, &buildResult);
    if (errCode != CF_SUCCESS) {
        return errCode;
    }
    returnObj->chain = buildResult->certChain;
    return CF_SUCCESS;
}

CfResult FfiCertCreateTrustAnchorWithKeyStore(const CfBlob *keyStore, const CfBlob *pwd,
                                              CjX509TrustAnchorArray *returnObj)
{
    HcfX509TrustAnchorArray *anchorArray = nullptr;
    const auto errCode = HcfCreateTrustAnchorWithKeyStore(keyStore, pwd, &anchorArray);
    if (errCode != CF_SUCCESS) {
        return errCode;
    }
    returnObj->count = anchorArray->count;
    returnObj->data = static_cast<CjX509TrustAnchor **>(malloc(sizeof(CjX509TrustAnchor *) * anchorArray->count));
    if (returnObj->data == nullptr) {
        free(anchorArray->data);
        return CF_ERR_MALLOC;
    }
    for (int i = 0; i < anchorArray->count; ++i) {
        const auto anchor = static_cast<CjX509TrustAnchor *>(malloc(sizeof(CjX509TrustAnchor)));
        anchor->CAPubKey = anchorArray->data[i]->CAPubKey;
        anchor->CACert = anchorArray->data[i]->CACert;
        anchor->CASubject = anchorArray->data[i]->CASubject;
        anchor->nameConstraints = anchorArray->data[i]->nameConstraints;
        returnObj->data[i] = anchor;
    }
    free(anchorArray->data);
    return CF_SUCCESS;
}
