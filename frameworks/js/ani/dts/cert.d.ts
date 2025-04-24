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

import type { AsyncCallback } from './@ohos.base';
import cryptoFramework from './@ohos.security.cryptoFramework';

declare namespace cert {
  enum CertResult {
    INVALID_PARAMS = 401,
    NOT_SUPPORT = 801,
    ERR_OUT_OF_MEMORY = 19020001,
    ERR_RUNTIME_ERROR = 19020002,
    ERR_CRYPTO_OPERATION = 19030001,
    ERR_CERT_SIGNATURE_FAILURE = 19030002,
    ERR_CERT_NOT_YET_VALID = 19030003,
    ERR_CERT_HAS_EXPIRED = 19030004,
    ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 19030005,
    ERR_KEYUSAGE_NO_CERTSIGN = 19030006,
    ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE = 19030007,
    ERR_MAYBE_WRONG_PASSWORD = 19030008
  }

  interface DataBlob {
    data: Uint8Array;
  }

  interface DataArray {
    data: Array<Uint8Array>;
  }

  enum EncodingFormat {
    FORMAT_DER = 0,
    FORMAT_PEM = 1,
    FORMAT_PKCS7 = 2
  }

  enum CertItemType {
    CERT_ITEM_TYPE_TBS = 0,
    CERT_ITEM_TYPE_PUBLIC_KEY = 1,
    CERT_ITEM_TYPE_ISSUER_UNIQUE_ID = 2,
    CERT_ITEM_TYPE_SUBJECT_UNIQUE_ID = 3,
    CERT_ITEM_TYPE_EXTENSIONS = 4
  }

  enum ExtensionOidType {
    EXTENSION_OID_TYPE_ALL = 0,
    EXTENSION_OID_TYPE_CRITICAL = 1,
    EXTENSION_OID_TYPE_UNCRITICAL = 2
  }

  enum ExtensionEntryType {
    EXTENSION_ENTRY_TYPE_ENTRY = 0,
    EXTENSION_ENTRY_TYPE_ENTRY_CRITICAL = 1,
    EXTENSION_ENTRY_TYPE_ENTRY_VALUE = 2
  }

  interface EncodingBlob {
    data: Uint8Array;
    encodingFormat: EncodingFormat;
  }

  interface CertChainData {
    data: Uint8Array;
    count: number;
    encodingFormat: EncodingFormat;
  }

  enum EncodingType {
    ENCODING_UTF8 = 0
  }

  interface X509Cert {
    verify(key: cryptoFramework.PubKey, callback: AsyncCallback<void>): void;
    verify(key: cryptoFramework.PubKey): Promise<void>;
    getEncoded(callback: AsyncCallback<EncodingBlob>): void;
    getEncoded(): Promise<EncodingBlob>;
    getPublicKey(): cryptoFramework.PubKey;
    checkValidityWithDate(date: string): void;
    getVersion(): number;
    getSerialNumber(): number;
    getCertSerialNumber(): bigint;
    getIssuerName(): DataBlob;
    getSubjectName(encodingType?: EncodingType): DataBlob;
    getNotBeforeTime(): string;
    getNotAfterTime(): string;
    getSignature(): DataBlob;
    getSignatureAlgName(): string;
    getSignatureAlgOid(): string;
    getSignatureAlgParams(): DataBlob;
    getKeyUsage(): DataBlob;
    getExtKeyUsage(): DataArray;
    getBasicConstraints(): number;
    getSubjectAltNames(): DataArray;
    getIssuerAltNames(): DataArray;
    getItem(itemType: CertItemType): DataBlob;
    match(param: X509CertMatchParameters): boolean;
    getCRLDistributionPoint(): DataArray;
    getIssuerX500DistinguishedName(): X500DistinguishedName;
    getSubjectX500DistinguishedName(): X500DistinguishedName;
    toString(): string;
    hashCode(): Uint8Array;
    getExtensionsObject(): CertExtension;
  }
  function createX509Cert(inStream: EncodingBlob, callback: AsyncCallback<X509Cert>): void;
  function createX509Cert(inStream: EncodingBlob): Promise<X509Cert>;

  interface CertExtension {
    getEncoded(): EncodingBlob;
    getOidList(valueType: ExtensionOidType): DataArray;
    getEntry(valueType: ExtensionEntryType, oid: DataBlob): DataBlob;
    checkCA(): number;
    hasUnsupportedCriticalExtension(): boolean;
  }
  function createCertExtension(inStream: EncodingBlob, callback: AsyncCallback<CertExtension>): void;
  function createCertExtension(inStream: EncodingBlob): Promise<CertExtension>;

  interface X509CRLEntry {
    getEncoded(callback: AsyncCallback<EncodingBlob>): void;
    getEncoded(): Promise<EncodingBlob>;
    getSerialNumber(): bigint;
    getCertIssuer(): DataBlob;
    getRevocationDate(): string;
    getExtensions(): DataBlob;
    hasExtensions(): boolean;
    getCertIssuerX500DistinguishedName(): X500DistinguishedName;
    toString(): string;
    hashCode(): Uint8Array;
    getExtensionsObject(): CertExtension;
  }

  interface X509CRL {
    isRevoked(cert: X509Cert): boolean;
    getType(): string;
    getEncoded(callback: AsyncCallback<EncodingBlob>): void;
    getEncoded(): Promise<EncodingBlob>;
    verify(key: cryptoFramework.PubKey, callback: AsyncCallback<void>): void;
    verify(key: cryptoFramework.PubKey): Promise<void>;
    getVersion(): number;
    getIssuerName(): DataBlob;
    getLastUpdate(): string;
    getNextUpdate(): string;
    getRevokedCert(serialNumber: bigint): X509CRLEntry;
    getRevokedCertWithCert(cert: X509Cert): X509CRLEntry;
    getRevokedCerts(callback: AsyncCallback<Array<X509CRLEntry>>): void;
    getRevokedCerts(): Promise<Array<X509CRLEntry>>;
    getTBSInfo(): DataBlob;
    getSignature(): DataBlob;
    getSignatureAlgName(): string;
    getSignatureAlgOid(): string;
    getSignatureAlgParams(): DataBlob;
    getExtensions(): DataBlob;
    match(param: X509CRLMatchParameters): boolean;
    getIssuerX500DistinguishedName(): X500DistinguishedName;
    toString(): string;
    hashCode(): Uint8Array;
    getExtensionsObject(): CertExtension;
  }
  function createX509CRL(inStream: EncodingBlob, callback: AsyncCallback<X509CRL>): void;
  function createX509CRL(inStream: EncodingBlob): Promise<X509CRL>;

  interface CertChainValidator {
    validate(certChain: CertChainData, callback: AsyncCallback<void>): void;
    validate(certChain: CertChainData): Promise<void>;
    readonly algorithm: string;
  }
  function createCertChainValidator(algorithm: string): CertChainValidator;

  enum GeneralNameType {
    GENERAL_NAME_TYPE_OTHER_NAME = 0,
    GENERAL_NAME_TYPE_RFC822_NAME = 1,
    GENERAL_NAME_TYPE_DNS_NAME = 2,
    GENERAL_NAME_TYPE_X400_ADDRESS = 3,
    GENERAL_NAME_TYPE_DIRECTORY_NAME = 4,
    GENERAL_NAME_TYPE_EDI_PARTY_NAME = 5,
    GENERAL_NAME_TYPE_UNIFORM_RESOURCE_ID = 6,
    GENERAL_NAME_TYPE_IP_ADDRESS = 7,
    GENERAL_NAME_TYPE_REGISTERED_ID = 8
  }

  interface GeneralName {
    type: GeneralNameType;
    name?: Uint8Array;
  }

  interface X509CertMatchParameters {
    subjectAlternativeNames?: Array<GeneralName>;
    matchAllSubjectAltNames?: boolean;
    authorityKeyIdentifier?: Uint8Array;
    minPathLenConstraint?: number;
    x509Cert?: X509Cert;
    validDate?: string;
    issuer?: Uint8Array;
    extendedKeyUsage?: Array<string>;
    nameConstraints?: Uint8Array;
    certPolicy?: Array<string>;
    privateKeyValid?: string;
    keyUsage?: Array<boolean>;
    serialNumber?: bigint;
    subject?: Uint8Array;
    subjectKeyIdentifier?: Uint8Array;
    publicKey?: DataBlob;
    publicKeyAlgID?: string;
  }

  interface X509CRLMatchParameters {
    issuer?: Array<Uint8Array>;
    x509Cert?: X509Cert;
    updateDateTime?: string;
    maxCRL?: bigint;
    minCRL?: bigint;
  }

  interface CertCRLCollection {
    selectCerts(param: X509CertMatchParameters): Promise<Array<X509Cert>>;
    selectCerts(param: X509CertMatchParameters, callback: AsyncCallback<Array<X509Cert>>): void;
    selectCRLs(param: X509CRLMatchParameters): Promise<Array<X509CRL>>;
    selectCRLs(param: X509CRLMatchParameters, callback: AsyncCallback<Array<X509CRL>>): void;
  }
  function createCertCRLCollection(certs: Array<X509Cert>, crls?: Array<X509CRL>): CertCRLCollection;

  interface X509CertChain {
    getCertList(): Array<X509Cert>;
    validate(param: CertChainValidationParameters): Promise<CertChainValidationResult>;
    validate(param: CertChainValidationParameters, callback: AsyncCallback<CertChainValidationResult>): void;
    toString(): string;
    hashCode(): Uint8Array;
  }
  function createX509CertChain(inStream: EncodingBlob): Promise<X509CertChain>;
  function createX509CertChain(inStream: EncodingBlob, callback: AsyncCallback<X509CertChain>): void;
  function createX509CertChain(certs: Array<X509Cert>): X509CertChain;
  function buildX509CertChain(param: CertChainBuildParameters): Promise<CertChainBuildResult>;

  enum EncodingBaseFormat {
    PEM = 0,
    DER = 1
  }

  interface Pkcs12Data {
    privateKey?: string | Uint8Array;
    cert?: X509Cert;
    otherCerts?: Array<X509Cert>;
  }

  interface Pkcs12ParsingConfig {
    password: string;
    needsPrivateKey?: boolean;
    privateKeyFormat?: EncodingBaseFormat;
    needsCert?: boolean;
    needsOtherCerts?: boolean;
  }
  function parsePkcs12(data: Uint8Array, config: Pkcs12ParsingConfig): Pkcs12Data;
  function createTrustAnchorsWithKeyStore(keystore: Uint8Array, pwd: string): Promise<Array<X509TrustAnchor>>;
  function createX500DistinguishedName(nameStr: string): Promise<X500DistinguishedName>;
  function createX500DistinguishedName(nameDer: Uint8Array): Promise<X500DistinguishedName>;

  interface X500DistinguishedName {
    getName(): string;
    getName(type: string): Array<string>;
    getEncoded(): EncodingBlob;
  }

  interface X509TrustAnchor {
    CACert?: X509Cert;
    CAPubKey?: Uint8Array;
    CASubject?: Uint8Array;
    nameConstraints?: Uint8Array;
  }

  enum RevocationCheckOptions {
    REVOCATION_CHECK_OPTION_PREFER_OCSP = 0,
    REVOCATION_CHECK_OPTION_ACCESS_NETWORK,
    REVOCATION_CHECK_OPTION_FALLBACK_NO_PREFER,
    REVOCATION_CHECK_OPTION_FALLBACK_LOCAL
  }

  enum ValidationPolicyType {
    VALIDATION_POLICY_TYPE_X509 = 0,
    VALIDATION_POLICY_TYPE_SSL
  }

  enum KeyUsageType {
    KEYUSAGE_DIGITAL_SIGNATURE = 0,
    KEYUSAGE_NON_REPUDIATION,
    KEYUSAGE_KEY_ENCIPHERMENT,
    KEYUSAGE_DATA_ENCIPHERMENT,
    KEYUSAGE_KEY_AGREEMENT,
    KEYUSAGE_KEY_CERT_SIGN,
    KEYUSAGE_CRL_SIGN,
    KEYUSAGE_ENCIPHER_ONLY,
    KEYUSAGE_DECIPHER_ONLY
  }

  interface RevocationCheckParameter {
    ocspRequestExtension?: Array<Uint8Array>;
    ocspResponderURI?: string;
    ocspResponderCert?: X509Cert;
    ocspResponses?: Uint8Array;
    crlDownloadURI?: string;
    options?: Array<RevocationCheckOptions>;
    ocspDigest?: string;
  }

  interface CertChainValidationParameters {
    date?: string;
    trustAnchors: Array<X509TrustAnchor>;
    certCRLs?: Array<CertCRLCollection>;
    revocationCheckParam?: RevocationCheckParameter;
    policy?: ValidationPolicyType;
    sslHostname?: string;
    keyUsage?: Array<KeyUsageType>;
  }

  interface CertChainValidationResult {
    readonly trustAnchor: X509TrustAnchor;
    readonly entityCert: X509Cert;
  }

  interface CertChainBuildParameters {
    certMatchParameters: X509CertMatchParameters;
    maxLength?: number;
    validationParameters: CertChainValidationParameters;
  }

  interface CertChainBuildResult {
    readonly certChain: X509CertChain;
    readonly validationResult: CertChainValidationResult;
  }

  enum CmsContentType {
    SIGNED_DATA = 0
  }

  enum CmsContentDataFormat {
    BINARY = 0,
    TEXT = 1
  }

  enum CmsFormat {
    PEM = 0,
    DER = 1
  }

  interface PrivateKeyInfo {
    key: string | Uint8Array;
    password?: string;
  }

  interface CmsSignerConfig {
    mdName: string;
    addCert?: boolean;
    addAttr?: boolean;
    addSmimeCapAttr?: boolean;
  }

  interface CmsGeneratorOptions {
    contentDataFormat?: CmsContentDataFormat;
    outFormat?: CmsFormat;
    isDetached?: boolean;
  }

  interface CmsGenerator {
    addSigner(cert: X509Cert, keyInfo: PrivateKeyInfo, config: CmsSignerConfig): void;
    addCert(cert: X509Cert): void;
    doFinal(data: Uint8Array, options?: CmsGeneratorOptions): Promise<Uint8Array | string>;
    doFinalSync(data: Uint8Array, options?: CmsGeneratorOptions): Uint8Array | string;
  }
  function createCmsGenerator(contentType: CmsContentType): CmsGenerator;

  interface CsrAttribute {
    type: string;
    value: string;
  }

  interface CsrGenerationConfig {
    subject: X500DistinguishedName;
    mdName: string;
    attributes?: Array<CsrAttribute>;
    outFormat?: EncodingBaseFormat;
  }
  function generateCsr(keyInfo: PrivateKeyInfo, config: CsrGenerationConfig): string | Uint8Array;
}

export default cert;
