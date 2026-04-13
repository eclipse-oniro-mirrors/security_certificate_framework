# 证书链校验特性开发设计文档 v7

## 1 简介

### 1.1 背景说明

#### 1.1.1 证书链校验的重要性

在PKI（公钥基础设施）体系中，X.509证书用于验证实体身份和建立信任关系。证书链校验是确保证书可信的关键环节，其核心目标是验证：

1. **身份真实性**：证书由可信的证书颁发机构（CA）签发
2. **完整性**：证书内容未被篡改
3. **有效性**：证书在有效期内，且未被吊销
4. **用途匹配**：证书的密钥用途符合预期

在实际应用场景中（如HTTPS、代码签名、电子邮件加密等），客户端需要验证服务器或用户证书的合法性，以防止中间人攻击、身份伪造等安全威胁。

#### 1.1.2 功能需求背景

原有的 `validate(certChain: CertChainData)` 接口仅支持验证预先组装好的完整证书链，存在以下局限性：

1. **证书链不完整**：实际场景中，服务器可能只发送终端证书，中间证书需要客户端自行获取
2. **信任锚不灵活**：无法动态指定信任的根证书或使用系统CA
3. **验证参数受限**：无法自定义验证时间、主机名、密钥用途等参数
4. **错误信息不足**：验证失败时无法返回详细的错误原因和已验证的证书链

为解决上述问题，新增 `validate(cert: X509Cert, params: X509CertValidatorParams): Promise<VerifyCertResult>` 接口，提供更灵活、更完整的证书链校验能力。

#### 1.1.3 各项功能说明

X509CertValidatorParams 提供了丰富的参数配置，用于控制证书链验证的各个方面。根据功能类型，可将参数分为以下几类：

- **信任锚配置**：trustedCerts、trustSystemCa、partialChain --- 定义验证的信任起点
- **证书链构建**：untrustedCerts、allowDownloadIntermediateCa --- 辅助构建完整的证书链
- **时间验证**：date、validateDate --- 控制证书有效期的验证方式
- **扩展验证**：hostnames、emailAddresses、keyUsage --- 验证证书的具体用途和属性
- **特殊场景**：ignoreErrs、userId --- 处理特殊验证需求，如测试环境或国密证书
- **吊销检查**：revokedParams --- 检查证书是否已被吊销

**X509CertValidatorParams 参数功能说明：**

| 参数名 | 类型 | 功能作用说明 |
|--------|------|-------------|
| trustedCerts | Array\<X509Cert\> | **信任证书列表**。指定信任的根证书或中间CA证书，作为验证的信任锚点。验证时，证书链必须能追溯到这些信任证书。必须设置此参数或将trustSystemCa设为true。最大数量：100。 |
| untrustedCerts | Array\<X509Cert\> | **非信任证书列表**。提供辅助构建证书链的中间证书。这些证书仅用于构建链，不作为信任锚点。适用于服务器未发送完整证书链的场景。最大数量：100。 |
| trustSystemCa | boolean | **是否信任系统CA**。默认值为false。设为true时，使用操作系统预置的CA证书库作为信任锚。适用于验证公共网站证书，无需手动配置根证书。 |
| partialChain | boolean | **是否允许部分链验证**。默认值为false。设为true时，允许信任链中的任意证书作为信任锚，而非必须追溯到根证书。 |
| allowDownloadIntermediateCa | boolean | **是否允许从网络下载中间CA证书**。默认值为false。设为true时，当证书链缺失中间证书时，自动从证书的AIA扩展下载颁发者证书，解决证书链不完整的问题。 |
| date | string | **验证日期**。格式为YYMMDDHHMMSSZ或YYYYMMDDHHMMSSZ（长度13-15）。默认使用当前系统时间。支持自定义验证时间，适用于离线验证历史签名等场景。 |
| validateDate | boolean | **是否验证日期**。默认值为true。设为false时跳过证书有效期验证。 |
| ignoreErrs | Array\<CertResult\> | **忽略指定错误**。允许忽略特定的验证错误。例如，可使用CertResult.ERR_CERT_HAS_EXPIRED忽略证书过期错误。适用于特殊场景，如测试环境。最大数量：8。支持的错误码见下表。 |
| hostnames | Array\<string\> | **主机名列表**。验证证书的主题备用名（SAN）或通用名（CN）是否包含指定的主机名。用于HTTPS等场景，防止证书被用于非授权域名。最大数量：100，每个主机名最大长度：128。 |
| emailAddresses | Array\<string\> | **邮箱地址列表**。验证证书是否包含指定的邮箱地址。目前仅支持1个邮箱。用于S/MIME邮件加密签名等场景。最大长度：128。 |
| keyUsage | Array\<KeyUsageType\> | **密钥用途列表**。验证证书的密钥用途扩展是否包含指定的用途。确保证书用于预期目的，如数字签名、数据加密、证书签发等。最大数量：9。 |
| userId | Uint8Array | **SM2用户ID**。用于验证国密SM2证书时设置签名验证所需的用户标识符。最大长度：128。 |
| revokedParams | X509CertRevokedParams | **吊销检查参数**。用于检查证书是否被吊销。包含CRL列表、OCSP响应数据、是否允许在线检查等配置。 |

**ignoreErrs 支持忽略的错误码说明：**

| 错误码 | 常量名 | 值 | 说明 |
|--------|--------|-----|------|
| 19030003 | CERT_NOT_YET_VALID | 证书未生效 | 证书的生效时间在验证时间之后 |
| 19030004 | CERT_HAS_EXPIRED | 证书已过期 | 证书的过期时间在验证时间之前 |
| 19030011 | CERT_UNKNOWN_CRITICAL_EXTENSION | 未知的关键扩展 | 证书包含无法处理的关键扩展 |
| 19030015 | CRL_NOT_FOUND | 未找到CRL | 无法获取证书吊销列表 |
| 19030016 | CRL_NOT_YET_VALID | CRL未生效 | CRL的生效时间在验证时间之后 |
| 19030017 | CRL_HAS_EXPIRED | CRL已过期 | CRL的过期时间在验证时间之前 |
| 19030020 | OCSP_RESPONSE_NOT_FOUND | 未找到OCSP响应 | 无法获取OCSP响应数据 |
| 19030024 | NETWORK_TIMEOUT | 网络超时 | 网络连接或传输超时 |

**说明**：
- 以上8种错误码可以通过 ignoreErrs 参数指定忽略，其他错误码不支持忽略。
- 忽略错误后验证将继续进行后续校验。

**X509CertRevokedParams 吊销检查参数功能说明：**

| 参数名 | 类型 | 功能作用说明 |
|--------|------|-------------|
| revocationFlags | Array\<CertRevocationFlag\> | **吊销检查标志**。必填参数。设置吊销检查策略：PREFER_OCSP（优先OCSP）、CRL_CHECK（使用CRL）、OCSP_CHECK（使用OCSP）、CHECK_ALL_CERT（检查所有证书）。数量范围：[1, 4]。 |
| crls | Array\<X509CRL\> | **CRL列表**。提供用于验证的证书吊销列表。如果匹配的CRL存在，则跳过下载。最大数量：100。 |
| allowDownloadCrl | boolean | **是否允许下载CRL**。默认值为false。设为true时，从证书的CRL分发点扩展下载CRL。 |
| ocspResponses | Array\<Uint8Array\> | **OCSP响应数据**。预置的OCSP响应数据。如果找到匹配的OCSP响应，则跳过在线检查。最大数量：100。 |
| allowOcspCheckOnline | boolean | **是否允许在线OCSP检查**。默认值为false。设为true时，从证书的AIA扩展获取OCSP URL并发送请求。 |
| ocspDigest | OcspDigest | **OCSP摘要算法**。默认值为SHA256。设置OCSP请求使用的摘要算法（SHA1/SHA224/SHA256/SHA384/SHA512）。 |

**CertRevocationFlag 吊销检查标志详细规则：**

| 标志值 | 常量名 | 作用说明 |
|--------|--------|----------|
| 0 | CERT_REVOCATION_PREFER_OCSP | **优先OCSP**。仅当同时启用CRL_CHECK和OCSP_CHECK时有效，改变检查优先级。设置后先执行OCSP检查，未找到响应或超时时回退CRL；不设置则先执行CRL检查，未找到CRL或超时时回退OCSP。 |
| 1 | CERT_REVOCATION_CRL_CHECK | **启用CRL检查**。使用证书吊销列表检查证书状态。首先使用预置的crls参数，未匹配时若allowDownloadCrl=true则从CDP扩展下载CRL。 |
| 2 | CERT_REVOCATION_OCSP_CHECK | **启用OCSP检查**。使用在线证书状态协议检查证书状态。首先使用预置的ocspResponses参数，未匹配时若allowOcspCheckOnline=true则从AIA扩展获取OCSP URL并发送请求。 |
| 3 | CERT_REVOCATION_CHECK_ALL_CERT | **检查所有证书**。设置后对证书链中所有证书执行吊销检查（跳过自签名证书）；不设置则仅检查终端证书（证书链第一个证书）。 |

**参数校验规则：**

- revocationFlags数量范围：[1, 4]，必须设置至少一个标志
- 必须设置CRL_CHECK或OCSP_CHECK（不能仅设置PREFER_OCSP或CHECK_ALL_CERT）
- userId参数与吊销检查不能同时使用（互斥）

**组合使用示例：**

| revocationFlags组合 | 执行逻辑 |
|---------------------|----------|
| `[CRL_CHECK]` | 仅CRL检查，无回退机制 |
| `[OCSP_CHECK]` | 仅OCSP检查，无回退机制 |
| `[CRL_CHECK, OCSP_CHECK]` | 先CRL检查，未找到CRL或网络超时时回退OCSP；若CRL校验发现证书被吊销则直接返回错误不回退 |
| `[PREFER_OCSP, CRL_CHECK, OCSP_CHECK]` | 先OCSP检查，未找到OCSP响应或网络超时时回退CRL；若OCSP校验发现证书被吊销则直接返回错误不回退 |
| `[CRL_CHECK, CHECK_ALL_CERT]` | 对证书链所有证书执行CRL检查（跳过自签名证书） |
| `[PREFER_OCSP, CRL_CHECK, OCSP_CHECK, CHECK_ALL_CERT]` | 对所有证书优先OCSP检查，未找到响应或超时时回退CRL |

**回退机制说明：**

回退仅发生在资源获取失败（未找到CRL/OCSP响应或网络超时），校验失败（如证书被吊销）不会回退。

| 优先方式 | 回退条件（资源获取失败） | 不回退条件（校验失败） | 回退目标 |
|----------|--------------------------|------------------------|----------|
| OCSP优先（PREFER_OCSP） | OCSP_RESPONSE_NOT_FOUND 或 NETWORK_TIMEOUT | CERT_REVOKED、OCSP_SIGNATURE_FAILURE等 | CRL检查 |
| CRL优先（无PREFER_OCSP） | CRL_NOT_FOUND 或 NETWORK_TIMEOUT | CERT_REVOKED、CRL_SIGNATURE_FAILURE等 | OCSP检查 |

**说明**：
- 回退机制仅针对资源获取失败的场景，确保吊销检查尽可能完成。
- 如果校验发现证书确实被吊销或签名验证失败，直接返回错误，不会回退到另一种检查方式。

**VerifyCertResult 返回结果说明：**

| 参数名 | 类型 | 说明 |
|--------|------|------|
| certChain | Array\<X509Cert\> | **验证后的证书链**。验证成功时返回完整的证书链，从终端证书到信任锚点。可用于后续的证书信息查询或其他验证操作。 |
| errorMsg | string | **错误信息**。验证失败时返回详细的错误信息，包含参数名和失败原因。 |

### 1.2 功能概述

本次需求新增 `validate(cert: X509Cert, params: X509CertValidatorParams): Promise<VerifyCertResult>` 接口，提供以下功能：

| 功能 | 说明 |
|------|------|
| 信任证书列表 | 提供信任的根证书用于验证 |
| 非信任证书列表 | 提供中间证书辅助构建证书链 |
| 系统CA信任 | 信任系统预置的CA证书 |
| AIA自动下载中间证书 | 自动下载缺失的中间证书 |
| 日期验证 | 验证证书有效期 |
| 主机名验证 | 验证证书主机名匹配 |
| 邮箱验证 | 验证证书邮箱地址匹配 |
| 密钥用途验证 | 验证证书密钥用途匹配 |
| 网络超时处理 | 下载超时检测和错误返回 |
| DoS防护 | 下载次数限制防止攻击 |
| 部分链验证 | 允许部分证书链验证 |
| 忽略错误码 | 忽略指定验证错误 |
| SM2用户ID | 国密SM2证书验证支持 |
| 吊销检查（CRL） | 通过CRL检查证书是否被吊销 |
| 吊销检查（CRL下载） | 从CDP扩展下载CRL |
| 吊销检查（OCSP） | 通过OCSP检查证书是否被吊销 |
| 吊销检查（OCSP在线） | 在线OCSP检查 |
| 详细错误信息 | 返回参数名和失败原因 |
| 参数范围校验 | 统一的参数范围限制 |

### 1.3 代码量统计

| 模块 | 文件数 | 行数 |
|------|--------|------|
| Adapter层 (OpenSSL适配) | 1 | 1711 行 |
| NAPI层 (JS接口绑定) | 5 | 2497 行 |
| 接口层 (Inner API) | 1 | 140 行 |
| Core层 (核心框架) | 1 | 229 行 |
| **总计** | **8** | **4577 行** |

## 2 实现方案

### 2.1 JS接口

#### 2.1.1 接口定义

**CertChainValidator 类**

```typescript
interface CertChainValidator {
    // 原有接口：验证证书链
    validate(certChain: CertChainData, callback: AsyncCallback<void>): void;
    validate(certChain: CertChainData): Promise<void>;

    // 新增接口：带参数验证单个证书
    validate(cert: X509Cert, params: X509CertValidatorParams): Promise<VerifyCertResult>;

    // 获取算法名称
    readonly algorithm: string;
}
```

**创建验证器**

```typescript
function createCertChainValidator(algorithm: string): CertChainValidator;
```

- 参数 `algorithm`：验证器类型，目前仅支持 "PKIX"
- 返回值：CertChainValidator 实例

#### 2.1.2 参数结构定义

**X509CertValidatorParams 参数结构**

```typescript
interface X509CertValidatorParams {
    // 信任证书列表（必填，或设置trustSystemCa为true）
    trustedCerts?: Array<X509Cert>;
    // 非信任证书列表（用于提供中间证书）
    untrustedCerts?: Array<X509Cert>;
    // 是否信任系统CA证书
    trustSystemCa?: boolean;
    // 是否允许部分链验证
    partialChain?: boolean;
    // 是否允许自动下载中间证书（核心特性）
    allowDownloadIntermediateCa?: boolean;
    // 验证日期（字符串格式，长度13-15）
    date?: string;
    // 是否验证日期
    validateDate?: boolean;
    // 忽略的错误码列表
    ignoreErrs?: Array<CertResult>;
    // 主机名列表
    hostnames?: Array<string>;
    // 邮箱地址列表
    emailAddresses?: Array<string>;
    // 密钥用途列表
    keyUsage?: Array<KeyUsageType>;
    // SM2用户ID
    userId?: Uint8Array;
    // 吊销检查参数
    revokedParams?: X509CertRevokedParams;
}
```

**X509CertRevokedParams 吊销检查参数**

```typescript
interface X509CertRevokedParams {
    // 吊销检查标志（必填，数量范围[1, 4]）
    revocationFlags: Array<CertRevocationFlag>;
    // CRL列表
    crls?: Array<X509CRL>;
    // 是否允许下载CRL
    allowDownloadCrl?: boolean;
    // OCSP响应数据
    ocspResponses?: Array<Uint8Array>;
    // 是否允许在线OCSP检查
    allowOcspCheckOnline?: boolean;
    // OCSP摘要算法
    ocspDigest?: OcspDigest;
}
```

**VerifyCertResult 结果结构**

```typescript
interface VerifyCertResult {
    // 验证后的证书链
    readonly certChain: Array<X509Cert>;
}
```

#### 2.1.3 枚举类型定义

**KeyUsageType 密钥用途枚举**

```typescript
enum KeyUsageType {
    KEYUSAGE_DIGITAL_SIGNATURE = 0,    // 数字签名
    KEYUSAGE_NON_REPUDIATION = 1,      // 不可否认
    KEYUSAGE_KEY_ENCIPHERMENT = 2,     // 密钥加密
    KEYUSAGE_DATA_ENCIPHERMENT = 3,    // 数据加密
    KEYUSAGE_KEY_AGREEMENT = 4,        // 密钥协商
    KEYUSAGE_KEY_CERT_SIGN = 5,        // 证书签名
    KEYUSAGE_CRL_SIGN = 6,             // CRL签名
    KEYUSAGE_ENCIPHER_ONLY = 7,        // 仅加密
    KEYUSAGE_DECIPHER_ONLY = 8         // 仅解密
}
```

**CertRevocationFlag 吊销检查标志枚举**

```typescript
enum CertRevocationFlag {
    CERT_REVOCATION_PREFER_OCSP = 0,    // 优先使用OCSP
    CERT_REVOCATION_CRL_CHECK = 1,      // 使用CRL检查
    CERT_REVOCATION_OCSP_CHECK = 2,     // 使用OCSP检查
    CERT_REVOCATION_CHECK_ALL_CERT = 3  // 检查所有证书
}
```

**OcspDigest OCSP摘要算法枚举**

```typescript
enum OcspDigest {
    SHA1 = 0,
    SHA224 = 1,
    SHA256 = 2,
    SHA384 = 3,
    SHA512 = 4
}
```

**CertResult 错误码枚举**

```typescript
enum CertResult {
    INVALID_PARAMS = 401,
    NOT_SUPPORT = 801,
    ERR_OUT_OF_MEMORY = 19020001,
    ERR_RUNTIME_ERROR = 19020002,
    ERR_PARAMETER_CHECK_FAILED = 19020003,
    ERR_CRYPTO_OPERATION = 19030001,
    ERR_CERT_SIGNATURE_FAILURE = 19030002,
    ERR_CERT_NOT_YET_VALID = 19030003,
    ERR_CERT_HAS_EXPIRED = 19030004,
    ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 19030005,
    ERR_KEYUSAGE_NO_CERTSIGN = 19030006,
    ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE = 19030007,
    ERR_CERT_UNTRUSTED = 19030009,
    ERR_CERT_HAS_REVOKED = 19030010,
    ERR_UNKNOWN_CRITICAL_EXTENSION = 19030011,
    ERR_CERT_HOSTNAME_MISMATCH = 19030012,
    ERR_CERT_EMAIL_ADDRESS_MISMATCH = 19030013,
    ERR_CERT_KEYUSAGE_MISMATCH = 19030014,
    ERR_CRL_NOT_FOUND = 19030015,
    ERR_CRL_NOT_YET_VALID = 19030016,
    ERR_CRL_HAS_EXPIRED = 19030017,
    ERR_CRL_SIGNATURE_FAILURE = 19030018,
    ERR_CRL_ISSUER_NOT_FOUND = 19030019,
    ERR_OCSP_RESPONSE_NOT_FOUND = 19030020,
    ERR_OCSP_RESPONSE_INVALID = 19030021,
    ERR_OCSP_SIGNATURE_FAILURE = 19030022,
    ERR_OCSP_VERIFY_FAILED = 19030023,
    ERR_OCSP_CERT_STATUS_UNKNOWN = 19030024,
    ERR_NETWORK_TIMEOUT = 19030025,
}
```

#### 2.1.4 使用示例

**示例1：基本使用（AIA自动下载）**

```typescript
import cert from '@ohos.security.cert';

// 创建证书链验证器
let validator = cert.createCertChainValidator("PKIX");

// 准备验证参数
let params = {
    trustedCerts: [rootCert],                    // 信任的根证书
    allowDownloadIntermediateCa: true,           // 启用自动下载中间证书
    validateDate: true                            // 验证日期
};

// 验证证书
try {
    let result = await validator.validate(leafCert, params);
    console.log("Verification succeeded");
    console.log("Certificate chain length:", result.certChain.length);
} catch (err) {
    console.log("Verification failed:", err.code, err.message);
}
```

**示例2：完整参数**

```typescript
let params = {
    trustedCerts: [rootCert],
    untrustedCerts: [intermediateCert1, intermediateCert2],
    trustSystemCa: false,
    allowDownloadIntermediateCa: true,
    validateDate: true,
    date: "20241231235959Z",
    hostnames: ["example.com", "www.example.com"],
    emailAddresses: ["admin@example.com"],
    keyUsage: [cert.KeyUsageType.KEYUSAGE_DIGITAL_SIGNATURE]
};

let result = await validator.validate(leafCert, params);
```

**示例3：使用系统CA**

```typescript
let params = {
    trustSystemCa: true,                         // 使用系统预置CA
    allowDownloadIntermediateCa: true,
    hostnames: ["www.example.com"]
};

let result = await validator.validate(leafCert, params);
```

**示例4：吊销检查**

```typescript
let params = {
    trustedCerts: [rootCert],
    revokedParams: {
        revocationFlags: [
            cert.CertRevocationFlag.CERT_REVOCATION_PREFER_OCSP,
            cert.CertRevocationFlag.CERT_REVOCATION_CRL_CHECK
        ],
        allowDownloadCrl: true,
        allowOcspCheckOnline: true
    }
};

let result = await validator.validate(leafCert, params);
```

**示例5：忽略错误**

```typescript
let params = {
    trustedCerts: [rootCert],
    ignoreErrs: [cert.CertResult.ERR_CERT_HAS_EXPIRED]  // 忽略证书过期错误
};

let result = await validator.validate(leafCert, params);
```

### 2.2 Inner C接口

#### 2.2.1 核心数据结构

**验证参数结构体 HcfX509CertValidatorParams**

```c
typedef struct {
    HcfX509CertificateArray untrustedCerts;    // 非信任证书列表
    HcfX509CertificateArray trustedCerts;      // 信任证书列表
    bool trustSystemCa;                        // 是否信任系统CA
    bool partialChain;                         // 是否允许部分链验证
    bool allowDownloadIntermediateCa;          // 是否允许下载中间证书
    bool validateDate;                         // 是否验证日期
    char *date;                                // 验证日期字符串
    HcfInt32Array ignoreErrs;                  // 忽略的错误码列表
    HcfStringArray hostnames;                  // 主机名列表
    HcfStringArray emailAddresses;             // 邮箱地址列表
    HcfInt32Array keyUsage;                    // 密钥用途列表
    CfBlob userId;                             // 用户ID
    HcfX509CertRevokedParams *revokedParams;   // 吊销检查参数
} HcfX509CertValidatorParams;
```

**验证结果结构体 HcfVerifyCertResult**

```c
#define MAX_VERIFY_ERROR_MSG_LEN 512

typedef struct {
    HcfX509CertificateArray certs;               // 验证后的证书链
    char errorMsgBuf[MAX_VERIFY_ERROR_MSG_LEN];  // 错误信息缓冲区
    const char *errorMsg;                        // 错误信息
} HcfVerifyCertResult;
```

**吊销检查参数结构体 HcfX509CertRevokedParams**

```c
typedef struct {
    HcfInt32Array revocationFlags;    // 吊销检查标志
    HcfX509CrlArray crls;             // CRL列表
    bool allowDownloadCrl;            // 是否允许下载CRL
    bool allowOcspCheckOnline;        // 是否允许在线OCSP检查
    CfBlobArray ocspResponses;        // OCSP响应数据
    int32_t ocspDigest;               // OCSP摘要算法
} HcfX509CertRevokedParams;
```

**证书链验证器接口 HcfCertChainValidator**

```c
struct HcfCertChainValidator {
    struct CfObjectBase base;

    // 验证证书链（原有接口）
    CfResult (*validate)(HcfCertChainValidator *self,
                         const HcfCertChainData *certChainData);

    // 获取算法名称
    const char *(*getAlgorithm)(HcfCertChainValidator *self);

    // 验证单个X509证书（新增接口）
    CfResult (*validateX509Cert)(HcfCertChainValidator *self,
                                 HcfX509Certificate *cert,
                                 const HcfX509CertValidatorParams *params,
                                 HcfVerifyCertResult *result);
};
```

**创建函数**

```c
CfResult HcfCertChainValidatorCreate(const char *algorithm,
                                     HcfCertChainValidator **pathValidator);
```

#### 2.2.2 参数范围常量定义

```c
// 吊销检查标志数量范围
#define MAX_REVOCATION_FLAG_COUNT 4

// CRL最大数量
#define MAX_CRL_COUNT 100

// OCSP响应最大数量
#define MAX_OCSP_RESPONSE_COUNT 100

// 非信任证书最大数量
#define MAX_UNTRUSTED_CERT_COUNT 100

// 信任证书最大数量
#define MAX_TRUSTED_CERT_COUNT 100

// 忽略错误最大数量（支持8种错误码）
#define MAX_IGNORE_ERR_COUNT 8

// 主机名最大数量
#define MAX_HOSTNAMES_COUNT 100

// 邮箱地址最大数量
#define MAX_EMAIL_ADDRESS_COUNT 1

// 主机名最大长度
#define MAX_HOSTNAME_LENGTH 128

// 邮箱地址最大长度
#define MAX_EMAIL_ADDRESS_LENGTH 128

// 用户ID最大长度
#define MAX_USER_ID_LEN 128

// 密钥用途最大数量
#define MAX_KEYUSAGE_COUNT 9

// 日期字符串长度范围
#define MIN_DATE_LEN 13
#define MAX_DATE_LEN 15

// 验证错误信息最大长度
#define MAX_VERIFY_ERROR_MSG_LEN 512
```

#### 2.2.3 NapiParamInfo结构体

```c
typedef struct NapiParamInfo {
    const char *name;               // 参数名
    bool mustExist;                 // 是否必须存在
    int minLen;                     // 最小长度
    int maxLen;                     // 最大长度
    struct NapiParamInfo *innerParams; // 数组元素参数描述
} NapiParamInfo;
```

**NapiParamInfo使用示例：**

```c
// 字符串参数
NapiParamInfo dateInfo = { "date", false, MIN_DATE_LEN, MAX_DATE_LEN, NULL };
ret = NapiGetStringValueEx(env, arg, &dateInfo, param.date, errMsg);

// 数组参数（带元素约束）
NapiParamInfo hostnameElemInfo = { NULL, true, 1, MAX_HOSTNAME_LENGTH, NULL };
NapiParamInfo hostnamesInfo = { "hostnames", false, 1, MAX_HOSTNAMES_COUNT, &hostnameElemInfo };
ret = NapiGetStringArrayEx(env, arg, &hostnamesInfo, param.hostnames, errMsg);
```

#### 2.2.4 辅助类型定义

```c
// 整数数组
typedef struct {
    int32_t *data;
    uint32_t count;
} HcfInt32Array;

// 字符串数组
typedef struct {
    char **data;
    uint32_t count;
} HcfStringArray;

// 证书数组
typedef struct {
    HcfX509Certificate **data;
    uint32_t count;
} HcfX509CertificateArray;

// CRL数组
typedef struct {
    HcfX509Crl **data;
    uint32_t count;
} HcfX509CrlArray;

// Blob数组
typedef struct {
    CfBlob *data;
    uint32_t count;
} CfBlobArray;
```

#### 2.2.5 枚举类型定义

**吊销检查标志 HcfCertRevocationFlag**

```c
typedef enum {
    CERT_REVOCATION_PREFER_OCSP     = 0,
    CERT_REVOCATION_CRL_CHECK       = 1,
    CERT_REVOCATION_OCSP_CHECK      = 2,
    CERT_REVOCATION_CHECK_ALL_CERT  = 3,
} HcfCertRevocationFlag;
```

**OCSP摘要算法 HcfOcspDigest**

```c
typedef enum {
    OCSP_DIGEST_SHA1   = 0,
    OCSP_DIGEST_SHA224 = 1,
    OCSP_DIGEST_SHA256 = 2,
    OCSP_DIGEST_SHA384 = 3,
    OCSP_DIGEST_SHA512 = 4
} HcfOcspDigest;
```

#### 2.2.6 错误码定义 CfResult

```c
typedef enum CfResult {
    CF_SUCCESS = 0,
    CF_INVALID_PARAMS = -10001,
    CF_NOT_SUPPORT = -10002,
    CF_NULL_POINTER = -10003,
    CF_NOT_EXIST = -10004,

    CF_ERR_MALLOC = -20001,
    CF_ERR_COPY = -20002,
    CF_ERR_NAPI = -20003,
    CF_ERR_INTERNAL = -20004,
    CF_ERR_PARAMETER_CHECK = -20005,

    CF_ERR_CRYPTO_OPERATION = -30001,
    CF_ERR_CERT_SIGNATURE_FAILURE = -30002,
    CF_ERR_CERT_NOT_YET_VALID = -30003,
    CF_ERR_CERT_HAS_EXPIRED = -30004,
    CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = -30005,
    CF_ERR_KEYUSAGE_NO_CERTSIGN = -30006,
    CF_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE = -30007,
    CF_ERR_CERT_UNTRUSTED = -30014,
    CF_ERR_CERT_REVOKED = -30015,
    CF_ERR_CERT_UNKNOWN_CRITICAL_EXTENSION = -30016,
    CF_ERR_HOSTNAME_NOT_MATCHED = -30017,
    CF_ERR_EMAIL_NOT_MATCHED = -30018,
    CF_ERR_KEYUSAGE_NOT_MATCHED = -30019,
    CF_ERR_CRL_NOT_FOUND = -30020,
    CF_ERR_CRL_NOT_YET_VALID = -30021,
    CF_ERR_CRL_HAS_EXPIRED = -30022,
    CF_ERR_CRL_SIGNATURE_FAILURE = -30023,
    CF_ERR_UNABLE_TO_GET_CRL_ISSUER = -30024,
    CF_ERR_OCSP_RESPONSE_NOT_FOUND = -30025,
    CF_ERR_OCSP_RESPONSE_INVALID = -30026,
    CF_ERR_OCSP_SIGNATURE_FAILURE = -30027,
    CF_ERR_OCSP_CERT_STATUS_UNKNOWN = -30029,
    CF_ERR_NETWORK_TIMEOUT = -30030,
} CfResult;
```

#### 2.2.7 忽略错误码定义

**可忽略的错误码常量（用于ignoreErrs参数）：**

```c
// 用于 ignoreErrs 参数的错误码定义（正数，与CertResult枚举值对应）
#define CERT_NOT_YET_VALID               19030003  // 证书未生效
#define CERT_HAS_EXPIRED                 19030004  // 证书已过期
#define CERT_UNKNOWN_CRITICAL_EXTENSION  19030011  // 未知的关键扩展
#define CRL_NOT_FOUND                    19030015  // 未找到CRL
#define CRL_NOT_YET_VALID                19030016  // CRL未生效
#define CRL_HAS_EXPIRED                  19030017  // CRL已过期
#define OCSP_RESPONSE_NOT_FOUND          19030020  // 未找到OCSP响应
#define NETWORK_TIMEOUT                  19030024  // 网络超时
```

**OpenSSL错误码映射：**

```c
// OpenSSL X509验证错误与可忽略错误码的映射关系
static const OpensslErrorToResult X509_VERIFY_IGNORE_ERR_MAP[] = {
    {X509_V_ERR_CERT_NOT_YET_VALID,        CERT_NOT_YET_VALID},
    {X509_V_ERR_CERT_HAS_EXPIRED,          CERT_HAS_EXPIRED},
    {X509_V_ERR_CRL_NOT_YET_VALID,         CRL_NOT_YET_VALID},
    {X509_V_ERR_CRL_HAS_EXPIRED,           CRL_HAS_EXPIRED},
    {X509_V_ERR_UNABLE_TO_GET_CRL,         CRL_NOT_FOUND},
    {X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION, CERT_UNKNOWN_CRITICAL_EXTENSION},
};
```

**说明**：
- ignoreErrs参数使用正数错误码（如19030003），与CertResult枚举值对应。
- OCSP_RESPONSE_NOT_FOUND和NETWORK_TIMEOUT在吊销检查时单独处理，不参与OpenSSL验证回调。
- 最大支持忽略8种错误，但实际可用的错误码为上述8种。

### 2.3 NAPI层实现

#### 2.3.1 参数获取函数

**NapiGetXxxEx系列函数：**

```c
// 获取布尔值（无长度校验）
CfResult NapiGetBoolValueEx(napi_env env, napi_value arg, const char *name, 
    bool &value, char **errMsg);

// 获取字符串（支持长度校验和错误信息）
CfResult NapiGetStringValueEx(napi_env env, napi_value arg, 
    const NapiParamInfo *info, char *&value, char **errMsg);

// 获取Blob（支持长度校验）
CfResult NapiGetBlobValueEx(napi_env env, napi_value arg, 
    const NapiParamInfo *info, CfBlob &value, char **errMsg);

// 获取数组基础信息
CfResult NapiGetArrayBaseInfoEx(napi_env env, napi_value arg, 
    const NapiParamInfo *info, napi_value &arrayObj, uint32_t &length, char **errMsg);

// 获取字符串数组（支持元素长度校验）
CfResult NapiGetStringArrayEx(napi_env env, napi_value arg, 
    const NapiParamInfo *info, HcfStringArray &value, char **errMsg);

// 获取Blob数组
CfResult NapiGetBlobArrayEx(napi_env env, napi_value arg, 
    const NapiParamInfo *info, CfBlobArray &value, char **errMsg);

// 获取整数数组
CfResult NapiGetInt32ArrayEx(napi_env env, napi_value arg, 
    const NapiParamInfo *info, HcfInt32Array &value, char **errMsg);

// 获取整数（无长度校验）
CfResult NapiGetInt32ExEx(napi_env env, napi_value arg, const char *name, 
    int32_t &value, char **errMsg);
```

#### 2.3.2 错误信息构建

```c
static void SetBuildParamError(char **errMsg, const char *format, ...)
{
    if (errMsg == nullptr) {
        return;
    }
    char *buf = static_cast<char *>(CfMallocEx(MAX_BUILD_PARAM_ERR_MSG_LEN));
    if (buf == nullptr) {
        return;
    }
    va_list args;
    va_start(args, format);
    (void)vsnprintf_s(buf, MAX_BUILD_PARAM_ERR_MSG_LEN, MAX_BUILD_PARAM_ERR_MSG_LEN - 1, format, args);
    va_end(args);
    *errMsg = buf;
}
```

**错误信息格式示例：**

```
'trustSystemCa': get bool failed
'date': value len is invalid, should be in [13, 15]
'hostnames': element 0 length is invalid, should be in [1, 128]
'keyUsage': length 10 is invalid, should be in [1, 9]
```

#### 2.3.3 参数解析示例

```c
static CfResult GetArrayParamsEx(napi_env env, napi_value arg, 
    HcfX509CertValidatorParams &param, char **errMsg)
{
    NapiParamInfo trustedCertInfo = { 
        CERT_VALIDATOR_TAG_TRUSTED_CERTS.c_str(), false, 0, MAX_TRUSTED_CERT_COUNT, NULL 
    };
    CfResult ret = GetCertArrayFromNapiValueEx(env, arg, &trustedCertInfo, 
        param.trustedCerts, errMsg);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        return ret;
    }

    NapiParamInfo hostnameElemInfo = { NULL, true, 1, MAX_HOSTNAME_LENGTH, NULL };
    NapiParamInfo hostnamesInfo = { 
        CERT_VALIDATOR_TAG_HOSTNAMES.c_str(), false, 1, MAX_HOSTNAMES_COUNT, 
        &hostnameElemInfo 
    };
    ret = NapiGetStringArrayEx(env, arg, &hostnamesInfo, param.hostnames, errMsg);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        return ret;
    }

    NapiParamInfo keyUsageInfo = { 
        CERT_VALIDATOR_TAG_KEY_USAGE.c_str(), false, 1, MAX_KEYUSAGE_COUNT, NULL 
    };
    ret = NapiGetInt32ArrayEx(env, arg, &keyUsageInfo, param.keyUsage, errMsg);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        return ret;
    }

    return CF_SUCCESS;
}
```

### 2.4 实现逻辑

#### 2.4.1 架构层次

```
┌─────────────────────────────────────────────────────────────────┐
│                      JS Application Layer                        │
│                    (ArkTS/TypeScript)                            │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                        NAPI Layer                                │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ napi_cert_chain_validator.cpp                             │  │
│  │ - CreateCertChainValidator()                              │  │
│  │ - Validate() / ValidateX509Cert()                         │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ napi_x509_cert_chain_validate_params.cpp                  │  │
│  │ - BuildX509CertValidatorParams()                          │  │
│  │ - 参数解析和转换 (使用NapiParamInfo)                        │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ napi_x509_cert_chain_validate_result.cpp                  │  │
│  │ - BuildVerifyCertResultJS()                               │  │
│  │ - 结果构建和返回                                           │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ napi_common.cpp                                           │  │
│  │ - NapiParamInfo结构体定义                                  │  │
│  │ - NapiGetXxxEx系列函数                                    │  │
│  │ - SetBuildParamError错误信息构建                           │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ napi_cert_crl_common.cpp                                  │  │
│  │ - CRL相关公共方法                                          │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Core Layer                                │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ cert_chain_validator.c                                    │  │
│  │ - HcfCertChainValidatorCreate()                           │  │
│  │ - 验证器创建和分发                                         │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ cert_chain_validator_spi.h                                │  │
│  │ - SPI接口定义                                              │  │
│  │ - engineValidateX509Cert()                                │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Adapter Layer                               │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ x509_cert_chain_validator_openssl.c                       │  │
│  │                                                           │  │
│  │ 核心验证函数:                                              │  │
│  │ - ValidateX509Cert()         入口函数                      │  │
│  │ - BuildAndVerifyCertChain()  核心验证+下载重试             │  │
│  │                                                           │  │
│  │ 参数校验函数:                                               │  │
│  │ - CheckCertValidatorParams()  参数范围校验                 │  │
│  │                                                           │  │
│  │ AIA下载函数:                                               │  │
│  │ - DownloadAndAddIntermediateCert()  下载中间证书入口        │  │
│  │ - TryDownloadFromSingleAia()        尝试从单个AIA下载       │  │
│  │ - DownloadCertFromAiaUrl()          从URL下载证书           │  │
│  │                                                           │  │
│  │ 吊销检查函数:                                               │  │
│  │ - CheckCertRevocation()       吊销检查入口                 │  │
│  │ - CheckSingleCertByCrl()      CRL检查                      │  │
│  │ - CheckSingleCertByOcsp()     OCSP检查                     │  │
│  │ - DownloadCrlFromCdp()        CRL下载                      │  │
│  │ - PerformOnlineOcspCheck()    在线OCSP检查                 │  │
│  │                                                           │  │
│  │ 参数处理函数:                                               │  │
│  │ - ParseOpenSSLParams()        解析OpenSSL参数              │  │
│  │ - ConstructTrustedStore()     构建信任存储                 │  │
│  │ - ConstructUntrustedStack()   构建非信任栈                 │  │
│  │ - CheckCertValidatorExtensions() 扩展检查                  │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                     OpenSSL Library                              │
│  X509_verify_cert()      - 证书链验证                            │
│  X509_load_http()        - HTTP下载证书                          │
│  X509_CRL_load_http()    - HTTP下载CRL                           │
│  X509_get_ext_d2i()      - 获取扩展                              │
│  X509_check_host()       - 主机名检查                            │
│  X509_check_email()      - 邮箱检查                              │
│  X509_self_signed()      - 自签名检查                            │
│  OCSP_sendreq_bio()      - 发送OCSP请求                          │
│  OCSP_basic_verify()     - OCSP签名验证                          │
│  ERR_peek_error()        - 错误获取                              │
└─────────────────────────────────────────────────────────────────┘
```

#### 2.4.2 参数校验流程

```c
static CfResult CheckCertValidatorParams(const HcfX509CertValidatorParams *params,
    CertVerifyResultInner *result)
{
    // 1. 检查信任锚配置
    if (params->trustedCerts.count == 0 && !params->trustSystemCa) {
        RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK,
            "Must set trustedCerts, or set trustSystemCa to true.", result);
    }

    // 2. 检查密钥用途数量
    if (params->keyUsage.count > MAX_KEYUSAGE_COUNT) {
        RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK, 
            "The number of keyUsage cannot exceed 9.", result);
    }

    // 3. 检查主机名数量
    if (params->hostnames.count > MAX_HOSTNAMES_COUNT) {
        RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK,
            "The number of hostnames cannot exceed 100.", result);
    }

    // 4. 检查邮箱地址数量
    if (params->emailAddresses.count > MAX_EMAIL_ADDRESS_COUNT) {
        RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK,
            "The number of emailAddresse cannot exceed 1.", result);
    }

    // 5. 检查吊销参数
    if (params->revokedParams != NULL) {
        if (params->revokedParams->revocationFlags.count == 0 ||
            params->revokedParams->revocationFlags.count > MAX_REVOCATION_FLAG_COUNT) {
            RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK,
                "If enabling revocation checking, the length of revocationFlags must be in [1, 4].", result);
        }
    }

    return CF_SUCCESS;
}
```

#### 2.4.2.1 忽略错误码参数解析

**ParseIgnoreErrs() 函数实现：**

```c
static CfResult ParseIgnoreErrs(const HcfX509CertValidatorParams *params,
    HcfX509CertValidatorOpenSSLParams *opensslParams, CertVerifyResultInner *resultInner)
{
    if (params->ignoreErrs.data == NULL || params->ignoreErrs.count == 0) {
        return CF_SUCCESS;
    }
    
    // 检查数量限制
    if (params->ignoreErrs.count > MAX_IGNORE_ERR_COUNT) {
        RETURN_VERIFY_ERROR(CF_ERR_PARAMETER_CHECK, 
            "Invalid ignoreErrs count, max count is 8.", resultInner);
    }
    
    // 解析忽略的错误码
    uint32_t pos = 0;
    opensslParams->ignoreOcspRespNotFound = false;
    opensslParams->ignoreNetworkTimeout = false;
    
    for (uint32_t i = 0; i < params->ignoreErrs.count; i++) {
        // OCSP响应未找到和超时错误单独处理
        if (params->ignoreErrs.data[i] == OCSP_RESPONSE_NOT_FOUND) {
            opensslParams->ignoreOcspRespNotFound = true;
            continue;
        }
        if (params->ignoreErrs.data[i] == NETWORK_TIMEOUT) {
            opensslParams->ignoreNetworkTimeout = true;
            continue;
        }
        
        // 查找OpenSSL错误码映射
        for (uint32_t j = 0; j < sizeof(X509_VERIFY_IGNORE_ERR_MAP) / sizeof(X509_VERIFY_IGNORE_ERR_MAP[0]); j++) {
            if (params->ignoreErrs.data[i] == X509_VERIFY_IGNORE_ERR_MAP[j].result) {
                opensslParams->ignoreErrs[pos++] = X509_VERIFY_IGNORE_ERR_MAP[j].errCode;
                break;
            }
        }
    }
    
    // 以0结尾，用于遍历判断结束
    opensslParams->ignoreErrs[pos] = 0;
    return CF_SUCCESS;
}
```

**VerifyCallback 验证回调函数：**

```c
static int VerifyCallback(int ret, X509_STORE_CTX *verifyCtx)
{
    // 如果验证成功，直接返回
    if (ret == 1) {
        return 1;
    }
    
    int certVerifyResult = X509_STORE_CTX_get_error(verifyCtx);
    
    // 检查是否在忽略列表中
    for (int i = 0; opensslParams->ignoreErrs[i] != 0; i++) {
        if (certVerifyResult == opensslParams->ignoreErrs[i]) {
            // 忽略该错误，记录日志后返回成功
            LOGW("The %{public}s(%{public}d) error was ignored, current cert subject name: %{public}s",
                 X509_verify_cert_error_string(certVerifyResult), certVerifyResult, 
                 GetCertSubjectName(X509_STORE_CTX_get_current_cert(verifyCtx)));
            return 1;  // 继续验证
        }
    }
    
    // 未在忽略列表中，返回原始结果
    return ret;
}
```

**说明**：
- `ignoreErrs` 数组以0结尾，便于遍历判断结束条件。
- `OCSP_RESPONSE_NOT_FOUND` 和 `NETWORK_TIMEOUT` 错误在吊销检查阶段单独处理，不参与OpenSSL验证回调。
- 验证回调函数通过 `X509_STORE_CTX_set_verify_cb()` 注册到验证上下文中。

#### 2.4.3 AIA自动下载中间证书

**下载参数配置：**

| 参数名 | 宏定义 | 值 | 说明 |
|--------|--------|-----|------|
| 中间CA下载总次数限制 | `MAX_TOTAL_DOWNLOAD_CERT_COUNT` | 5 | 单次验证最多下载5个中间证书 |
| AIA扩展遍历次数限制 | `MAX_INFO_ACCESS_TRAVERSE_COUNT` | 3 | 遍历AIA扩展的最大次数 |
| 单次下载超时 | `DOWNLOAD_TIMEOUT_SECONDS` | 3秒 | HTTP下载证书的超时时间 |

**流程说明：**

```
BuildAndVerifyCertChain() 主循环：
├── remainingCount = 5 (MAX_TOTAL_DOWNLOAD_CERT_COUNT)
├── 循环执行验证
│   ├── 调用 ExecuteSingleVerification() 执行X509_verify_cert()
│   ├── 如果验证成功 → 返回成功
│   ├── 如果错误码不是 X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY → 返回错误
│   ├── 如果 allowDownloadIntermediateCa == false → 返回错误
│   ├── remainingCount--
│   └── 调用 DownloadAndAddIntermediateCert() 下载中间证书
│       ├── 获取证书的AIA扩展 (NID_info_access)
│       ├── 遍历 ACCESS_DESCRIPTION (最多3次)
│       │   ├── 检查 method == NID_ad_ca_issuers
│       │   ├── 检查 location->type == GEN_URI
│       │   └── 调用 DownloadCertFromAiaUrl()
│       │       └── X509_load_http(url, NULL, NULL, 3秒超时)
│       └── 将下载的证书添加到 untrustedCertStack
└── 循环结束（remainingCount == 0 或下载成功）
```

#### 2.4.3 吊销检查总逻辑

**吊销检查入口函数 CheckCertRevocation()：**

```
CheckCertRevocation()：
├── 获取证书链长度 (chainLen)
├── 根据 CHECK_ALL_CERT 标志确定检查范围
│   ├── CHECK_ALL_CERT 启用 → checkCount = chainLen (检查所有证书)
│   └── CHECK_ALL_CERT 未启用 → checkCount = 1 (仅检查终端证书)
├── 遍历证书链 (for i = 0 to checkCount)
│   ├── 获取当前证书 cert = chain[i]
│   ├── 判断是否自签名证书 (X509_self_signed)
│   │   └── 是 → 跳过，继续下一个证书
│   ├── 设置颁发者证书 issuer
│   │   └── issuer = chain[i+1] (从证书链中获取)
│   ├── 调用 CheckSingleCertRevocation(cert) 执行单证书吊销检查
│   │   ├── 成功 → 继续下一个证书
│   │   └── 失败 → 添加证书主题到错误信息，返回错误
│   └── 循环结束
└── 返回 CF_SUCCESS
```

**单证书吊销检查 CheckSingleCertRevocation()：**

```
CheckSingleCertRevocation(cert)：
├── Case 1: 同时启用 CRL 和 OCSP (crlCheck && ocspCheck)
│   ├── PREFER_OCSP 启用
│   │   ├── 先调用 CheckSingleCertByOcsp()
│   │   ├── OCSP 失败且错误为 NOT_FOUND 或 TIMEOUT
│   │   │   └── 回退到 CheckSingleCertByCrl()
│   │   └── 返回结果
│   └── PREFER_OCSP 未启用 (CRL优先)
│   │   ├── 先调用 CheckSingleCertByCrl()
│   │   ├── CRL 失败且错误为 CRL_NOT_FOUND
│   │   │   └── 回退到 CheckSingleCertByOcsp()
│   │   └── 返回结果
├── Case 2: 仅启用 OCSP (ocspCheck)
│   └── 调用 CheckSingleCertByOcsp()
│   └── 返回结果
├── Case 3: 仅启用 CRL (crlCheck)
│   └── 调用 CheckSingleCertByCrl()
│   └── 返回结果
└── Case 4: 未启用吊销检查
    └── 返回 CF_SUCCESS
```

**ignoreErrs 在吊销检查中的应用：**

| 忽略错误码 | 处理逻辑 |
|------------|----------|
| OCSP_RESPONSE_NOT_FOUND | 当OCSP响应获取失败时，如果设置了忽略，则跳过该错误继续验证 |
| NETWORK_TIMEOUT | 当网络请求超时时，如果设置了忽略，则跳过该错误继续验证 |

**说明**：
- `OCSP_RESPONSE_NOT_FOUND` 和 `NETWORK_TIMEOUT` 错误仅在吊销检查阶段可能产生。
- 这两个错误码通过 `ignoreOcspRespNotFound` 和 `ignoreNetworkTimeout` 标志单独处理。
- 如果设置了忽略，吊销检查失败不会导致整体验证失败。

**吊销检查策略选择：**

| revocationFlags 组合 | 执行顺序 | 回退策略 |
|----------------------|----------|----------|
| [CRL_CHECK] | 仅 CRL | 无回退 |
| [OCSP_CHECK] | 仅 OCSP | 无回退 |
| [PREFER_OCSP, CRL_CHECK, OCSP_CHECK] | OCSP → CRL | OCSP 找不到/超时时回退 CRL |
| [CRL_CHECK, OCSP_CHECK] | CRL → OCSP | CRL 找不到时回退 OCSP |
| [CHECK_ALL_CERT] | 检查所有证书 | 无关检查方式 |

**关键代码实现：**

```c
static CfResult CheckCertRevocation(CertVerifyResultInner *result,
    const HcfX509CertValidatorParams *params, HcfX509CertValidatorOpenSSLParams *opensslParams)
{   
    int chainLen = sk_X509_num(result->certChain);
    // 根据 CHECK_ALL_CERT 标志决定检查范围
    int checkCount = opensslParams->revocationCheckAll ? chainLen : 1;
    
    for (int i = 0; i < checkCount; i++) {
        X509 *cert = sk_X509_value(result->certChain, i);
        
        // 跳过自签名证书（通常是根证书）
        if (X509_self_signed(cert, 0)) {
            continue;
        }

        // 从证书链中获取颁发者证书
        opensslParams->issuer = (i + 1 < chainLen) ? 
            sk_X509_value(result->certChain, i + 1) : NULL;

        CfResult res = CheckSingleCertRevocation(cert, params, opensslParams, result);
        if (res != CF_SUCCESS) {
            // 将证书主题添加到错误信息中
            AppendCertSubjectToErrorMsg(cert, result);
            return res;
        }
    }

    return CF_SUCCESS;
}

static CfResult CheckSingleCertRevocation(X509 *cert,
    const HcfX509CertValidatorParams *params,
    HcfX509CertValidatorOpenSSLParams *opensslParams,
    CertVerifyResultInner *result)
{
    CfResult res;
    
    // Case 1: 同时启用 CRL 和 OCSP
    if (opensslParams->crlCheck && opensslParams->ocspCheck) {
        if (opensslParams->preferOcsp) {
            // OCSP 优先策略
            res = CheckSingleCertByOcsp(cert, params, opensslParams, result);
            if (res == CF_ERR_OCSP_RESPONSE_NOT_FOUND || res == CF_ERR_NETWORK_TIMEOUT) {
                // OCSP 找不到或超时，回退到 CRL
                res = CheckSingleCertByCrl(cert, params, opensslParams, result);
            }
        } else {
            // CRL 优先策略
            res = CheckSingleCertByCrl(cert, params, opensslParams, result);
            if (res == CF_ERR_CRL_NOT_FOUND) {
                // CRL 找不到，回退到 OCSP
                res = CheckSingleCertByOcsp(cert, params, opensslParams, result);
            }
        }
        return res;
    }
    
    // Case 2: 仅 OCSP
    if (opensslParams->ocspCheck) {
        return CheckSingleCertByOcsp(cert, params, opensslParams, result);
    }
    
    // Case 3: 仅 CRL
    if (opensslParams->crlCheck) {
        return CheckSingleCertByCrl(cert, params, opensslParams, result);
    }
    
    // Case 4: 未启用吊销检查
    return CF_SUCCESS;
}
```

**吊销检查参数解析：**

```c
// 从 revocationFlags 解析检查策略
static void ParseRevocationFlags(const HcfInt32Array *flags, 
    HcfX509CertValidatorOpenSSLParams *opensslParams)
{
    opensslParams->crlCheck = false;
    opensslParams->ocspCheck = false;
    opensslParams->preferOcsp = false;
    opensslParams->revocationCheckAll = false;
    
    for (uint32_t i = 0; i < flags->count; i++) {
        switch (flags->data[i]) {
            case CERT_REVOCATION_PREFER_OCSP:
                opensslParams->preferOcsp = true;
                break;
            case CERT_REVOCATION_CRL_CHECK:
                opensslParams->crlCheck = true;
                break;
            case CERT_REVOCATION_OCSP_CHECK:
                opensslParams->ocspCheck = true;
                break;
            case CERT_REVOCATION_CHECK_ALL_CERT:
                opensslParams->revocationCheckAll = true;
                break;
        }
    }
}
```

#### 2.4.4 CRL吊销检查

**CRL下载参数配置：**

| 参数名 | 宏定义 | 值 | 说明 |
|--------|--------|-----|------|
| CRL下载总次数限制 | `MAX_TOTAL_DOWNLOAD_COUNT` | 6次 | 单次验证最多下载CRL次数 |
| CRL下载超时 | `CRL_DOWNLOAD_TIMEOUT_SECONDS` | 3秒 | HTTP下载CRL的超时时间 |

**CRL检查流程：**

1. 检查 `revocationFlags` 是否包含 `CERT_REVOCATION_CRL_CHECK`
2. 首先使用 `crls` 参数中提供的 CRL
3. 如果 `allowDownloadCrl` 为 true，尝试从证书的 CRL Distribution Points 扩展下载 CRL
4. 验证 CRL 签名和有效期
5. 检查证书是否在 CRL 中

**CRL下载详细流程：**

```
DownloadCrlFromCdp()：
├── remainingCount = 6 (MAX_TOTAL_DOWNLOAD_COUNT)
├── 获取证书的CRL Distribution Points扩展 (NID_crl_distribution_points)
├── 遍历每个DistributionPoint
│   └── 遍历每个GENERAL_NAME (fullname类型)
│       ├── 检查 type == GEN_URI (URI类型)
│       ├── 校验URL为http/https (IsValidHttpUrl)
│       ├── remainingCount--
│       ├── ERR_clear_error()
│       ├── 调用 X509_CRL_load_http(url, NULL, NULL, 3秒超时)
│       │   ├── 成功 → 返回CRL
│       │   └── 失败 → 检查错误原因
│       │       ├── BIO_R_CONNECT_TIMEOUT → ret = CF_ERR_NETWORK_TIMEOUT
│       │       └── 其他 → 继续
│       └── 如果成功则跳出循环
├── 释放DIST_POINT栈
└── 返回结果
    ├── CRL不为空 → CF_SUCCESS
    ├── 超时 → CF_ERR_NETWORK_TIMEOUT
    └── 其他 → CF_ERR_CRL_NOT_FOUND
```

**CRL检查关键代码：**

```c
static CfResult CheckSingleCertByCrl(X509 *cert, const HcfX509CertValidatorParams *params,
    HcfX509CertValidatorOpenSSLParams *opensslParams, CertVerifyResultInner *result)
{
    // 1. 创建临时X509_STORE，启用CRL检查
    X509_STORE *store = X509_STORE_new();
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    
    // 2. 添加用户提供的CRL
    for (uint32_t i = 0; i < revokedParams->crls.count; i++) {
        X509_CRL *crl = GetX509CrlFromHcfX509Crl(revokedParams->crls.data[i]);
        X509_STORE_add_crl(store, crl);
    }
    
    // 3. 创建验证上下文
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert, NULL);
    
    // 4. 执行验证
    int ret = X509_verify_cert(ctx);
    if (ret != 1) {
        int err = X509_STORE_CTX_get_error(ctx);
        
        if (err == X509_V_ERR_UNABLE_TO_GET_CRL) {
            // 5. 尝试从网络下载CRL
            if (revokedParams->allowDownloadCrl) {
                X509_CRL *crl = DownloadCrlFromCdp(cert);
                if (crl != NULL) {
                    X509_STORE_add_crl(store, crl);
                    X509_CRL_free(crl);
                    // 重新验证...
                }
            }
        }
    }
    
    return CF_SUCCESS;
}
```

**CRL下载实现：**

```c
static CfResult DownloadCrlFromCdp(X509 *cert, X509_CRL **crlOut, CertVerifyResultInner *result)
{
    STACK_OF(DIST_POINT) *crldp = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
    if (crldp == NULL) {
        return ReturnVerifyError(CF_ERR_CRL_NOT_FOUND, "No CRL distribution points extension found.", result);
    }

    X509_CRL *crl = NULL;
    CfResult ret = CF_ERR_CRL_NOT_FOUND;
    int remainingCount = MAX_TOTAL_DOWNLOAD_COUNT;
    int num = sk_DIST_POINT_num(crldp);
    
    for (int i = 0; i < num && crl == NULL && remainingCount > 0; i++) {
        DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);
        // 检查distpoint类型为fullname
        if (dp == NULL || dp->distpoint == NULL || dp->distpoint->type != 0) {
            continue;
        }

        STACK_OF(GENERAL_NAME) *names = dp->distpoint->name.fullname;
        int nameCount = sk_GENERAL_NAME_num(names);
        
        for (int j = 0; j < nameCount && crl == NULL && remainingCount > 0; j++) {
            GENERAL_NAME *genName = sk_GENERAL_NAME_value(names, j);
            if (genName == NULL || genName->type != GEN_URI) {
                continue;
            }
            
            char *url = (char *)genName->d.uniformResourceIdentifier->data;
            if (!IsValidHttpUrl(url)) {
                LOGW("Invalid CRL URL (not http/https): %s", url);
                continue;
            }
            
            remainingCount--;
            ERR_clear_error();
            crl = X509_CRL_load_http(url, NULL, NULL, CRL_DOWNLOAD_TIMEOUT_SECONDS);
            
            if (crl != NULL) {
                break;
            }
            
            // 检查超时错误
            unsigned long err = ERR_peek_error();
            int reason = ERR_GET_REASON(err);
            if (reason == BIO_R_CONNECT_TIMEOUT || reason == BIO_R_TRANSFER_TIMEOUT) {
                ret = CF_ERR_NETWORK_TIMEOUT;
            }
        }
    }
    
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    
    if (crl != NULL) {
        *crlOut = crl;
        return CF_SUCCESS;
    }
    
    if (ret == CF_ERR_NETWORK_TIMEOUT) {
        return ReturnVerifyError(CF_ERR_NETWORK_TIMEOUT, "Failed to download CRL from CDP, network timeout.", result);
    }
    return ReturnVerifyError(CF_ERR_CRL_NOT_FOUND, "Failed to download CRL from CDP.", result);
}
```

#### 2.4.5 OCSP吊销检查

**OCSP请求参数配置：**

| 参数名 | 宏定义 | 值 | 说明 |
|--------|--------|-----|------|
| OCSP请求总次数限制 | `MAX_TOTAL_DOWNLOAD_COUNT` | 6次 | 单次验证最多OCSP请求次数 |
| OCSP连接超时 | `OCSP_REQUEST_TIMEOUT_SECONDS` | 4秒 | TCP连接超时时间 |
| OCSP响应超时 | `OCSP_REQUEST_TIMEOUT_SECONDS` | 4秒 | HTTP响应超时时间 |

**OCSP检查流程：**

1. 检查 `revocationFlags` 是否包含 `CERT_REVOCATION_OCSP_CHECK`
2. 首先使用 `ocspResponses` 参数中提供的 OCSP 响应
3. 如果 `allowOcspCheckOnline` 为 true，从证书的 AIA 扩展获取 OCSP URL 并发送请求
4. 使用 `ocspDigest` 指定的摘要算法
5. 验证 OCSP 响应签名
6. 检查证书状态

**OCSP在线请求详细流程：**

```
PerformOnlineOcspCheck()：
├── remainingCount = 6 (MAX_TOTAL_DOWNLOAD_COUNT)
├── 获取证书中的OCSP URL列表 (X509_get1_ocsp)
├── 创建OCSP请求
│   ├── 获取摘要算法 (GetOcspDigestByType)
│   ├── 创建 OCSP_CERTID (OCSP_cert_to_id)
│   └── 添加nonce (OCSP_request_add1_nonce)
├── 遍历每个OCSP URL (remainingCount > 0)
│   └── TrySingleOcspUrl()
│       ├── 解析URL (OCSP_parse_url)
│       ├── remainingCount--
│       ├── 创建连接BIO (CreateConnectBio)
│       │   └── BIO_do_connect_retry(bio, 4秒超时, 0)
│       │       ├── 成功 → 返回BIO
│       │       ├── 超时 (BIO_R_CONNECT_TIMEOUT) → CF_ERR_NETWORK_TIMEOUT
│       │       └── 其他失败 → CF_ERR_OCSP_RESPONSE_NOT_FOUND
│       ├── 发送OCSP请求 (SendOcspRequestWithTimeout)
│       │   ├── 创建请求上下文 (OCSP_sendreq_new)
│       │   ├── 设置响应超时 (OSSL_HTTP_REQ_CTX_set_expected, 4秒)
│       │   └── 发送请求 (OCSP_sendreq_nbio)
│       │       ├── 成功 → 返回响应
│       │       ├── 超时 → CF_ERR_NETWORK_TIMEOUT
│       │       └── 其他失败 → CF_ERR_OCSP_RESPONSE_NOT_FOUND
│       └── 验证响应 (VerifyOnlineOcspResponse)
│           ├── 检查响应状态
│           ├── 验证签名 (OCSP_basic_verify)
│           └── 获取证书状态
│               ├── V_OCSP_CERTSTATUS_GOOD → CF_SUCCESS
│               ├── V_OCSP_CERTSTATUS_REVOKED → CF_ERR_CERT_REVOKED
│               └── V_OCSP_CERTSTATUS_UNKNOWN → CF_ERR_OCSP_CERT_STATUS_UNKNOWN
└── 返回最终结果
```

**OCSP在线请求实现：**

```c
static CfResult PerformOnlineOcspCheck(X509 *cert, X509 *issuer,
    const HcfX509CertValidatorParams *params,
    const HcfX509CertValidatorOpenSSLParams *opensslParams,
    CertVerifyResultInner *result)
{
    // 1. 获取OCSP URL列表
    STACK_OF(OPENSSL_STRING) *ocspUrls = X509_get1_ocsp(cert);
    if (ocspUrls == NULL || sk_OPENSSL_STRING_num(ocspUrls) == 0) {
        return ReturnVerifyError(CF_ERR_OCSP_RESPONSE_NOT_FOUND, "No OCSP URL found in certificate.", result);
    }

    // 2. 创建OCSP请求，使用配置的摘要算法
    OCSP_REQUEST *req = NULL;
    CfResult res = CreateOcspRequest(cert, issuer, params->revokedParams, result, &req);
    if (res != CF_SUCCESS) {
        X509_email_free(ocspUrls);
        return res;
    }

    // 3. 获取certId用于后续验证
    OCSP_CERTID *certId = OCSP_CERTID_dup(OCSP_onereq_get0_id(OCSP_request_onereq_get0(req, 0)));
    
    // 4. 遍历URL发送请求
    int remainingCount = MAX_TOTAL_DOWNLOAD_COUNT;
    OcspCheckContext ctx = { req, certId, cert, &remainingCount };
    res = CF_ERR_OCSP_RESPONSE_NOT_FOUND;
    
    for (int i = 0; i < sk_OPENSSL_STRING_num(ocspUrls) && remainingCount > 0; i++) {
        res = TrySingleOcspUrl(sk_OPENSSL_STRING_value(ocspUrls, i), &ctx, opensslParams, result);
        // 只有不超时和找不到响应时才继续尝试下一个URL
        if (res != CF_ERR_OCSP_RESPONSE_NOT_FOUND && res != CF_ERR_NETWORK_TIMEOUT) {
            break;
        }
    }
    
    OCSP_CERTID_free(certId);
    OCSP_REQUEST_free(req);
    X509_email_free(ocspUrls);
    return res;
}

static CfResult TrySingleOcspUrl(const char *url, OcspCheckContext *ctx,
    const HcfX509CertValidatorOpenSSLParams *opensslParams, CertVerifyResultInner *result)
{
    char *host = NULL, *port = NULL, *path = NULL;
    int use_ssl = 0;

    // 解析URL
    if (OCSP_parse_url(url, &host, &port, &path, &use_ssl) != 1) {
        return ReturnVerifyError(CF_ERR_OCSP_RESPONSE_NOT_FOUND, "Failed to parse OCSP URL.", result);
    }

    (*ctx->remainingCount)--;
    
    // 创建连接 (4秒超时)
    int errReason = 0;
    BIO *bio = CreateConnectBio(host, port, &errReason);
    if (bio == NULL) {
        FreeConnectInfo(host, port, path);
        if (errReason == BIO_R_CONNECT_TIMEOUT || errReason == BIO_R_TRANSFER_TIMEOUT) {
            return ReturnVerifyError(CF_ERR_NETWORK_TIMEOUT, "OCSP connection timeout.", result);
        }
        return ReturnVerifyError(CF_ERR_OCSP_RESPONSE_NOT_FOUND, "Failed to connect to OCSP server.", result);
    }

    // 发送请求 (4秒响应超时)
    OCSP_RESPONSE *resp = NULL;
    CfResult sendRes = SendOcspRequestWithTimeout(bio, path, ctx->req, &resp, result);
    BIO_free(bio);
    FreeConnectInfo(host, port, path);

    if (sendRes != CF_SUCCESS) {
        return sendRes;
    }

    // 验证响应
    CfResult res = VerifyOnlineOcspResponse(resp, ctx->certId, ctx->cert, opensslParams, result);
    OCSP_RESPONSE_free(resp);
    return res;
}

static BIO *CreateConnectBio(const char *host, const char *port, int *errReason)
{
    BIO *bio = BIO_new_connect(host);
    if (bio == NULL) {
        *errReason = ERR_GET_REASON(ERR_peek_last_error());
        return NULL;
    }
    BIO_set_conn_port(bio, port);
    // 4秒连接超时
    int ret = BIO_do_connect_retry(bio, OCSP_REQUEST_TIMEOUT_SECONDS, 0);
    if (ret != 1) {
        *errReason = ERR_GET_REASON(ERR_peek_last_error());
        BIO_free(bio);
        return NULL;
    }
    return bio;
}

static CfResult SendOcspRequestWithTimeout(BIO *bio, const char *path, OCSP_REQUEST *req,
    OCSP_RESPONSE **respOut, CertVerifyResultInner *result)
{
    OSSL_HTTP_REQ_CTX *ctx = OCSP_sendreq_new(bio, path, req, -1);
    if (ctx == NULL) {
        return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Failed to create OCSP request context.", result);
    }

    // 4秒响应超时
    if (OSSL_HTTP_REQ_CTX_set_expected(ctx, NULL, 1, OCSP_REQUEST_TIMEOUT_SECONDS, 0) != 1) {
        OSSL_HTTP_REQ_CTX_free(ctx);
        return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Failed to set OCSP request timeout.", result);
    }

    OCSP_RESPONSE *resp = NULL;
    int ret = OCSP_sendreq_nbio(&resp, ctx);
    OSSL_HTTP_REQ_CTX_free(ctx);
    
    if (ret == 1) {
        *respOut = resp;
        return CF_SUCCESS;
    }

    int reason = ERR_GET_REASON(ERR_peek_error());
    if (reason == BIO_R_CONNECT_TIMEOUT || reason == BIO_R_TRANSFER_TIMEOUT) {
        return ReturnVerifyError(CF_ERR_NETWORK_TIMEOUT, "OCSP request timeout.", result);
    }
    return ReturnVerifyError(CF_ERR_OCSP_RESPONSE_NOT_FOUND, "OCSP response not found.", result);
}
```

**OCSP摘要算法映射：**

```c
static const EVP_MD *GetOcspDigest(int32_t digestType)
{
    switch (digestType) {
        case OCSP_DIGEST_SHA1:   return EVP_sha1();
        case OCSP_DIGEST_SHA224: return EVP_sha224();
        case OCSP_DIGEST_SHA256: return EVP_sha256();  // 默认
        case OCSP_DIGEST_SHA384: return EVP_sha384();
        case OCSP_DIGEST_SHA512: return EVP_sha512();
        default: return EVP_sha256();
    }
}
```

#### 2.4.6 吊销检查回退逻辑

当同时启用CRL和OCSP检查时，支持自动回退：

| 场景 | 触发条件 | 回退目标 |
|------|----------|----------|
| CRL优先，找不到CRL | `X509_V_ERR_UNABLE_TO_GET_CRL` 且已开启OCSP | OCSP校验 |
| OCSP优先，OCSP不可用 | 配置响应无效且在线检查失败且已开启CRL | CRL校验 |
| 其他错误（CRL过期等） | - | 不回退，直接返回错误 |

#### 2.4.7 主机名验证

```c
static CfResult CheckCertValidatorExtensions(X509 *x509,
    const HcfX509CertValidatorParams *params, CertVerifyResultInner *result)
{
    if (params->hostnames.count > 0) {
        bool match = false;
        for (uint32_t i = 0; i < params->hostnames.count; i++) {
            if (X509_check_host(x509, params->hostnames.data[i],
                strlen(params->hostnames.data[i]), 0, NULL) == 1) {
                match = true;
                break;
            }
        }
        if (!match) {
            return CF_ERR_HOSTNAME_NOT_MATCHED;
        }
    }
    return CF_SUCCESS;
}
```

#### 2.4.8 邮箱验证

```c
if (params->emailAddresses.count > 0) {
    bool match = false;
    for (uint32_t i = 0; i < params->emailAddresses.count; i++) {
        if (X509_check_email(x509, params->emailAddresses.data[i],
            strlen(params->emailAddresses.data[i]), 0) == 1) {
            match = true;
            break;
        }
    }
    if (!match) {
        return CF_ERR_EMAIL_NOT_MATCHED;
    }
}
```

#### 2.4.9 密钥用途验证

```c
static const uint32_t KEYUSAGE_TO_OPENSSL_MAP[] = {
    KU_DIGITAL_SIGNATURE,   /* KEYUSAGE_DIGITAL_SIGNATURE = 0 */
    KU_NON_REPUDIATION,     /* KEYUSAGE_NON_REPUDIATION = 1 */
    KU_KEY_ENCIPHERMENT,    /* KEYUSAGE_KEY_ENCIPHERMENT = 2 */
    KU_DATA_ENCIPHERMENT,   /* KEYUSAGE_DATA_ENCIPHERMENT = 3 */
    KU_KEY_AGREEMENT,       /* KEYUSAGE_KEY_AGREEMENT = 4 */
    KU_KEY_CERT_SIGN,       /* KEYUSAGE_KEY_CERT_SIGN = 5 */
    KU_CRL_SIGN,            /* KEYUSAGE_CRL_SIGN = 6 */
    KU_ENCIPHER_ONLY,       /* KEYUSAGE_ENCIPHER_ONLY = 7 */
    KU_DECIPHER_ONLY,       /* KEYUSAGE_DECIPHER_ONLY = 8 */
};

if (params->keyUsage.count > 0) {
    uint32_t keyUsage = X509_get_key_usage(x509);
    for (uint32_t i = 0; i < params->keyUsage.count; i++) {
        int32_t kuType = params->keyUsage.data[i];
        if (kuType < 0 || (uint32_t)kuType >= MAX_KEYUSAGE_COUNT) {
            return CF_ERR_PARAMETER_CHECK;
        }
        uint32_t kuBit = KEYUSAGE_TO_OPENSSL_MAP[kuType];
        if (!(keyUsage & kuBit)) {
            return CF_ERR_KEYUSAGE_NOT_MATCHED;
        }
    }
}
```

#### 2.4.10 系统CA信任

```c
static CfResult ConstructTrustedStore(const HcfX509CertValidatorParams *params,
    X509_STORE **store, CertVerifyResultInner *result)
{
    X509_STORE *storeTmp = X509_STORE_new();

    // 添加用户提供的信任证书
    for (uint32_t i = 0; i < params->trustedCerts.count; i++) {
        X509 *cert = GetX509FromHcfX509Certificate(params->trustedCerts.data[i]);
        X509_STORE_add_cert(storeTmp, cert);
    }

    // 加载系统CA证书
    if (params->trustSystemCa) {
        X509_STORE_load_locations(storeTmp, NULL, CERT_VERIFY_DIR);
    }

    *store = storeTmp;
    return CF_SUCCESS;
}
```

#### 2.4.11 自签名证书处理

```c
// 使用X509_self_signed判断自签名证书，跳过吊销检查
if (X509_self_signed(cert, 0)) {
    continue;
}
```

#### 2.4.12 内存管理

| 资源 | 分配时机 | 释放函数 |
|------|----------|----------|
| X509证书（下载） | 下载成功后 | sk_X509_pop_free() |
| X509_STORE | ParseOpenSSLParams | X509_STORE_free() |
| X509_STORE_CTX | BuildAndVerifyCertChain | X509_STORE_CTX_free() |
| URL字符串 | TryDownloadFromSingleAia | CfFree() |
| X509_CRL | DownloadCrlFromCdp | X509_CRL_free() |
| OCSP_REQUEST | PerformOnlineOcspCheck | OCSP_REQUEST_free() |
| OCSP_RESPONSE | PerformOnlineOcspCheck | OCSP_RESPONSE_free() |
| 参数内存 | BuildX509CertValidatorParams | FreeX509CertValidatorParams() |
| 结果内存 | FillVerifyCertResult | 用户调用destroy |
| 错误信息 | SetBuildParamError | FreeVerifyCertResult |

#### 2.4.13 安全考虑

**已实现的安全措施：**
- DoS防护：
  - 中间CA下载：最多5次
  - CRL下载：最多6次
  - OCSP请求：最多6次
- 超时控制：所有网络操作均为3-4秒超时
- 参数控制：默认不启用自动下载，需显式设置
- 吊销检查：支持CRL和OCSP双重验证
- 自签名证书：自动跳过吊销检查
- 参数范围校验：防止非法参数值

## 附录

### A. 修改文件清单

| 序号 | 文件路径 | 行数 | 说明 |
|------|----------|------|------|
| 1 | frameworks/adapter/v1.0/src/x509_cert_chain_validator_openssl.c | 1711 | OpenSSL适配层，核心实现 |
| 2 | frameworks/core/v1.0/certificate/cert_chain_validator.c | 229 | 验证器创建和分发 |
| 3 | frameworks/js/napi/certificate/src/napi_cert_chain_validator.cpp | 559 | NAPI接口实现 |
| 4 | frameworks/js/napi/certificate/src/napi_x509_cert_chain_validate_params.cpp | 928 | 参数解析（使用NapiParamInfo） |
| 5 | frameworks/js/napi/certificate/src/napi_x509_cert_chain_validate_result.cpp | 151 | 结果构建 |
| 6 | frameworks/js/napi/certificate/src/napi_cert_crl_common.cpp | 245 | CRL相关公共方法 |
| 7 | frameworks/js/napi/certificate/src/napi_common.cpp | 614 | NAPI公共函数 |
| 8 | interfaces/inner_api/certificate/cert_chain_validator.h | 140 | Inner API接口定义 |

### B. 参考标准

| 标准 | 说明 |
|------|------|
| RFC 5280 | Internet X.509 Public Key Infrastructure Certificate and CRL Profile |
| RFC 4325 | Internet X.509 Public Key Infrastructure Authority Information Access Certificate Extension |
| RFC 5246 | The Transport Layer Security (TLS) Protocol Version 1.2 |
| RFC 6960 | X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP |

### C. 术语说明

| 术语 | 全称 | 说明 |
|------|------|------|
| AIA | Authority Information Access | 权威信息访问扩展，包含颁发者证书的访问方式 |
| OCSP | Online Certificate Status Protocol | 在线证书状态协议 |
| CRL | Certificate Revocation List | 证书吊销列表 |
| CDP | CRL Distribution Points | CRL分发点扩展 |
| PKIX | Public Key Infrastructure (X.509) | 基于X.509的公钥基础设施 |
| CA | Certificate Authority | 证书颁发机构 |
| DoS | Denial of Service | 拒绝服务攻击 |
| PKI | Public Key Infrastructure | 公钥基础设施 |
| SAN | Subject Alternative Name | 主题备用名 |
| CN | Common Name | 通用名 |