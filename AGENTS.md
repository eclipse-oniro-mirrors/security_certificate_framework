# 证书算法库框架组件指引

## 算法库概述

证书算法库框架（Certificate Framework / certificate_framework）是 OpenHarmony 安全子系统下的证书算法框架，屏蔽第三方证书算法库（OpenSSL）的实现差异，对外提供统一的证书解析与校验、证书扩展域段解析、证书吊销列表（CRL）解析、证书链校验、CMS 生成、CSR 生成等能力。仅提供基础证书解析与校验能力，不提供密钥管理能力，密钥材料的持久化存储、安全存储与生命周期管理由HUKS（OpenHarmony Universal KeyStore，OpenHarmony通用密钥库系统） 负责，HUKS不在本模职责范围内。

## 项目定位

### 大文件读取策略
- 适配层 .c 文件通常超过 1000 行，不要全文读取
- 先用 grep 搜索关键函数名（如 Validate、VerifyCertChain、ExecuteSingleVerification）定位行号
- 再按行号范围局部读取（offset + limit）
- 词汇型路由表已指明文件路径，到达后用搜索定位函数而非全文扫描

本仓库对应 OpenHarmony `base/security/certificate_framework`。证书算法库框架屏蔽了第三方证书算法库（OpenSSL）的实现差异，对外提供统一的证书、证书扩展域段、证书吊销列表解析及证书链校验等能力。优先按这些目录定位问题：

- `frameworks/core/`：框架核心实现层，统一对象管理、参数解析、能力注册。
- `frameworks/core/v1.0/`：v1.0 接口的框架侧实现，含证书、CRL、证书链、证书 DN、CMS、CRL 集合等对象。
- `frameworks/core/v1.0/spi/`：框架与适配层之间的服务提供者接口，是框架与适配层解耦的关键边界。
- `frameworks/adapter/`：算法库适配层，依赖 OpenSSL 调用具体接口实现上层能力。
- `frameworks/adapter/v1.0/`：v1.0 接口的 OpenSSL 适配实现。
- `frameworks/adapter/v2.0/`：v2.0 接口的 OpenSSL 适配实现。
- `frameworks/adapter/attestation/`：设备证书校验（attestation）适配实现。
- `frameworks/ability/`：框架层能力注册。
- `frameworks/common/`：内部公共方法（日志、内存、字符串、错误码、检查工具）。
- `frameworks/js/napi/`、`frameworks/js/ani/`：JS 接口的两种封装（NAPI/ANI）。
- `frameworks/cj/`：Cangjie FFI 接口。
- `frameworks/api_metrics/`：API 度量统计。
- `interfaces/inner_api/`：inner c 接口，为框架层的接口，JS 接口均调用inner c接口，OpenHarmony内部模块可能会调用inner c接口。
- `test/unittest/`、`test/fuzztest/`：单元测试和 fuzz 目标。

### 按任务类型定位代码

> **修改前强制检查**：通过本表定位到目标文件后，修改代码前必须先阅读"公共 API 约束"章节，确认修改不会导致已有 API 的行为语义变更（如新增校验导致原先可接受的输入被拒绝）。

| 任务类型　　　　　　　　　　　　　　 | 先看　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| --------------------------------------| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 新增/修改证书解析　　　　　　　　　　| `frameworks/core/v1.0/certificate/x509_certificate.c`、`frameworks/adapter/v1.0/src/x509_certificate_openssl.c`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| 新增/修改证书扩展域段　　　　　　　　| `frameworks/core/extension/`、`frameworks/adapter/v1.0/src/` 中 extension 相关　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 新增/修改证书吊销列表（CRL）　　　　 | `frameworks/core/v1.0/certificate/x509_crl.c`、`frameworks/adapter/v1.0/src/x509_crl_openssl.c`、`x509_crl_entry_openssl.c`　　　　　　　　　　　　　　　　　　　　　　　　　　|
| 新增/修改证书链校验　　　　　　　　　| `frameworks/core/v1.0/certificate/x509_cert_chain.c`、`cert_chain_validator.c`、`frameworks/adapter/v1.0/src/x509_cert_chain_openssl.c`、`x509_cert_chain_validator_openssl.c` |
| 新增/修改证书 DN（可分辨名称）　　　 | `frameworks/core/v1.0/certificate/x509_distinguished_name.c`、`frameworks/adapter/v1.0/src/x509_distinguished_name_openssl.c`　　　　　　　　　　　　　　　　　　　　　　　　　|
| 新增/修改 CMS 生成　　　　　　　　　 | `frameworks/core/v1.0/certificate/cert_cms_generator.c`、`frameworks/adapter/v1.0/src/x509_cert_cms_generator_openssl.c`　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 新增/修改 CSR 生成　　　　　　　　　 | `frameworks/adapter/v1.0/src/x509_csr_openssl.c`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 新增/修改 CRL 集合　　　　　　　　　 | `frameworks/core/v1.0/certificate/cert_crl_collection.c`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 新增/修改设备证书校验（attestation） | `frameworks/core/attestation/src/hm_attestation_cert_verify.c`、`frameworks/adapter/attestation/`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| 修改 v2.0 适配层　　　　　　　　　　 | `frameworks/adapter/v2.0/`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 修改框架核心对象管理　　　　　　　　 | `frameworks/core/life/cf_api.c`、`frameworks/ability/src/cf_ability.c`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 修改参数解析　　　　　　　　　　　　 | `frameworks/core/param/src/cf_param.c`、`cf_param_parse.c`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 修改 SPI 接口定义　　　　　　　　　　| `frameworks/core/v1.0/spi/`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| 修改 inner c 接口　　　　　　　　　　| `interfaces/inner_api/`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| 修改 NAPI JS 接口　　　　　　　　　　| `frameworks/js/napi/certificate/`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| 修改 ANI JS 接口　　　　　　　　　　 | `frameworks/js/ani/`（IDL 定义：`frameworks/js/ani/idl/*.taihe`）　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| 修改 Cangjie FFI 接口　　　　　　　　| `frameworks/cj/`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 修改 OpenSSL 适配公共逻辑　　　　　　| `frameworks/adapter/v1.0/src/certificate_openssl_common.c`、`frameworks/adapter/v1.0/inc/certificate_openssl_common.h`　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 修改 API 度量统计　　　　　　　　　　| `frameworks/api_metrics/`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|

### 嵌套指引

本仓库无目录级别的嵌套指引。所有任务级指导通过本文件和接口头文件中的注释提供。

### 大文件读取策略

适配层 `.c` 文件通常超过 1000 行，全文读取会消耗大量 Token。定位到目标文件后：
- 先用 grep 搜索关键函数名（如 `Validate`、`VerifyCertChain`、`InitializeRequest`、`ExecuteSingleVerification`）定位行号
- 再按行号范围局部读取（offset + limit）
- 词汇型路由表已指明文件路径，到达后用搜索定位函数而非全文扫描

## 知识索引

### 词汇型路由

当任务描述、issue、日志、API 或文件中出现以下术语时，按所属层级先读对应文件再动手。"—"表示该术语在该层无独立文件。

词汇型路由使用原则：
- 仅当术语是题目的核心分析对象时才读取对应文件
- 参数结构体中引用的支撑类型（CfBlob/CfResult/CfObjectBase）在上下文中内联理解
- 不要对参数字段类型做连锁式词汇查询

#### JS/ANI 层

JS 绑定层包含 NAPI（`frameworks/js/napi/certificate/`）、ANI（`frameworks/js/ani/`）、Cangjie FFI（`frameworks/cj/`）三种封装。ANI 以 IDL（`frameworks/js/ani/idl/*.taihe`）为接口定义唯一入口，生成代码不可手改。

| 领域术语 | NAPI（`frameworks/js/napi/certificate/`） | ANI（`frameworks/js/ani/`） | CJ（`frameworks/cj/`） |
| --- | --- | --- | --- |
| X.509 证书（解析/校验/字段获取） | `src/napi_x509_certificate.cpp`、`inc/napi_x509_certificate.h` | `src/ani_x509_cert.cpp`、`inc/ani_x509_cert.h` | `src/cj_x509_certificate.cpp`、`inc/cj_x509_certificate.h` |
| 证书扩展域段（Extension/OID） | `src/napi_cert_extension.cpp`、`inc/napi_cert_extension.h` | `src/ani_cert_extension.cpp`、`inc/ani_cert_extension.h` | — |
| 证书吊销列表（CRL） | `src/napi_x509_crl.cpp`、`inc/napi_x509_crl.h`、`src/napi_x509_crl_entry.cpp`、`inc/napi_x509_crl_entry.h` | `src/ani_x509_crl.cpp`、`inc/ani_x509_crl.h`、`src/ani_x509_crl_entry.cpp`、`inc/ani_x509_crl_entry.h` | `src/cj_x509_crl.cpp`、`inc/cj_x509_crl.h`、`src/cj_x509_crl_entry.cpp`、`inc/cj_x509_crl_entry.h` |
| CRL 集合 | `src/napi_cert_crl_collection.cpp`、`inc/napi_cert_crl_collection.h` | `src/ani_cert_crl_collection.cpp`、`inc/ani_cert_crl_collection.h` | `src/cj_cert_crl_collection.cpp`、`inc/cj_cert_crl_collection.h` |
| 证书链校验（CertChain/Validator） | `src/napi_x509_cert_chain.cpp`、`inc/napi_x509_cert_chain.h`、`src/napi_cert_chain_validator.cpp`、`inc/napi_cert_chain_validator.h`、`src/napi_x509_cert_chain_validate_params.cpp`、`inc/napi_x509_cert_chain_validate_params.h`、`src/napi_x509_cert_chain_validate_result.cpp`、`inc/napi_x509_cert_chain_validate_result.h` | `src/ani_x509_cert_chain.cpp`、`inc/ani_x509_cert_chain.h`、`src/ani_cert_chain_validator.cpp`、`inc/ani_cert_chain_validator.h`、`src/ani_x509_cert_chain_validate_result.cpp`、`inc/ani_x509_cert_chain_validate_result.h` | `src/cj_x509_certchain.cpp`、`inc/cj_x509_certchain.h`、`src/cj_certchain_validator.cpp`、`inc/cj_certchain_validator.h` |
| 证书 DN（Distinguished Name） | `src/napi_x509_distinguished_name.cpp`、`inc/napi_x509_distinguished_name.h` | `src/ani_x500_distinguished_name.cpp`、`inc/ani_x500_distinguished_name.h` | `src/cj_x500_distinguished_name.cpp`、`inc/cj_x500_distinguished_name.h` |
| CMS（Cryptographic Message Syntax） | `src/napi_cert_cms_generator.cpp`、`inc/napi_cert_cms_generator.h` | `src/ani_cert_cms_generator.cpp`、`inc/ani_cert_cms_generator.h` | — |
| CSR（Certificate Signing Request） | — | — | — |
| 设备证书校验（Attestation） | — | — | — |
| 证书匹配参数（CertMatchParameters） | `src/napi_x509_cert_match_parameters.cpp`、`inc/napi_x509_cert_match_parameters.h`、`src/napi_x509_crl_match_parameters.cpp`、`inc/napi_x509_crl_match_parameters.h` | `src/ani_parameters.cpp`、`inc/ani_parameters.h` | — |
| 信任锚（TrustAnchor） | `src/napi_x509_trust_anchor.cpp`、`inc/napi_x509_trust_anchor.h` | `src/ani_parameters.cpp`、`inc/ani_parameters.h` | — |
| CfObject/CfObjectBase（对象模型） | `src/napi_object.cpp`、`inc/napi_object.h`、`src/napi_certificate_init.cpp` | `src/ani_object.cpp`、`inc/ani_object.h` | `src/cj_cf_object.cpp`、`inc/cj_cf_object.h` |
| CfParamSet（参数集） | `src/napi_common.cpp`、`inc/napi_common.h`、`src/napi_cert_utils.cpp`、`inc/napi_cert_utils.h` | `src/ani_common.cpp`、`inc/ani_common.h` | `src/cj_cert_common.cpp`、`inc/cj_cert_common.h` |
| 公钥（PubKey） | `src/napi_pub_key.cpp`、`inc/napi_pub_key.h`、`src/napi_key.cpp`、`inc/napi_key.h` | `src/ani_pub_key.cpp`、`inc/ani_pub_key.h` | — |

#### inner c 接口

inner c 接口头文件位于 `interfaces/inner_api/`，为框架层的对外接口，JS 接口均调用 inner c 接口，OpenHarmony 内部模块也可能调用。

| 领域术语　　　　　　　　　　　　　　| 头文件（`interfaces/inner_api/`）　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| -------------------------------------| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| X.509 证书（解析/校验/字段获取）　　| `certificate/x509_certificate.h`、`certificate/certificate.h`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 证书扩展域段（Extension/OID）　　　 | `include/cf_type.h`（`CfExtensionOidType`/`CfExtensionEntryType`）　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| 证书吊销列表（CRL）　　　　　　　　 | `certificate/x509_crl.h`、`certificate/x509_crl_entry.h`、`certificate/crl.h`、`certificate/cert_crl_common.h`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| 证书和CRL 集合　　　　　　　　　　　| `certificate/cert_crl_collection.h`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 证书链校验（CertChain/Validator）　 | `certificate/x509_cert_chain.h`、`certificate/cert_chain_validator.h`、`certificate/x509_cert_chain_validate_params.h`、`certificate/x509_cert_chain_validate_result.h` |
| 证书 DN（Distinguished Name）　　　 | `certificate/x509_distinguished_name.h`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| CMS（Cryptographic Message Syntax） | `certificate/cert_cms_generator.h`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| CSR（Certificate Signing Request）　| `certificate/x509_csr.h`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| 设备证书校验（Attestation）　　　　 | `attestation/hm_attestation_cert_verify.h`、`attestation/hm_attestation_cert_ext_type.h`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| 证书匹配参数（CertMatchParameters） | `certificate/x509_cert_match_parameters.h`、`certificate/x509_crl_match_parameters.h`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 信任锚（TrustAnchor）　　　　　　　 | `certificate/x509_trust_anchor.h`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| CfObject/CfObjectBase（对象模型）　 | `include/cf_api.h`、`common/cf_object_base.h`、`common/cf_blob.h`、`common/cf_result.h`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| CfParamSet（参数集）　　　　　　　　| `include/cf_param.h`、`include/cf_type.h`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |

#### 框架层

框架核心实现层位于 `frameworks/core/`，统一对象管理、参数解析、能力注册，通过 SPI（`frameworks/core/v1.0/spi/`）与适配层解耦。

| 领域术语　　　　　　　　　　　　　　| 文件（`frameworks/core/`）　　　　　　　　　　　　　　　　　　　　　　　　　　　| SPI 定义（`frameworks/core/v1.0/spi/`）　　　　　　　 |
| -------------------------------------| ---------------------------------------------------------------------------------| -------------------------------------------------------|
| X.509 证书（解析/校验/字段获取）　　| `v1.0/certificate/x509_certificate.c`　　　　　　　　　　　　　　　　　　　　　 | `x509_certificate_spi.h`　　　　　　　　　　　　　　　|
| 证书扩展域段（Extension/OID）　　　 | `extension/`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　| —　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 证书吊销列表（CRL）　　　　　　　　 | `v1.0/certificate/x509_crl.c`、`v1.0/certificate/cert_crl_common.c`　　　　　　 | `x509_crl_spi.h`　　　　　　　　　　　　　　　　　　　|
| 证书和CRL 集合　　　　　　　　　　　| `v1.0/certificate/cert_crl_collection.c`　　　　　　　　　　　　　　　　　　　　| —　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 证书链校验（CertChain/Validator）　 | `v1.0/certificate/x509_cert_chain.c`、`v1.0/certificate/cert_chain_validator.c` | `x509_cert_chain_spi.h`、`cert_chain_validator_spi.h` |
| 证书 DN（Distinguished Name）　　　 | `v1.0/certificate/x509_distinguished_name.c`　　　　　　　　　　　　　　　　　　| `x509_distinguished_name_spi.h`　　　　　　　　　　　 |
| CMS（Cryptographic Message Syntax） | `v1.0/certificate/cert_cms_generator.c`　　　　　　　　　　　　　　　　　　　　 | `cert_cms_generator_spi.h`　　　　　　　　　　　　　　|
| CSR（Certificate Signing Request）　| —　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 | —　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 设备证书校验（Attestation）　　　　 | `attestation/src/hm_attestation_cert_verify.c`　　　　　　　　　　　　　　　　　| —　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 证书匹配参数（CertMatchParameters） | —　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 | —　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 信任锚（TrustAnchor）　　　　　　　 | —　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 | —　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| CfObject/CfObjectBase（对象模型）　 | `life/cf_api.c`、`ability/src/cf_ability.c`（`frameworks/ability/`）　　　　　　| —　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| CfParamSet（参数集）　　　　　　　　| `param/src/cf_param.c`、`param/src/cf_param_parse.c`　　　　　　　　　　　　　　| —　　　　　　　　　　　　　　　　　　　　　　　　　　 |

#### 实现层

适配层位于 `frameworks/adapter/`，依赖 OpenSSL 调用具体接口实现上层能力。

| 领域术语　　　　　　　　　　　　　　| 文件（`frameworks/adapter/`）　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| -------------------------------------| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| X.509 证书（解析/校验/字段获取）　　| `v1.0/src/x509_certificate_openssl.c`、`v1.0/src/x509_certificate_create.c`、`v1.0/inc/x509_certificate_openssl.h`、`v1.0/inc/x509_certificate_create.h`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 证书扩展域段（Extension/OID）　　　 | `v1.0/src/x509_certificate_openssl.c` 中 extension 相关、`v1.0/inc/x509_certificate_openssl.h`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 证书吊销列表（CRL）　　　　　　　　 | `v1.0/src/x509_crl_openssl.c`、`v1.0/src/x509_crl_entry_openssl.c`、`v1.0/inc/x509_crl_openssl.h`、`v1.0/inc/x509_crl_entry_openssl.h`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 证书和CRL 集合　　　　　　　　　　　| —　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| 证书链校验（CertChain/Validator）　 | `v1.0/src/x509_cert_chain_openssl.c`、`v1.0/src/x509_cert_chain_openssl_ex.c`、`v1.0/src/x509_cert_chain_validator_openssl.c`、`v1.0/inc/x509_cert_chain_openssl.h`、`v1.0/inc/x509_cert_chain_openssl_ex.h`、`v1.0/inc/x509_cert_chain_validator_openssl.h` |
| 证书 DN（Distinguished Name）　　　 | `v1.0/src/x509_distinguished_name_openssl.c`、`v1.0/inc/x509_distinguished_name_openssl.h`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| CMS（Cryptographic Message Syntax） | `v1.0/src/x509_cert_cms_generator_openssl.c`、`v1.0/inc/x509_cert_cms_generator_openssl.h`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| CSR（Certificate Signing Request）　| `v1.0/src/x509_csr_openssl.c`、`v1.0/inc/x509_csr_openssl.h`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 设备证书校验（Attestation）　　　　 | `attestation/`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 证书匹配参数（CertMatchParameters） | —　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| 信任锚（TrustAnchor）　　　　　　　 | —　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| CfObject/CfObjectBase（对象模型）　 | —　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| CfParamSet（参数集）　　　　　　　　| —　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| OpenSSL 适配公共逻辑（通用）　　　　| `v1.0/src/certificate_openssl_common.c`、`v1.0/inc/certificate_openssl_common.h`、`v1.0/inc/certificate_openssl_class.h`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| v2.0 适配（通用）　　　　　　　　　 | `v2.0/`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|

### 任务型路由

当任务涉及多个"按任务类型定位代码"表中的类型时，按下表确定依次涉及的类型和顺序：

| 任务场景　　　　　　　　　| 依次涉及的任务类型　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| ---------------------------| ----------------------------------------------------------------------------------------------------|
| JS 接口新增证书字段获取　 | 新增/修改证书解析　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| JS 接口新增证书链校验参数 | 新增/修改证书链校验 → 修改 inner c 接口（如需新增参数）　　　　　　　　　　　　　　　　　　　　　　|
| 新增 v2.0 接口能力　　　　| 修改 SPI 接口定义 → 修改 v2.0 适配层 → 修改框架核心对象管理 → 修改 NAPI JS 接口 + 修改 ANI JS 接口 |

通用规则：
- 仅扩展能力（不新增接口）：适配层实现 → 框架核心层
- 新增接口：适配层实现 → SPI 接口定义 → 框架核心层 → NAPI JS 接口 + ANI JS 接口
- 新增 inner c 接口参数：适配层实现 → inner c 接口（`interfaces/inner_api`）

### 开始编辑前

在修改代码前，按以下顺序确认：
1. 确认任务类别
2. 根据上表确定需要阅读的文档
3. 根据"项目约束"确认不违反任何约束
4. 声明："将修改 X，已阅读 Y 文档，遵循 Z 约束"

## 构建和验证

### 构建方式1-基于OpenHarmony项目构建
构建命令从 OpenHarmony 源码根目录执行，不在本子目录执行。

```sh
./build.sh --product-name rk3568 --build-target certificate_framework --ccache
prebuilts/build-tools/linux-x86/bin/ninja -C out/rk3568 certificate_framework_test
```

框架库目标为 `certificate_framework_core`，Cangjie FFI 库目标为 `cj_cert_ffi`，ANI 库目标为 `certificate_framework_ani`，NAPI 库目标为 `cert`。

### 构建方式2-独立构建
无需OpenHarmony全量代码，仅下载构建证书算法库依赖的OpenHarmony构建工具，及其依赖的部件，不在本子目录执行。
#### 下载代码
```sh
mkdir -p openharmony/independent_build && cd openharmony/independent_build
repo init -u https://gitcode.com/openharmony/manifest.git -b master --no-repo-verify
repo sync -c build
python3 -m pip install --user build/hb
bash build/prebuilts_config.sh #执行比较耗时
repo sync -c security_certificate_framework
```

#### 构建
```sh
time hb build certificate_framework -i #构建发布件，后续构建可以添加--skip-download
time hb build certificate_framework -t #构建tdd用例，后续构建可以添加--skip-download
```

### 构建方式3-通用编译器构建

#### 准备工作
下载完代码后将修改同步到build_asan_tdd目录下的build_asan_tdd/security/certificate_framework
```sh
git clone https://gitcode.com/kang1024/build_asan_tdd.git && cd build_asan_tdd
git submodule update --init --recursive --remote # clone submodule
```
#### 构建
```sh
bash build.sh certificate  # Build certificate
bash build.sh clean        # Clean output directory
```
#### 执行用例
```sh
bash build.sh test cf_adapter_test
bash build.sh test cf_core_test
bash build.sh test cf_sdk_test
bash build.sh test cf_version1_test
```

#### Fuzz 测试目标
本仓 fuzz 目标定义在 `test/fuzztest/` 下，为 `ohos_fuzztest`，通过 OpenHarmony fuzz 测试框架运行：

| Fuzz 目标 | 路径 |
| --- | --- |
| `CfCreateFuzzTest` | `test/fuzztest/cfcreate_fuzzer/` |
| `CfParamFuzzTest` | `test/fuzztest/cfparam_fuzzer/` |
| `CfGetAndCheckFuzzTest` | `test/fuzztest/cfgetandcheck_fuzzer/` |
| `X509CertificateFuzzTest` | `test/fuzztest/v1.0/x509certificate_fuzzer/` |
| `X509CertChainFuzzTest` | `test/fuzztest/v1.0/x509certchain_fuzzer/` |
| `X509CrlFuzzTest` | `test/fuzztest/v1.0/x509crl_fuzzer/` |
| `X509DistinguishedNameFuzzTest` | `test/fuzztest/v1.0/x509distinguishedname_fuzzer/` |

### 静态检查
修改 C/C++ 文件后，执行本地代码检查，确认无新增告警再提交。

检查命令从 OpenHarmony 源码根目录执行，不在本子目录执行。
```sh
./build.sh --product-name rk3568 --build-target certificate_framework --gn-args enable_cpp_static_check=true
```

### 完成标准

任务被认为完成，当且仅当：

1. **代码改动已提交** - 使用 `git commit -s`，多代理协作时添加 `Co-Authored-By: Agent`
2. **本地构建通过** - 执行上述构建命令
   - 构建方式1-基于OpenHarmony项目构建 和 构建方式2-独立构建 二选一，保证mr门禁无编译问题
   - 构建方式3-通用编译器构建 若修改inner c层以下代码，则必选，会验证inner c接口和public c接口，保证其功能，并通过ASAN检查
3. **相关测试通过** - 对应单元测试和 fuzz 测试通过
4. **板侧验证（如适用）** - 涉及证书解析、证书链校验、attestation 的改动需提供验证证据
5. **文档更新（如适用）** - 公共 API 修改需更新注释和文档

### 如果无法运行验证

明确说明无法运行的原因，列出推荐的验证步骤供人工执行，标记需要人工验证的部分。

### 完成报告格式

报告应包含：改动摘要（文件列表、改动点）、验证结果（构建/测试输出）、风险评估（API 兼容性、安全性、性能风险）、未完成事项。

## 项目约束

### 性能约束

- 证书解析、证书链校验等路径避免不必要的内存拷贝和全量格式化日志。
- 证书链校验可能涉及多证书遍历，避免在每次校验中重复解析同一证书。

### 架构约束

- 框架层（`frameworks/core/`）与适配层（`frameworks/adapter/`）必须通过 SPI（`frameworks/core/v1.0/spi/`）解耦。框架层不直接调用 OpenSSL API，适配层不直接暴露给上层。
- 框架对象的销毁统一走 `CfObjDestroy` 和对象自身的 `destroy` 方法，遵循 `CfObjectBase` 的对象模型，不要跨层手动 free。
- 适配层能力通过工厂函数按类型实例化，类型匹配规则集中在框架层，适配层只负责实现具体能力。
- 如果某个能力不支持某个函数，必须提供空实现并返回 `CF_ERR_INVALID_CALL`，防止上层调用时因函数指针为 NULL 导致 crash。
- v1.0 和 v2.0 接口共存时，新增能力需明确适用版本，不要混用两套接口。

### 编码约定

- 本仓库以 C 语言为主（框架、适配层），C++ 用于 NAPI/ANI/CJ 绑定和测试。C 文件改动优先复用项目既有宏和约定。
- 内存分配使用 `CfMalloc`/`CfFree`（`frameworks/common/v1.0/inc/cf_memory.h`），释放使用 `SELF_FREE_PTR`/`CF_FREE_PTR` 宏，不要混用原生 `malloc`/`free`。
- 返回值统一使用 `CfResult`（`interfaces/inner_api/common/cf_result.h`），成功返回 `CF_SUCCESS`，错误使用 `CF_INVALID_PARAMS`、`CF_NOT_SUPPORT`、`CF_ERR_MALLOC`、`CF_ERR_CERT_SIGNATURE_FAILURE` 等。
- 日志使用 `LOGD`/`LOGI`/`LOGW`/`LOGE`（`frameworks/common/v1.0/inc/cf_log.h`），不要使用 `printf` 等日志打印方式。
- 字符串操作依赖 `bounds_checking_function` 做边界检查。
- C++ 改动（NAPI/ANI/CJ）优先复用 `napi_cert_utils.h` 等既有封装，对象包装遵循已有的 wrap/unwrap 模式。
- napi 层一旦 C++ 对象通过 `napi_wrap` 成功绑定到 napi 对象，就不能主动释放该 C++ 对象。`napi_wrap` 绑定时已指定释放回调（finalizer），对象生命周期由 napi 托管，GC 时由回调负责 `delete`；主动释放会导致 double-free。仅在 `napi_wrap` 失败时才需手动 `delete`。
- napi 层异步接口中，若未对参数数据进行拷贝（零拷贝取数据），必须通过 `napi_create_reference` 增加该 napi 参数的引用计数，否则异步任务执行期间 JS 侧参数对象可能被 GC 释放，导致 native 层访问到已释放的内存（use-after-free）。引用在异步上下文清理时通过 `napi_delete_reference` 释放。
- napi 层异步接口中，当前操作对象（`thisVar`）同样必须通过 `napi_create_reference` 增加引用计数，否则异步任务执行期间 JS 侧 `this` 对象可能被 GC 释放，导致 native 层通过 unwrap 获取的 C++ 对象指针悬空。引用在异步上下文清理时通过 `napi_delete_reference` 释放。
- JS 接口调用失败抛出异常时，`errMsg` 应尽可能详细，包含失败原因、关键参数值等上下文信息，便于应用开发者定位问题。
- 不要修改原有逻辑的返回值和输出值，避免破坏既有调用方的行为契约。

### 公共 API 约束（修改前必须完整阅读本节）

> **强制检查**：在进行任何代码修改前，必须逐条检查以下约束。即使不修改函数签名或结构体定义，修改函数的行为逻辑（如新增校验、改变返回条件、缩小接受范围、改变处理逻辑）也属于行为语义变更，适用以下禁止条款。

**Do not（禁止）：**
- 修改已发布的 NAPI、ANI、Inner API 的函数签名、参数类型、返回值类型
- 修改已有 API 的错误码（`CfResult` 枚举值），除非明确标注为废弃
- 删除或重命名已有公共 API
- 修改已有 API 的行为语义，包括但不限于：同步变异步、返回数据格式变化、新增校验导致原先可接受的输入被拒绝、缩小已有函数的处理范围、改变已有函数的返回条件
- 修改 `frameworks/core/adapter.map` 中已导出的符号
- 修改 `interfaces/inner_api/` 下已发布的头文件结构布局

**Ask before（修改前必须确认）：**
- 新增公共 API：确认是否需要 DFX 日志、API 度量统计（`frameworks/api_metrics/`）、错误码定义
- 修改inner c接口：确认是否影响OpenHarmony内部调用者
- 修改错误处理逻辑：确认是否影响应用层的错误码兼容性
- 新增inner c接口：确认API必须CF开头（对象基类 API 如 `CfCreate`/`CfObjDestroy` 同样遵循）
- 新增输入校验、白名单、过滤逻辑：确认是否导致已有调用方的合法输入被拒绝，这属于行为语义变更，适用上述 Do not 第 4 条；如确需新增校验，应新增独立 API 而非修改现有 API

### 安全与边界

**Do not（禁止）：**
- 在日志中输出证书私钥明文、敏感扩展域段内容、attestation 敏感信息
- 将证书数据或校验结果残留内存未清零即释放（应使用安全清零后释放）
- 绕过参数校验直接将外部输入传入底层 OpenSSL 接口
- 在未验证长度的情况下进行内存拷贝、缓冲区操作
- 硬编码证书、私钥等敏感常量到源码中

**Ask before（修改前必须确认）：**
- 替换 OpenSSL 接口
- 修改证书链校验逻辑（涉及信任链安全性）
- 修改设备证书校验（attestation）相关逻辑
- 修改内存安全告警相关的污点数据处理逻辑

### 协议与数据格式兼容性

**Do not（禁止）：**
- 修改 `CfBlob`、`CfObjectBase`、`CfResult` 等跨层数据结构的字段顺序和布局
- 修改证书编码格式（PEM/DER）的输出约定
- 修改已有证书参数结构（`HcfX509Cert*MatchParameters` 等）的字段顺序

**Ask before（修改前必须确认）：**
- 新增证书字段或扩展域段类型：确认参数序列化和兼容性处理
- 修改证书链校验参数：确认是否影响既有调用方

### 生成代码边界

**Do not（禁止）：**
- 直接修改 ANI IDL 编译器生成的 C++ 代码文件
- 手动编辑 `taihe_ffi_gen` 生成的 FFI 代码

**正确做法：**
- 修改 ANI 接口时编辑 IDL 定义文件（`frameworks/js/ani/idl/*.taihe`）
- 重新运行 IDL 编译器生成代码
- 如果生成代码不满足需求，考虑调整 IDL 定义

### 设备操作约束

**涉及真实设备时的注意事项：**
- 涉及证书链校验行为验证的改动，必须提供板侧证据（日志、测试输出）
- 不要在真实设备上执行可能影响系统安全的破坏性证书操作
- attestation 相关验证需明确标注测试证书来源
