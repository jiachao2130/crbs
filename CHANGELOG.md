# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.0] - 2026-11-06

首个公开版本。

### Added

- **构建引擎**：单机 CLI 构建，支持 chroot 与 systemd-nspawn 后端、OverlayFS 增量构建、共享依赖层、dnf 元数据缓存、ccache 与 tmpfs 加速。
- **分布式构建**：hub / worker 架构，worker 以长轮询领取任务；多架构扇出、纯 noarch 收敛、任务优先级、取消、重试与超时控制。
- **批量构建**：依赖链拓扑排序与分轮构建；整仓重建批次，支持增量跳过、失败策略与批次取消。
- **产品管理**：产品配置以数据库为权威源，支持继承与 `+field` 追加、可见性、ACL、所有权转让、配置历史与 TOML 导出；提供 Web UI 管理入口。
- **可复现构建**：provenance 记录、`--reproduce` 锁定依赖快照重建、recipe 导出、产品级 deterministic 模式、构建重放比对与 `--repro-from-srpm`；`crbs verify` 做产物字节级比对。
- **产物管理**：构建产物自动发布到产品 repo，支持撤回与重组；GPG 签名由服务端在宿主侧完成；CLI / API / Web UI 均可下载产物与日志。
- **资源感知调度**：包资源画像（声明 + 学习）、派发水位门、heavy steering、worker 遥测与趋势展示。
- **运维能力**：GC 策略（结果、共享层、包缓存、孤儿挂载）、审计日志、Prometheus 指标、健康检查、优雅停机、数据库保留策略。
- **存储**：默认 SQLite，支持 PostgreSQL 双后端；schema 采用单 baseline + 版本闩，版本不匹配时拒绝启动。
- **认证与安全**：Bearer token 用户认证、worker secret、四级角色与产品 ACL、CSRF 防护、内置 TLS、公开访问开关、提交限流。
- **接口**：完整 CLI、HTTP API 与 Web UI。
- **打包**：RPM 拆分为 `crbs`、`crbs-server`、`crbs-worker`、`crbs-priv-helper`；提供 SRPM 生成脚本，目标机可重建。
