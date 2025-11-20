# Bloom Launcher (Rust)

Rust 实现的 Minecraft 启动器，目标：版本管理、资源自动化下载、JRE 探测/下载、微软账号登录、一键启动（CLI/后续可扩 GUI）。

## 当前进展
- 版本清单：拉取官方 `version_manifest_v2.json`，列出/选择版本。
- 版本描述下载：按版本下载 `<version>.json`，并解析启动参数、依赖与资产索引。
- 资源下载：并发 DownloadManager（可配置并发、重试），支持 SHA1 命中跳过下载；下载 client.jar、libraries、assets index 与 assets 对象。
- 启动命令：基于已下载依赖拼装基础 JVM 启动命令（尚未接入真实账号/鉴权）。
- 日志/错误：`tracing` + `snafu`，阶段化错误标记；缓存复用日志可见。

## 路线图（Roadmap）
- M1（已完成）：基础清单获取、版本描述解析与资源下载、CLI 交互选择版本/实例名。
- M2（进行中）：校验完善（全量 SHA1、尺寸兜底）、下载进度/速率展示。
- M3：微软登录（MS OAuth → XBL → XSTS → MC token），多账户与本地加密存储。
- M4：JRE 探测 & 按需下载（缓存，按版本/平台选择），natives 解压准备。
- M5：启动流程完善：规则过滤 JVM/Game args，注入真实凭据，子进程日志流。
- M6：实例/配置管理：Profile（分辨率、内存、JVM/Game args、自定义实例目录）。
- M7：GUI（可选 egui/tauri）与 Mod/Fabric/Forge/Quilt 安装支持。

## 目录结构（核心）
- `crates/cli`：命令行入口（选择版本/实例名，下载描述与资源，生成启动命令）。
- `crates/core`：
  - `versions.rs`：版本清单/描述解析，资源下载任务构建，启动命令生成。
  - `download.rs`：DownloadManager 并发下载（重试、SHA1 校验、缓存复用）。
  - `config.rs`：应用路径（缓存/实例目录）。
  - `error.rs`：阶段化错误类型。
- `crates/auth`：账号（当前占位，待接入微软流）。
- `crates/jvm`：JRE 探测占位，后续实现本地查找/下载。

## 使用
```bash
# 拉取依赖并运行 CLI（需网络）
RUST_LOG=info cargo run -p bloom-cli
```
步骤：选择版本 → 输入实例名称（默认用版本号）→ 自动下载描述/资源 → 输出建议启动命令（默认 java，占位身份）。

缓存路径：
- 配置根：`~/.bloom-launcher/`
- 缓存：`~/.cache/bloomlauncher/`（versions/libraries/assets）
- 实例：`~/.local/share/BloomLauncher/instances/`（按实例名创建）

## 设计要点
- 下载任务：带 id/重试/SHA1，命中校验则跳过；失败记录到 outcome，不影响其他任务。
- 资源布局：Mojang 官方路径规则（libraries Maven 路径，assets 按 hash 前两位分桶）。
- 规则处理：启动参数暂做基础展开，后续补齐 OS/feature 条件、auth 占位替换。
- 日志：`tracing`，默认 info；错误保留 stage，便于定位。

## 后续计划
- 填充 Auth/JVM 模块，接入真实凭据与 JRE 管理。
- 校验/断点续传/进度 UI，失败任务重试与汇总。
- 版本继承链展开（当前直接使用显式描述），支持 Forge/Fabric/Quilt 配方。
