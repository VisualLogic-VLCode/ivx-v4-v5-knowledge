# `ivx-v4-v5-knowledge` 同步与发布

## 1. 边界

`vx-json-evolution-claude` 是知识维护源，本仓是同步控制器、公开 Knowledge Runtime 和 Release 所有者，`ivx-v4-v5-migration` 只消费本仓已经发布的签名不可变 Release。三者不共享 Git 历史，也不使用 submodule、subtree 或整仓复制。

维护源负责三册正文、证据和稳定规则 ID；本仓负责从一个明确 commit 生成公开候选、去标识、隐私扫描、语义差异、签名和发布；Workflow 不发现维护源，不运行本仓脚本，也不读取候选目录。

## 2. 固定同步入口

```bash
npm run sync:source -- \
  --source /absolute/path/to/vx-json-evolution-claude \
  --source-ref HEAD \
  --version 0.1.5
```

同步器把 `source-ref` 解析为完整 commit，以 `git archive` 创建隔离快照，并在快照内运行该 revision 自带的 `build_book.py` 与 `book_lint.py`。工作树的未提交内容完全不进入候选；若维护源是 dirty，只在忽略的同步报告中记录 `DIRTY_SOURCE_IGNORED`。

同步器只读取 `config/public-export-allowlist.json` 声明的生成物。它确定性替换案例 nid、扫描 run/pattern/snippet ID 和长对象 ID，拒绝绝对维护路径、凭据、私钥、JWT、非示例邮箱、私网地址和残留真实案例标识。任一门禁失败时，旧 `runtime/` 保持不变。

成功时确定性生成：

```text
runtime/
├── manifest.json
├── rules.jsonl
├── provenance.json
├── books/
├── index/
└── vocab/
```

同一 source commit、版本和 allowlist 连续运行必须得到相同的 runtime 内容摘要。`candidate-out/latest/sync-report.*` 只记录脱敏计数、源 commit、dirty 是否被忽略、规则语义差异和版本建议，不进入 Git 或 Release。

## 3. Knowledge Card 政策

转换册中的稳定 `CVT-*-NNN` ID 是公开规则主键，永不复用。每张卡包含主题、状态、有限检索词、源模式、目标不变量、例外、证据和权限。首个公开版本只允许诊断与静态验证，`automaticRepair` 全部为 `false`；未来任何 `EXECUTABLE_REPAIR` 必须经过单独 Schema、政策和人工确认评审。

规则语义差异比较 `status`、`sourcePattern`、`targetInvariant`、`exceptions`、`match`、`evidence` 和 `permissions`：

- PATCH：只改公开书稿、索引、解释或非规范证据元数据；
- MINOR：新增/废弃规则、规则状态或规范性语义变化、兼容 Schema 扩展；
- MAJOR：破坏稳定 ID、Schema、检索协议或兼容范围。

同步器只建议版本，维护者决定实际版本。

## 4. 发布与密钥

仅调整 Workflow、Converter 或 Agent protocol 兼容范围时，按兼容性补丁发布：不要运行 `sync:source`，不要改动三册正文、Cards、索引、词表或来源记录；只更新包版本、Runtime 版本以及 `runtime/manifest.json` 与 `config/public-export-allowlist.json` 中一致的兼容范围。内容摘要和所有内容文件哈希必须保持不变，随后运行完整检查并走相同的提交、推送、签名和发布流程。

Knowledge 使用独立 Ed25519 密钥。私钥默认位于：

```text
~/.ivx-v4-v5-maintainer/keys/knowledge-release-private-key.pem
```

私钥必须是当前用户所有、普通非链接文件且权限 `0600`；它不进入仓库、Release、Workflow 配置或报告。仓库只提交 `keys/knowledge-release-public-key.pem`。

准备发布前先提交并推送精确候选 commit，然后执行：

```bash
npm run release:prepare -- \
  --version 0.1.5 \
  --previous-manifest ./release-out/knowledge-0.1.4/knowledge-stable.json
```

首个版本省略 `--previous-manifest`；后续版本必须传入上一版已验证的签名 manifest，使 stable payload 保留所有未撤销旧版本，用户才能执行可信回滚。准备器会验证旧 manifest 的独立 Knowledge 签名，并拒绝重复发布同一版本。

准备器从 tracked runtime 创建无脚本、无依赖、无入口点的 npm tarball，核对内部 manifest、逐文件 SHA-256、Cards、兼容范围和远端 commit，再生成签名 stable payload/manifest 与发布计划。它不改变 GitHub。

正式发布：

```bash
npm run release:publish -- \
  --plan ./release-out/knowledge-0.1.5/github-release-plan.json \
  --confirm PUBLISH_STABLE_KNOWLEDGE
```

发布器要求仓库公开、immutable Releases 已启用、`main`/`release-channel` 和 `v*` 有无 bypass 的删除与非快进保护。它依次创建 Draft Release、上传并核对 tarball 和签名 manifest、发布 Release、回读远端字节，最后更新 `release-channel/knowledge-stable.json`。稳定通道更新之前，用户不会自动选中该版本。

## 5. 用户更新与回滚

Workflow 配置独立 Knowledge 稳定通道和公钥，安装前验证外层签名/资产 SHA-256、包内 manifest/逐文件哈希、Card Schema、Workflow/Converter/Agent protocol 兼容范围和撤销列表。新 Job/Review 锁定实际版本与摘要；正在进行的任务不静默切换。旧可信版本保留用于 rollback。

维护源后续更新的固定流程始终相同：先提交维护源，再在本仓运行 `sync:source --source-ref <commit>`，审阅 sync report 和 runtime diff，选择版本，提交/推送本仓，最后准备和发布 Release。Workflow 和用户侧不参与两仓同步。
