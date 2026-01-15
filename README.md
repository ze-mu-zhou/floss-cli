# floss-cli

一个极薄的 Rust 库：通过启动外部进程的方式调用 `floss`（FLARE Obfuscated String Solver）命令行工具。

核心目标：**不重写 FLOSS 的分析逻辑**，只负责：
- 组装参数（支持透传任意 FLOSS CLI 参数，覆盖 `floss -h/-H` 的全部功能）
- 执行命令并捕获 `stdout/stderr`
- 可选：在启用 `-j/--json` 时解析 JSON 输出（内置 `ResultDocument`，也支持自定义 `serde` 类型）

## 完整用法文档

全部 API、执行模式、错误语义与示例见 [USAGE.md](USAGE.md)。

## 快速使用

> 本库基于 tokio 异步运行时，调用时需处于 tokio runtime 中。

```rust
use floss_cli::{FlossCli, Result, ResultDocument};

#[tokio::main]
async fn main() -> Result<()> {
    // 方式 0（推荐）：自动探测
    // - 优先使用 PATH 里的 floss/floss.exe
    // - 否则回退到可用的 python -m floss
    let cli = FlossCli::detect().await?;

    // 方式 1：假设系统 PATH 里有 floss/floss.exe
    // let cli = FlossCli::new("floss");

    // 方式 2：用 python -m floss（适合只安装了 Python 包的场景）
    // let cli = FlossCli::python_module("python");

    let doc: ResultDocument = cli
        .command()
        .arg("--only")
        .args(["static", "decoded"])
        .sample("malware.exe")
        .run_results()
        .await?;

    println!("decoded strings: {}", doc.strings.decoded_strings.len());
    Ok(())
}
```

## 执行模式（全量异步）

- `run_raw().await`：捕获 stdout/stderr，不检查退出码
- `run_allow_exit_codes([1, 2]).await`：允许指定退出码视为成功
- `run_inherit().await`：stdout/stderr 直连终端，不检查退出码
- `run_inherit_checked().await`：直连终端，退出码非 0 直接返回错误
- `spawn()`：直连终端，返回 `tokio::process::Child`
- `spawn_piped()`：stdout/stderr 为 piped，返回 `tokio::process::Child` 供流式读取
- `command_line()`：返回 `program + args`（含 `--` 与 sample），便于日志/审计

> `spawn/spawn_piped` 不自动绑定 Job Object，也不处理超时；需要调用方自行管理。

## 输出控制

- `run_raw_limited(max_bytes).await`：限制 stdout/stderr 的最大捕获字节数，超出部分会被丢弃

## 环境变量覆盖（优先级从高到低）

1) `FLOSS_EXE`：直接指定可执行文件路径  
2) `FLOSS_PYTHON` + `FLOSS_PYTHON_ARGS`：用指定 Python 解释器运行 `-m floss`  
3) `PATH` 中的 `floss/floss.exe`  
4) 默认 Python 候选（Windows: `python/python3/py -3`；其他系统: `python3/python`）

> `FLOSS_PYTHON_ARGS` 使用空白分隔，支持用 `'` 或 `"` 包裹含空格的参数；在 `"` 中支持 `\"` 转义双引号（其余转义不支持）。

## 超时说明

- 超时会尝试终止进程树：Windows 优先使用 Job Object（`KILL_ON_JOB_CLOSE`），失败回退 `taskkill /T /F`/`kill`；Unix 先发 `SIGTERM`（100ms 宽限），再升级到 `SIGKILL`。
- 若无法终止进程，会返回 `FlossError::TimedOutKillFailed`，并尽量避免主线程卡死。

## 读取 FLOSS 帮助（覆盖全部 CLI 功能）

```rust
use floss_cli::{FlossCli, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = FlossCli::new("floss");
    println!("{}", cli.help().await?);      // 等价于 floss -h
    println!("{}", cli.help_all().await?);  // 等价于 floss -H（高级参数）
    Ok(())
}
```

## 设计约束

- 本库不依赖 FLOSS 的 Python 源码 API；只依赖“可执行的 floss CLI”（或 `python -m floss`）。
- 若你希望“调用 FLOSS 的所有功能”，请直接透传参数：`.arg(...)` / `.args(...)`。
