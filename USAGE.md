# floss-cli 使用文档

本文覆盖本库全部公开 API/用法，面向需要在 Rust 中调用 FLOSS CLI 的场景。

## 1. 安装

```toml
[dependencies]
floss-cli = "0.1.2"
```

> 本库基于 tokio 异步运行时；你的调用代码需要处于 tokio runtime 中。

## 2. 运行前提

- 你需要系统中可执行的 FLOSS CLI：`floss`/`floss.exe`，或可用的 `python -m floss`。
- 本库只封装 CLI，不依赖 FLOSS 的 Python API。

## 3. 创建 FlossCli（入口）

### 3.1 自动探测（推荐）

```rust
use floss_cli::{FlossCli, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = FlossCli::detect().await?;
    Ok(())
}
```

### 3.2 手动指定

```rust
use floss_cli::{FlossCli, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let _cli = FlossCli::new("floss");
    let _cli = FlossCli::python_module("python"); // python -m floss
    Ok(())
}
```

### 3.3 环境变量覆盖（优先级从高到低）

1. `FLOSS_EXE`：直接指定可执行文件路径
2. `FLOSS_PYTHON` + `FLOSS_PYTHON_ARGS`：指定 Python 解释器与额外参数
3. `PATH` 中的 `floss`/`floss.exe`
4. 默认 Python 候选（Windows：`python/python3/py -3`；其他：`python3/python`）

`FLOSS_PYTHON_ARGS` 规则：
- 以空白分隔
- 支持 `'` 或 `"` 包裹包含空格的参数
- 仅支持 `"` 作为双引号内转义，其它转义不支持

## 4. 构建一次调用（FlossCommand）

```rust
use floss_cli::{FlossCli, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = FlossCli::detect().await?;

    let cmd = cli
        .command()
        .arg("--only")
        .args(["static", "decoded"])
        .sample("malware.exe");

    let line = cmd.command_line();
    println!("{}", line); // program + args
    Ok(())
}
```

- `.arg(...)` / `.args(...)`：原样透传参数
- `.sample(...)`：自动插入 `--`，避免样本路径被当成参数
- `.command_line()`：返回 `program + args`，用于日志/审计

## 5. 执行模式（全部异步）

### 5.1 标准执行

- `run().await`：捕获 stdout/stderr，检查退出码（非 0 返回错误）
- `run_allow_exit_codes([1, 2]).await`：允许指定退出码视为成功
- `run_raw().await`：捕获 stdout/stderr，不检查退出码
- `run_raw_limited(max_bytes).await`：限制 stdout/stderr 捕获字节数

### 5.2 JSON 解析

- `run_json::<T>().await`：自动补 `-j/--json`（若未传入），反序列化为 `T`
- `run_results().await`：解析为内置 `ResultDocument`

### 5.3 直连终端（适合长时间分析）

- `run_inherit().await`：stdout/stderr 直连终端，不检查退出码
- `run_inherit_checked().await`：直连终端，非 0 退出码报错

### 5.4 子进程托管

- `spawn()`：stdout/stderr 直连终端，返回 `tokio::process::Child`
- `spawn_piped()`：stdout/stderr 为 piped，返回 `Child`

> `spawn/spawn_piped` 不处理超时，也不绑定 Job Object；由调用方自行管理子进程。

## 6. 输出结构与处理

### 6.1 FlossOutput

`run/run_raw/run_allow_exit_codes` 返回 `FlossOutput`：
- `program` / `args` / `status`
- `stdout: Vec<u8>` / `stderr: Vec<u8>`

字符串辅助方法：
- `stdout_lossy()` / `stderr_lossy()`：容错 UTF-8
- `stdout_string()` / `stderr_string()`：严格 UTF-8

### 6.2 FlossOutputLimited

`run_raw_limited` 返回 `FlossOutputLimited`，包含：
- `stdout_truncated` / `stderr_truncated` 截断标记

### 6.3 JSON 结果结构

内置类型：`ResultDocument`（模块 `floss_cli::results`）。
- `decoding_function_scores` 的 key 支持十进制与 `0x` 十六进制地址字符串

## 7. 超时与进程树终止

- `FlossCli::with_timeout(...)` 或 `FlossCommand::with_timeout(...)` 设置超时
- 超时后会尝试终止进程树（Best-effort）：
  - Windows：优先 Job Object（`KILL_ON_JOB_CLOSE`），失败回退 `taskkill`/`kill`
  - Unix：先 `SIGTERM`（等待 100ms），再升级 `SIGKILL`
- 终止失败会返回 `FlossError::TimedOutKillFailed`

## 8. 常见用法示例

### 8.1 解析 JSON 结果

```rust
use floss_cli::{FlossCli, Result, ResultDocument};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = FlossCli::detect().await?;
    let doc: ResultDocument = cli
        .command()
        .sample("malware.exe")
        .run_results()
        .await?;

    println!("decoded strings: {}", doc.strings.decoded_strings.len());
    Ok(())
}
```

### 8.2 允许非 0 退出码

```rust
use floss_cli::{FlossCli, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = FlossCli::detect().await?;
    let out = cli.command().sample("malware.exe").run_allow_exit_codes([1]).await?;
    println!("status: {}", out.status);
    Ok(())
}
```

### 8.3 直连终端（长时间分析）

```rust
use floss_cli::{FlossCli, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = FlossCli::detect().await?;
    cli.command().arg("-H").run_inherit().await?;
    Ok(())
}
```

### 8.4 输出限量防止占满内存

```rust
use floss_cli::{FlossCli, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = FlossCli::detect().await?;
    let out = cli.command().sample("malware.exe").run_raw_limited(1024 * 1024).await?;
    println!("stdout truncated: {}", out.stdout_truncated);
    Ok(())
}
```

### 8.5 spawn_piped + 自行读取

```rust
use floss_cli::{FlossCli, Result};
use tokio::io::AsyncReadExt;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = FlossCli::detect().await?;
    let mut child = cli.command().sample("malware.exe").spawn_piped()?;

    let mut stdout = Vec::new();
    if let Some(mut reader) = child.stdout.take() {
        reader.read_to_end(&mut stdout).await?;
    }

    let status = child.wait().await?;
    println!("status: {}", status);
    Ok(())
}
```

## 9. 错误类型与可观测性

`FlossError` 主要变体：
- `AutoDetectFailed`：自动探测失败
- `Io`：进程启动/IO 错误
- `Json`：JSON 反序列化失败
- `NonZeroExit`：非 0 退出码（包含 stdout/stderr）
- `TimedOut` / `TimedOutKillFailed`：超时及终止失败
- `Utf8`：严格 UTF-8 解码失败

`NonZeroExit`/`TimedOut` 会包含 `command`（program + args），便于定位实际执行路径。

## 10. 兼容性说明

- Windows：优先 Job Object 管理进程树；失败回退 `taskkill`/`kill`
- Unix：优先 `SIGTERM` 再 `SIGKILL`
- `spawn/spawn_piped` 不接管超时与进程树终止
