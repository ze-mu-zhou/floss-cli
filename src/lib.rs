//! 在 Rust 中以子进程方式调用 `floss`（FLARE Obfuscated String Solver）CLI。
//!
//! 你可以把它当作一个“参数拼装 + 进程执行 + 输出抓取（可选 JSON 解析）”的薄封装：
//! - 支持透传任意 FLOSS CLI 参数（因此能覆盖 `floss -h/-H` 暴露的全部功能）
//! - 可选解析 `-j/--json` 的输出为任意 `serde` 可反序列化类型
//! - 内置 `ResultDocument`：直接反序列化 FLOSS 的 JSON 结果
//!
//! # 示例
//! ```no_run
//! use floss_cli::{FlossCli, Result, ResultDocument};
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     let cli = FlossCli::detect().await?;
//!     let doc: ResultDocument = cli.command().sample("malware.exe").run_results().await?;
//!     println!("decoded strings: {}", doc.strings.decoded_strings.len());
//!     Ok(())
//! }
//! ```

extern crate alloc;

pub mod results;

pub use crate::results::ResultDocument;

use alloc::borrow::Cow;
use alloc::string::{FromUtf8Error, String};
use core::result::Result as CoreResult;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::Error as IoError;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde_json::Error as SerdeJsonError;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;
use tokio::time;

/// 本库统一的 `Result` 类型别名。
pub type Result<T> = CoreResult<T, FlossError>;

/// 调用 FLOSS 过程中可能出现的错误。
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum FlossError {
    #[error("自动探测失败: {message}")]
    AutoDetectFailed { message: String },

    #[error("启动进程失败: {0}")]
    Io(#[from] IoError),

    #[error("解析 JSON 失败: {0}")]
    Json(#[from] SerdeJsonError),

    #[error("floss 退出码非 0: {status} ({command})")]
    NonZeroExit {
        command: Box<CommandLine>,
        status: ExitStatus,
        stderr: Vec<u8>,
        stdout: Vec<u8>,
    },

    #[error("floss 执行超时: timeout={timeout:?} ({command})")]
    TimedOut {
        command: Box<CommandLine>,
        stderr: Vec<u8>,
        stdout: Vec<u8>,
        timeout: Duration,
    },

    #[error("floss 执行超时且无法终止进程: timeout={timeout:?} ({command}): {source}")]
    TimedOutKillFailed {
        command: Box<CommandLine>,
        stderr: Vec<u8>,
        stdout: Vec<u8>,
        timeout: Duration,
        #[source]
        source: IoError,
    },

    #[error("输出不是有效的 UTF-8: {0}")]
    Utf8(#[from] FromUtf8Error),
}

/// FLOSS 进程输出。
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FlossOutput {
    pub args: Vec<OsString>,
    pub program: OsString,
    pub status: ExitStatus,
    pub stderr: Vec<u8>,
    pub stdout: Vec<u8>,
}

/// 已解析的命令行信息，便于日志与审计。
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CommandLine {
    pub args: Vec<OsString>,
    pub program: OsString,
}

impl fmt::Display for CommandLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "program={} args=[", self.program.to_string_lossy())?;
        for (index, arg) in self.args.iter().enumerate() {
            if index > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", arg.to_string_lossy())?;
        }
        write!(f, "]")
    }
}

/// 限量读取输出时的结果（stdout/stderr 可能被截断）。
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FlossOutputLimited {
    pub args: Vec<OsString>,
    pub program: OsString,
    pub status: ExitStatus,
    pub stderr: Vec<u8>,
    pub stderr_truncated: bool,
    pub stdout: Vec<u8>,
    pub stdout_truncated: bool,
}

impl FlossOutput {
    /// 将 stderr 以“容错方式”解码（遇到非法 UTF-8 会替换为 U+FFFD）。
    #[must_use]
    pub fn stderr_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.stderr)
    }

    /// 将 stderr 按 UTF-8 严格解码。
    ///
    /// # Errors
    /// - 当 stderr 不是有效的 UTF-8 时，返回 `FlossError::Utf8`。
    pub fn stderr_string(&self) -> Result<String> {
        Ok(String::from_utf8(self.stderr.clone())?)
    }

    /// 将 stdout 以“容错方式”解码（遇到非法 UTF-8 会替换为 U+FFFD）。
    #[must_use]
    pub fn stdout_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.stdout)
    }

    /// 将 stdout 按 UTF-8 严格解码。
    ///
    /// # Errors
    /// - 当 stdout 不是有效的 UTF-8 时，返回 `FlossError::Utf8`。
    pub fn stdout_string(&self) -> Result<String> {
        Ok(String::from_utf8(self.stdout.clone())?)
    }
}

/// FLOSS CLI 入口配置（可执行文件名/路径、基础参数、工作目录与环境变量）。
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FlossCli {
    /// 启动时的基础参数（例如 `python -m floss` 的 `-m floss`）。
    base_args: Vec<OsString>,
    /// 可选工作目录。
    current_dir: Option<PathBuf>,
    /// 额外注入的环境变量。
    env: Vec<(OsString, OsString)>,
    /// 可执行文件名/路径，或 Python 解释器路径（当使用 `python -m floss` 时）。
    program: OsString,
    /// 进程执行超时（超过该时间会尝试终止子进程）。
    timeout: Option<Duration>,
}

impl FlossCli {
    /// 构建一次调用（可继续追加参数、可选追加样本路径），最后用 `run/run_raw/run_json` 执行。
    #[must_use]
    pub fn command(&self) -> FlossCommand {
        FlossCommand {
            args: Vec::new(),
            base_args: self.base_args.clone(),
            current_dir: self.current_dir.clone(),
            env: self.env.clone(),
            program: self.program.clone(),
            sample: None,
            timeout: self.timeout,
        }
    }

    /// 自动探测调用方式：
    /// 1) 若设置 `FLOSS_EXE`，优先使用该值作为可执行文件；
    /// 2) 若设置 `FLOSS_PYTHON`，优先尝试 `FLOSS_PYTHON {FLOSS_PYTHON_ARGS} -m floss -h`；
    /// 3) 否则检测 PATH 中是否存在 `floss.exe`（Windows）或 `floss`（其他系统）；
    /// 4) 最后尝试 Python：Windows 依次尝试 `python/python3/py -3`，其他系统依次尝试 `python3/python`。
    ///
    /// # Errors
    /// - 当既找不到可执行的 `floss`，也找不到可运行 `python -m floss` 的 Python 时，返回 `FlossError::AutoDetectFailed`。
    pub async fn detect() -> Result<Self> {
        if let Some(exe) = env::var_os("FLOSS_EXE") {
            if exe.is_empty() {
                return Err(FlossError::AutoDetectFailed {
                    message: "FLOSS_EXE 为空，无法作为可执行文件".to_owned(),
                });
            }
            return Ok(Self::new(exe));
        }

        if let Some(python) = env::var_os("FLOSS_PYTHON") {
            if python.is_empty() {
                return Err(FlossError::AutoDetectFailed {
                    message: "FLOSS_PYTHON 为空，无法作为 Python 解释器".to_owned(),
                });
            }
            let python_args = env::var_os("FLOSS_PYTHON_ARGS")
                .map(|value| parse_env_args(&value))
                .unwrap_or_default();
            if python_module_available_os_args(python.as_os_str(), &python_args).await {
                return Ok(Self::python_module_with_os_args(python, &python_args));
            }
            return Err(FlossError::AutoDetectFailed {
                message: format!(
                    "FLOSS_PYTHON 指定的 Python 无法执行 `-m floss -h`: {}",
                    python.as_os_str().display()
                ),
            });
        }

        if let Some(path_os_string) = env::var_os("PATH") {
            let path_os_str = path_os_string.as_os_str();
            if cfg!(windows) {
                if let Some(found) = find_in_path(path_os_str, OsStr::new("floss.exe")) {
                    return Ok(Self::new(found));
                }
            }

            if let Some(found) = find_in_path(path_os_str, OsStr::new("floss")) {
                return Ok(Self::new(found));
            }
        }

        let python_candidates: &[PythonCandidate] = if cfg!(windows) {
            &[
                PythonCandidate::new("python", &[]),
                PythonCandidate::new("python3", &[]),
                PythonCandidate::new("py", &["-3"]),
            ]
        } else {
            &[
                PythonCandidate::new("python3", &[]),
                PythonCandidate::new("python", &[]),
            ]
        };

        for candidate in python_candidates {
            if python_module_available(candidate.program, candidate.extra_args).await {
                return Ok(Self::python_module_with_args(
                    candidate.program,
                    candidate.extra_args,
                ));
            }
        }

        Err(FlossError::AutoDetectFailed {
            message: "PATH 中未找到 floss.exe，且未找到可成功执行 `python -m floss -h` 的 Python".to_owned(),
        })
    }

    /// 等价于执行 `floss -h`，返回 stdout。
    ///
    /// # Errors
    /// - 当启动进程失败时，返回 `FlossError::Io`。
    /// - 当 stdout 不是有效 UTF-8 时，返回 `FlossError::Utf8`。
    pub async fn help(&self) -> Result<String> {
        self.command().arg("-h").run_raw().await?.stdout_string()
    }

    /// 等价于执行 `floss -H`，返回 stdout（包含高级参数）。
    ///
    /// # Errors
    /// - 当启动进程失败时，返回 `FlossError::Io`。
    /// - 当 stdout 不是有效 UTF-8 时，返回 `FlossError::Utf8`。
    pub async fn help_all(&self) -> Result<String> {
        self.command().arg("-H").run_raw().await?.stdout_string()
    }

    /// 使用一个可执行程序名/路径创建实例，例如：`floss` 或 `floss.exe` 或绝对路径。
    #[must_use]
    pub fn new<Program>(program: Program) -> Self
    where
        Program: Into<OsString>,
    {
        Self {
            base_args: Vec::new(),
            current_dir: None,
            env: Vec::new(),
            program: program.into(),
            timeout: None,
        }
    }

    /// 返回当前配置使用的可执行程序（或 Python 解释器）路径/名称。
    #[must_use]
    pub fn program(&self) -> &OsStr {
        self.program.as_os_str()
    }

    /// 通过 `python -m floss` 方式调用（适合只安装了 Python 包、没有独立 floss 可执行文件的场景）。
    #[must_use]
    pub fn python_module<Python>(python: Python) -> Self
    where
        Python: Into<OsString>,
    {
        Self::python_module_with_args(python, &[])
    }

    fn python_module_with_args<Python>(python: Python, extra_args: &[&str]) -> Self
    where
        Python: Into<OsString>,
    {
        let mut base_args = Vec::with_capacity(extra_args.len() + 2);
        for arg in extra_args {
            base_args.push(OsString::from(*arg));
        }
        base_args.push(OsString::from("-m"));
        base_args.push(OsString::from("floss"));

        Self {
            base_args,
            current_dir: None,
            env: Vec::new(),
            program: python.into(),
            timeout: None,
        }
    }

    fn python_module_with_os_args<Python>(python: Python, extra_args: &[OsString]) -> Self
    where
        Python: Into<OsString>,
    {
        let mut base_args = Vec::with_capacity(extra_args.len() + 2);
        for arg in extra_args {
            base_args.push(arg.clone());
        }
        base_args.push(OsString::from("-m"));
        base_args.push(OsString::from("floss"));

        Self {
            base_args,
            current_dir: None,
            env: Vec::new(),
            program: python.into(),
            timeout: None,
        }
    }

    /// 等价于执行 `floss --version`，返回 stdout。
    ///
    /// # Errors
    /// - 当启动进程失败时，返回 `FlossError::Io`。
    /// - 当 stdout 不是有效 UTF-8 时，返回 `FlossError::Utf8`。
    pub async fn version(&self) -> Result<String> {
        self.command().arg("--version").run_raw().await?.stdout_string()
    }

    /// 设置工作目录（`Command::current_dir`）。
    #[must_use]
    pub fn with_current_dir<Dir>(mut self, dir: Dir) -> Self
    where
        Dir: Into<PathBuf>,
    {
        self.current_dir = Some(dir.into());
        self
    }

    /// 增加环境变量（`Command::env`）。
    #[must_use]
    pub fn with_env<Key, Value>(mut self, key: Key, value: Value) -> Self
    where
        Key: Into<OsString>,
        Value: Into<OsString>,
    {
        self.env.push((key.into(), value.into()));
        self
    }

    /// 设置执行超时：超过该时间会尝试终止子进程并返回 `FlossError::TimedOut`。
    /// 若无法终止子进程，则返回 `FlossError::TimedOutKillFailed`。
    /// 若无法终止子进程，则返回 `FlossError::TimedOutKillFailed`。
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

/// 一次具体的 FLOSS 调用（可透传任意参数，保证“全功能”覆盖）。
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FlossCommand {
    /// 透传给 FLOSS 的参数（不做语义校验）。
    args: Vec<OsString>,
    /// 启动时的基础参数（例如 `python -m floss` 的 `-m floss`）。
    base_args: Vec<OsString>,
    /// 可选工作目录。
    current_dir: Option<PathBuf>,
    /// 额外注入的环境变量。
    env: Vec<(OsString, OsString)>,
    /// 可执行文件名/路径，或 Python 解释器路径（当使用 `python -m floss` 时）。
    program: OsString,
    /// 样本路径（FLOSS 的位置参数 `sample`）。
    sample: Option<PathBuf>,
    /// 进程执行超时（超过该时间会尝试终止子进程）。
    timeout: Option<Duration>,
}

impl FlossCommand {
    /// 追加一个原始参数（完全透传，不做语义校验）。
    #[must_use]
    pub fn arg<Argument>(mut self, arg: Argument) -> Self
    where
        Argument: Into<OsString>,
    {
        self.args.push(arg.into());
        self
    }

    /// 追加多个原始参数（完全透传，不做语义校验）。
    #[must_use]
    pub fn args<Arguments, Argument>(mut self, args: Arguments) -> Self
    where
        Arguments: IntoIterator<Item = Argument>,
        Argument: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// 返回本次调用的命令行信息（含 `--` 与 sample）。
    #[must_use]
    pub fn command_line(&self) -> CommandLine {
        let prepared = self.clone().prepare();
        CommandLine {
            args: prepared.args,
            program: prepared.program,
        }
    }

    /// 执行命令并检查退出码（非 0 返回 `FlossError::NonZeroExit`）。
    ///
    /// # Errors
    /// - 当启动进程失败时，返回 `FlossError::Io`。
    /// - 当进程退出码非 0 时，返回 `FlossError::NonZeroExit`（包含 stdout/stderr）。
    pub async fn run(self) -> Result<FlossOutput> {
        let out = self.run_raw().await?;
        if out.status.success() {
            Ok(out)
        } else {
            let FlossOutput {
                args,
                program,
                status,
                stderr,
                stdout,
            } = out;
            Err(FlossError::NonZeroExit {
                command: Box::new(CommandLine { args, program }),
                status,
                stderr,
                stdout,
            })
        }
    }

    /// 执行命令并允许指定退出码视为成功。
    ///
    /// # Errors
    /// - 当启动进程失败时，返回 `FlossError::Io`。
    /// - 当退出码不在允许列表时，返回 `FlossError::NonZeroExit`（包含 stdout/stderr）。
    pub async fn run_allow_exit_codes<Codes>(self, codes: Codes) -> Result<FlossOutput>
    where
        Codes: IntoIterator<Item = i32> + Send,
        Codes::IntoIter: Send,
    {
        let out = self.run_raw().await?;
        if out.status.success() {
            return Ok(out);
        }

        if let Some(code) = out.status.code() {
            if codes.into_iter().any(|allowed| allowed == code) {
                return Ok(out);
            }
        }

        let FlossOutput {
            args,
            program,
            status,
            stderr,
            stdout,
        } = out;
        Err(FlossError::NonZeroExit {
            command: Box::new(CommandLine { args, program }),
            status,
            stderr,
            stdout,
        })
    }

    /// 以 JSON 方式运行 FLOSS 并反序列化输出。
    ///
    /// - 若未显式传入 `-j/--json`，会自动补上 `-j`。
    /// - 该方法默认会检查退出码（非 0 直接返回错误）。
    ///
    /// # Errors
    /// - 当启动进程失败时，返回 `FlossError::Io`。
    /// - 当进程退出码非 0 时，返回 `FlossError::NonZeroExit`（包含 stdout/stderr）。
    /// - 当 stdout 不是有效 JSON 时，返回 `FlossError::Json`。
    pub async fn run_json<Output>(self) -> Result<Output>
    where
        Output: DeserializeOwned,
    {
        let has_json_flag = self.args.iter().any(|argument| {
            let argument_os_str = argument.as_os_str();
            argument_os_str == OsStr::new("-j") || argument_os_str == OsStr::new("--json")
        });

        let out = if has_json_flag {
            self.run().await?
        } else {
            self.arg("-j").run().await?
        };
        Ok(serde_json::from_slice(&out.stdout)?)
    }

    /// 以 JSON 方式运行 FLOSS 并解析为 `ResultDocument`。
    ///
    /// - 若未显式传入 `-j/--json`，会自动补上 `-j`。
    /// - 该方法默认会检查退出码（非 0 直接返回错误）。
    ///
    /// # Errors
    /// - 当启动进程失败时，返回 `FlossError::Io`。
    /// - 当进程退出码非 0 时，返回 `FlossError::NonZeroExit`（包含 stdout/stderr）。
    /// - 当 stdout 不是有效 JSON 时，返回 `FlossError::Json`。
    pub async fn run_results(self) -> Result<ResultDocument> {
        self.run_json::<ResultDocument>().await
    }

    /// 执行命令并返回输出（不检查退出码）。
    ///
    /// # Errors
    /// - 当启动进程失败时，返回 `FlossError::Io`。
    /// - 当超时且无法终止进程时，返回 `FlossError::TimedOutKillFailed`。
    pub async fn run_raw(self) -> Result<FlossOutput> {
        let prepared = self.prepare();
        let mut cmd = prepared.command();
        configure_process_group(&mut cmd);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn()?;
        let job = create_job_for_child(&child);
        let stdout_reader = child
            .stdout
            .take()
            .ok_or_else(|| IoError::other("无法捕获 stdout"))?;
        let stderr_reader = child
            .stderr
            .take()
            .ok_or_else(|| IoError::other("无法捕获 stderr"))?;

        let stdout_handle = tokio::spawn(async move { read_all(stdout_reader).await });
        let stderr_handle = tokio::spawn(async move { read_all(stderr_reader).await });

        let wait_outcome = match prepared.timeout {
            Some(timeout) => wait_with_timeout(&mut child, timeout, job.as_ref()).await?,
            None => WaitOutcome::Exited(child.wait().await?),
        };

        let PreparedCommand {
            args,
            program,
            timeout,
            ..
        } = prepared;

        match wait_outcome {
            WaitOutcome::Exited(status) => {
                let stdout = join_io(stdout_handle, "stdout").await?;
                let stderr = join_io(stderr_handle, "stderr").await?;
                Ok(FlossOutput {
                    args,
                    program,
                    status,
                    stderr,
                    stdout,
                })
            }
            WaitOutcome::TimedOut { kill_error, reaped } => {
                let timeout = timeout.unwrap_or_default();
                let command = Box::new(CommandLine { args, program });
                if reaped {
                    let stdout = join_io(stdout_handle, "stdout").await?;
                    let stderr = join_io(stderr_handle, "stderr").await?;
                    return Err(FlossError::TimedOut {
                        command,
                        stderr,
                        stdout,
                        timeout,
                    });
                }

                stdout_handle.abort();
                stderr_handle.abort();

                let stdout = Vec::new();
                let stderr = Vec::new();
                if let Some(source) = kill_error {
                    return Err(FlossError::TimedOutKillFailed {
                        command,
                        stderr,
                        stdout,
                        timeout,
                        source,
                    });
                }

                Err(FlossError::TimedOut {
                    command,
                    stderr,
                    stdout,
                    timeout,
                })
            }
        }
    }

    /// 执行命令并以固定上限读取 stdout/stderr（不检查退出码）。
    ///
    /// - 若输出超过 `max_bytes`，仅保留前 `max_bytes` 字节，剩余字节会被丢弃。
    ///
    /// # Errors
    /// - 当启动进程失败时，返回 `FlossError::Io`。
    /// - 当超过超时时间时，返回 `FlossError::TimedOut`（stdout/stderr 可能被截断）。
    /// - 当超时且无法终止进程时，返回 `FlossError::TimedOutKillFailed`。
    pub async fn run_raw_limited(self, max_bytes: usize) -> Result<FlossOutputLimited> {
        let prepared = self.prepare();
        let mut cmd = prepared.command();
        configure_process_group(&mut cmd);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn()?;
        let job = create_job_for_child(&child);
        let stdout_reader = child
            .stdout
            .take()
            .ok_or_else(|| IoError::other("无法捕获 stdout"))?;
        let stderr_reader = child
            .stderr
            .take()
            .ok_or_else(|| IoError::other("无法捕获 stderr"))?;

        let stdout_handle =
            tokio::spawn(async move { read_all_limited(stdout_reader, max_bytes).await });
        let stderr_handle =
            tokio::spawn(async move { read_all_limited(stderr_reader, max_bytes).await });

        let wait_outcome = match prepared.timeout {
            Some(timeout) => wait_with_timeout(&mut child, timeout, job.as_ref()).await?,
            None => WaitOutcome::Exited(child.wait().await?),
        };

        let PreparedCommand {
            args,
            program,
            timeout,
            ..
        } = prepared;

        match wait_outcome {
            WaitOutcome::Exited(status) => {
                let stdout = join_io(stdout_handle, "stdout").await?;
                let stderr = join_io(stderr_handle, "stderr").await?;
                Ok(FlossOutputLimited {
                    args,
                    program,
                    status,
                    stderr: stderr.data,
                    stderr_truncated: stderr.truncated,
                    stdout: stdout.data,
                    stdout_truncated: stdout.truncated,
                })
            }
            WaitOutcome::TimedOut { kill_error, reaped } => {
                let timeout = timeout.unwrap_or_default();
                let command = Box::new(CommandLine { args, program });
                if reaped {
                    let stdout = join_io(stdout_handle, "stdout").await?;
                    let stderr = join_io(stderr_handle, "stderr").await?;
                    return Err(FlossError::TimedOut {
                        command,
                        stderr: stderr.data,
                        stdout: stdout.data,
                        timeout,
                    });
                }

                stdout_handle.abort();
                stderr_handle.abort();

                let stdout = Vec::new();
                let stderr = Vec::new();
                if let Some(source) = kill_error {
                    return Err(FlossError::TimedOutKillFailed {
                        command,
                        stderr,
                        stdout,
                        timeout,
                        source,
                    });
                }

                Err(FlossError::TimedOut {
                    command,
                    stderr,
                    stdout,
                    timeout,
                })
            }
        }
    }

    /// 执行命令并将 stdout/stderr 直连终端（不检查退出码）。
    ///
    /// # Errors
    /// - 当启动进程失败时，返回 `FlossError::Io`。
    /// - 当超过超时时间时，返回 `FlossError::TimedOut`（stderr/stdout 为空）。
    /// - 当超时且无法终止进程时，返回 `FlossError::TimedOutKillFailed`（stderr/stdout 为空）。
    pub async fn run_inherit(self) -> Result<ExitStatus> {
        self.run_inherit_impl(false).await
    }

    /// 执行命令并将 stdout/stderr 直连终端（退出码非 0 返回错误）。
    ///
    /// # Errors
    /// - 当启动进程失败时，返回 `FlossError::Io`。
    /// - 当超过超时时间时，返回 `FlossError::TimedOut`（stderr/stdout 为空）。
    /// - 当超时且无法终止进程时，返回 `FlossError::TimedOutKillFailed`（stderr/stdout 为空）。
    /// - 当退出码非 0 时，返回 `FlossError::NonZeroExit`（stderr/stdout 为空）。
    pub async fn run_inherit_checked(self) -> Result<ExitStatus> {
        self.run_inherit_impl(true).await
    }

    /// 启动子进程并将 stdout/stderr 直连终端，返回 `Child` 由调用方管理。
    ///
    /// 注意：该方法不处理超时，由调用方自行管理。
    ///
    /// # Errors
    /// - 当启动进程失败时，返回 `FlossError::Io`。
    pub fn spawn(self) -> Result<Child> {
        let prepared = self.prepare();
        let mut cmd = prepared.command();
        cmd.stdin(Stdio::inherit());
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());
        Ok(cmd.spawn()?)
    }

    /// 启动子进程并将 stdout/stderr 设为 piped，返回 `Child` 由调用方管理。
    ///
    /// 注意：该方法不处理超时，由调用方自行管理。
    ///
    /// # Errors
    /// - 当启动进程失败时，返回 `FlossError::Io`。
    pub fn spawn_piped(self) -> Result<Child> {
        let prepared = self.prepare();
        let mut cmd = prepared.command();
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        Ok(cmd.spawn()?)
    }

    /// 设置样本（FLOSS 的位置参数 `sample`）。
    ///
    /// 内部会自动插入 `--`，避免样本路径以 `-` 开头时被误解析为参数。
    #[must_use]
    pub fn sample<Sample>(mut self, sample: Sample) -> Self
    where
        Sample: AsRef<Path>,
    {
        self.sample = Some(sample.as_ref().to_path_buf());
        self
    }

    /// 设置执行超时：超过该时间会尝试终止子进程并返回 `FlossError::TimedOut`。
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    async fn run_inherit_impl(self, check_exit: bool) -> Result<ExitStatus> {
        let prepared = self.prepare();
        let mut cmd = prepared.command();
        configure_process_group(&mut cmd);
        cmd.stdin(Stdio::inherit());
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());

        let mut child = cmd.spawn()?;
        let job = create_job_for_child(&child);
        let wait_outcome = match prepared.timeout {
            Some(timeout) => wait_with_timeout(&mut child, timeout, job.as_ref()).await?,
            None => WaitOutcome::Exited(child.wait().await?),
        };

        let PreparedCommand {
            args,
            program,
            timeout,
            ..
        } = prepared;

        let status = match wait_outcome {
            WaitOutcome::Exited(status) => status,
            WaitOutcome::TimedOut { kill_error, .. } => {
                let timeout = timeout.unwrap_or_default();
                let command = Box::new(CommandLine { args, program });
                if let Some(source) = kill_error {
                    return Err(FlossError::TimedOutKillFailed {
                        command,
                        stderr: Vec::new(),
                        stdout: Vec::new(),
                        timeout,
                        source,
                    });
                }
                return Err(FlossError::TimedOut {
                    command,
                    stderr: Vec::new(),
                    stdout: Vec::new(),
                    timeout,
                });
            }
        };

        if check_exit && !status.success() {
            let command = Box::new(CommandLine { args, program });
            return Err(FlossError::NonZeroExit {
                command,
                status,
                stderr: Vec::new(),
                stdout: Vec::new(),
            });
        }

        Ok(status)
    }
}

/// 在给定 `PATH` 中搜索指定文件名，返回第一个可执行路径。
fn find_in_path(path: &OsStr, file_name: &OsStr) -> Option<PathBuf> {
    for dir in env::split_paths(path) {
        let candidate = dir.join(file_name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

struct PreparedCommand {
    args: Vec<OsString>,
    current_dir: Option<PathBuf>,
    env: Vec<(OsString, OsString)>,
    program: OsString,
    timeout: Option<Duration>,
}

impl PreparedCommand {
    fn command(&self) -> Command {
        let mut cmd = Command::new(&self.program);
        cmd.args(&self.args);

        if let Some(dir) = self.current_dir.as_ref() {
            cmd.current_dir(dir);
        }

        for (key, value) in &self.env {
            cmd.env(key, value);
        }

        cmd
    }
}

impl FlossCommand {
    fn prepare(self) -> PreparedCommand {
        let mut final_args = Vec::with_capacity(self.base_args.len() + self.args.len() + 2);
        final_args.extend(self.base_args);
        final_args.extend(self.args);
        if let Some(sample) = self.sample {
            final_args.push(OsString::from("--"));
            final_args.push(sample.into_os_string());
        }

        PreparedCommand {
            args: final_args,
            current_dir: self.current_dir,
            env: self.env,
            program: self.program,
            timeout: self.timeout,
        }
    }
}

fn parse_env_args(value: &OsStr) -> Vec<OsString> {
    let input = value.to_string_lossy();
    let mut args = Vec::new();
    let mut buf = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut arg_started = false;
    let mut escape = false;

    for ch in input.chars() {
        if escape {
            buf.push(ch);
            arg_started = true;
            escape = false;
            continue;
        }

        if ch == '\\' {
            if in_single {
                buf.push(ch);
                arg_started = true;
            } else if in_double {
                escape = true;
            } else {
                escape = true;
                arg_started = true;
            }
            continue;
        }

        if in_single {
            if ch == '\'' {
                in_single = false;
            } else {
                buf.push(ch);
            }
            arg_started = true;
            continue;
        }

        if in_double {
            if ch == '"' {
                in_double = false;
            } else {
                buf.push(ch);
            }
            arg_started = true;
            continue;
        }

        if ch.is_whitespace() {
            if arg_started {
                args.push(OsString::from(std::mem::take(&mut buf)));
                arg_started = false;
            }
            continue;
        }

        if ch == '\'' {
            in_single = true;
            arg_started = true;
            continue;
        }

        if ch == '"' {
            in_double = true;
            arg_started = true;
            continue;
        }

        buf.push(ch);
        arg_started = true;
    }

    if escape && !in_single {
        buf.push('\\');
    }

    if arg_started {
        args.push(OsString::from(buf));
    }

    args
}

struct PythonCandidate {
    extra_args: &'static [&'static str],
    program: &'static str,
}

impl PythonCandidate {
    const fn new(program: &'static str, extra_args: &'static [&'static str]) -> Self {
        Self { extra_args, program }
    }
}

async fn python_module_available<Program>(program: Program, extra_args: &[&str]) -> bool
where
    Program: AsRef<OsStr>,
{
    let status = Command::new(program.as_ref())
        .args(extra_args)
        .args(["-m", "floss", "-h"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;

    matches!(status, Ok(exit_status) if exit_status.success())
}

async fn python_module_available_os_args(program: &OsStr, extra_args: &[OsString]) -> bool {
    let status = Command::new(program)
        .args(extra_args)
        .args(["-m", "floss", "-h"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;

    matches!(status, Ok(exit_status) if exit_status.success())
}

async fn join_io<T>(handle: JoinHandle<std::io::Result<T>>, name: &str) -> std::io::Result<T> {
    match handle.await {
        Ok(result) => result,
        Err(_panic) => Err(IoError::other(format!("{name} 读取任务发生 panic"))),
    }
}

struct ReadLimited {
    data: Vec<u8>,
    truncated: bool,
}

async fn read_all<R>(mut reader: R) -> std::io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).await?;
    Ok(buf)
}

async fn read_all_limited<R>(mut reader: R, max_bytes: usize) -> std::io::Result<ReadLimited>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut truncated = false;
    let mut scratch = [0_u8; 8192];

    loop {
        let count = reader.read(&mut scratch).await?;
        if count == 0 {
            break;
        }

        if buf.len() < max_bytes {
            let remaining = max_bytes - buf.len();
            let to_copy = remaining.min(count);
            buf.extend_from_slice(&scratch[..to_copy]);
            if to_copy < count {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }

    Ok(ReadLimited { data: buf, truncated })
}

enum WaitOutcome {
    Exited(ExitStatus),
    TimedOut { kill_error: Option<IoError>, reaped: bool },
}

async fn wait_for_exit(child: &mut Child, grace: Duration) -> std::io::Result<bool> {
    match time::timeout(grace, child.wait()).await {
        Ok(status) => {
            status?;
            Ok(true)
        }
        Err(_elapsed) => Ok(false),
    }
}

async fn wait_with_timeout(
    child: &mut Child,
    timeout: Duration,
    job: Option<&JobObject>,
) -> std::io::Result<WaitOutcome> {
    match time::timeout(timeout, child.wait()).await {
        Ok(status) => Ok(WaitOutcome::Exited(status?)),
        Err(_elapsed) => {
            if let Some(status) = child.try_wait()? {
                return Ok(WaitOutcome::Exited(status));
            }

            if let Err(error) = kill_process_tree(child, job).await {
                return Ok(WaitOutcome::TimedOut {
                    kill_error: Some(error),
                    reaped: false,
                });
            }

            let reaped = wait_for_exit(child, Duration::from_millis(200)).await?;
            Ok(WaitOutcome::TimedOut {
                kill_error: None,
                reaped,
            })
        }
    }
}

#[cfg(unix)]
fn configure_process_group(cmd: &mut Command) {
    unsafe {
        cmd.pre_exec(|| {
            let _ = libc::setpgid(0, 0);
            Ok(())
        });
    }
}

#[cfg(not(unix))]
const fn configure_process_group(_cmd: &mut Command) {}

#[cfg(windows)]
struct JobObject(windows_sys::Win32::Foundation::HANDLE);

#[cfg(not(windows))]
struct JobObject;

#[cfg(windows)]
unsafe impl Send for JobObject {}

#[cfg(windows)]
unsafe impl Sync for JobObject {}

#[cfg(windows)]
impl JobObject {
    fn create() -> std::io::Result<Self> {
        use std::mem::size_of;
        use std::ptr::null_mut;
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };

        let handle = unsafe { CreateJobObjectW(null_mut(), null_mut()) };
        if handle.is_null() {
            return Err(IoError::last_os_error());
        }

        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let info_size = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
            .map_err(|_error| IoError::other("JOBOBJECT_EXTENDED_LIMIT_INFORMATION 大小溢出"))?;
        let info_ptr = std::ptr::addr_of!(info).cast();
        let result = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                info_ptr,
                info_size,
            )
        };

        if result == 0 {
            let error = IoError::last_os_error();
            unsafe {
                CloseHandle(handle);
            }
            return Err(error);
        }

        Ok(Self(handle))
    }

    fn assign_pid(&self, pid: u32) -> std::io::Result<()> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
        };

        let process_handle = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid) };
        if process_handle.is_null() {
            return Err(IoError::last_os_error());
        }

        let result = unsafe { AssignProcessToJobObject(self.0, process_handle) };
        unsafe {
            CloseHandle(process_handle);
        }
        if result == 0 {
            return Err(IoError::last_os_error());
        }

        Ok(())
    }

    fn terminate(&self) -> std::io::Result<()> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        let result = unsafe { TerminateJobObject(self.0, 1) };
        if result == 0 {
            Err(IoError::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(windows)]
impl Drop for JobObject {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        unsafe {
            CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
fn create_job_for_child(child: &Child) -> Option<JobObject> {
    let job = JobObject::create().ok()?;
    let pid = child.id()?;
    job.assign_pid(pid).ok()?;
    Some(job)
}

#[cfg(not(windows))]
const fn create_job_for_child(_child: &Child) -> Option<JobObject> {
    None
}

#[cfg(unix)]
async fn kill_process_tree(child: &mut Child, _job: Option<&JobObject>) -> std::io::Result<()> {
    let pid = match child.id() {
        Some(pid) => match i32::try_from(pid) {
            Ok(pid) => pid,
            Err(_error) => {
                return child
                    .kill()
                    .await
                    .map_err(|err| IoError::other(format!("killpg 目标 PID 无效: {err}")));
            }
        },
        None => {
            return child
                .kill()
                .await
                .map_err(|err| IoError::other(format!("无法获取子进程 PID: {err}")));
        }
    };

    let term_result = unsafe { libc::killpg(pid, libc::SIGTERM) };
    if term_result == 0 {
        if wait_for_exit(child, Duration::from_millis(100)).await? {
            return Ok(());
        }
    }

    let kill_result = unsafe { libc::killpg(pid, libc::SIGKILL) };
    if kill_result == 0 {
        return Ok(());
    }

    let killpg_error = IoError::last_os_error();
    if killpg_error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }

    match child.kill().await {
        Ok(()) => Ok(()),
        Err(kill_error) => Err(IoError::other(format!(
            "killpg 失败: {killpg_error}; kill 失败: {kill_error}"
        ))),
    }
}

#[cfg(windows)]
async fn kill_process_tree(child: &mut Child, job: Option<&JobObject>) -> std::io::Result<()> {
    let mut errors = Vec::new();
    if let Some(job) = job {
        if let Err(error) = job.terminate() {
            errors.push(format!("TerminateJobObject 失败: {error}"));
        } else {
            return Ok(());
        }
    }

    if let Some(pid) = child.id() {
        let mut cmd = Command::new("taskkill");
        cmd.args(["/T", "/F", "/PID", &pid.to_string()]);
        match cmd.status().await {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => {
                let code = status
                    .code()
                    .map_or_else(|| "unknown".to_owned(), |value| value.to_string());
                errors.push(format!("taskkill 失败: exit={code}"));
            }
            Err(error) => {
                errors.push(format!("taskkill 启动失败: {error}"));
            }
        }
    } else {
        errors.push("无法获取子进程 PID".to_owned());
    }

    if let Err(error) = child.kill().await {
        errors.push(format!("kill 失败: {error}"));
    } else {
        return Ok(());
    }

    Err(IoError::other(errors.join("; ")))
}

#[cfg(not(any(unix, windows)))]
async fn kill_process_tree(child: &mut Child, _job: Option<&JobObject>) -> std::io::Result<()> {
    child.kill().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::const_new(());

    struct EnvGuard {
        key: &'static str,
        original: Option<OsString>,
    }

    impl EnvGuard {
        fn remove(key: &'static str) -> Self {
            let original = env::var_os(key);
            env::remove_var(key);
            Self { key, original }
        }

        fn set(key: &'static str, value: OsString) -> Self {
            let original = env::var_os(key);
            env::set_var(key, value);
            Self { key, original }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(value) = self.original.take() {
                env::set_var(self.key, value);
            } else {
                env::remove_var(self.key);
            }
        }
    }

    async fn lock_env() -> tokio::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().await
    }

    fn success_command() -> FlossCommand {
        if cfg!(windows) {
            FlossCli::new("cmd")
                .command()
                .args(["/C", "exit", "/B", "0"])
        } else {
            FlossCli::new("sh").command().args(["-c", "exit 0"])
        }
    }

    fn failure_command() -> FlossCommand {
        if cfg!(windows) {
            FlossCli::new("cmd")
                .command()
                .args(["/C", "exit", "/B", "1"])
        } else {
            FlossCli::new("sh").command().args(["-c", "exit 1"])
        }
    }

    #[test]
    fn sample_is_appended_after_double_dash() {
        let cmd = FlossCli::new("floss")
            .command()
            .arg("--only")
            .args(["static", "decoded"])
            .sample("a.exe");

        assert!(cmd.sample.is_some());
    }

    #[tokio::test]
    async fn detects_floss_from_path() -> Result<()> {
        let _env_lock = lock_env().await;
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let tmp = env::temp_dir().join(format!("floss-cli-test-{suffix}"));
        fs::create_dir_all(&tmp)?;

        let file_name = if cfg!(windows) { "floss.exe" } else { "floss" };
        let expected = tmp.join(file_name);
        fs::write(&expected, b"")?;

        let original_path = env::var_os("PATH");
        let original_exe = env::var_os("FLOSS_EXE");
        let original_python = env::var_os("FLOSS_PYTHON");
        env::remove_var("FLOSS_EXE");
        env::remove_var("FLOSS_PYTHON");
        env::set_var("PATH", &tmp);

        let detected = FlossCli::detect().await;
        match original_path {
            Some(value) => env::set_var("PATH", value),
            None => env::remove_var("PATH"),
        }
        match original_exe {
            Some(value) => env::set_var("FLOSS_EXE", value),
            None => env::remove_var("FLOSS_EXE"),
        }
        match original_python {
            Some(value) => env::set_var("FLOSS_PYTHON", value),
            None => env::remove_var("FLOSS_PYTHON"),
        }

        let cli = detected?;
        if cli.program() == expected.as_os_str() {
            return Ok(());
        }

        Err(FlossError::AutoDetectFailed {
            message: format!(
                "自动探测结果不符合预期: expected={expected:?} actual={actual:?}",
                expected = expected.as_os_str(),
                actual = cli.program()
            ),
        })
    }

    #[tokio::test]
    async fn detect_prefers_floss_exe_env() -> Result<()> {
        let _env_lock = lock_env().await;
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let tmp = env::temp_dir().join(format!("floss-cli-test-exe-{suffix}"));
        fs::create_dir_all(&tmp)?;
        let file_name = if cfg!(windows) { "floss.exe" } else { "floss" };
        let exe_path = tmp.join(file_name);
        fs::write(&exe_path, b"")?;

        let _guard_exe = EnvGuard::set("FLOSS_EXE", exe_path.as_os_str().to_os_string());
        let _guard_python = EnvGuard::remove("FLOSS_PYTHON");

        let cli = FlossCli::detect().await?;
        assert_eq!(cli.program(), exe_path.as_os_str());
        Ok(())
    }

    #[tokio::test]
    async fn detect_rejects_empty_floss_exe() {
        let _env_lock = lock_env().await;
        let _guard_exe = EnvGuard::set("FLOSS_EXE", OsString::new());
        let _guard_python = EnvGuard::remove("FLOSS_PYTHON");

        let result = FlossCli::detect().await;
        assert!(matches!(result, Err(FlossError::AutoDetectFailed { .. })));
    }

    #[tokio::test]
    async fn detect_rejects_unavailable_floss_python() {
        let _env_lock = lock_env().await;
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let python_name = format!("definitely-not-a-python-{suffix}");

        let _guard_exe = EnvGuard::remove("FLOSS_EXE");
        let _guard_python = EnvGuard::set("FLOSS_PYTHON", OsString::from(python_name));

        let result = FlossCli::detect().await;
        assert!(matches!(result, Err(FlossError::AutoDetectFailed { .. })));
    }

    #[test]
    fn python_module_with_args_includes_extra_args() {
        let cli = FlossCli::python_module_with_args("py", &["-3"]);
        let expected = vec![
            OsString::from("-3"),
            OsString::from("-m"),
            OsString::from("floss"),
        ];
        assert_eq!(cli.base_args, expected);
        assert_eq!(cli.program, OsString::from("py"));
    }

    #[test]
    fn python_module_with_os_args_includes_extra_args() {
        let args = vec![OsString::from("-3.11")];
        let cli = FlossCli::python_module_with_os_args("py", &args);
        let expected = vec![
            OsString::from("-3.11"),
            OsString::from("-m"),
            OsString::from("floss"),
        ];
        assert_eq!(cli.base_args, expected);
        assert_eq!(cli.program, OsString::from("py"));
    }

    #[test]
    fn command_inherits_timeout() {
        let timeout = Duration::from_millis(250);
        let cli = FlossCli::new("floss").with_timeout(timeout);
        let cmd = cli.command();
        assert_eq!(cmd.timeout, Some(timeout));
    }

    #[test]
    fn prepare_inserts_double_dash_before_sample() {
        let sample = PathBuf::from("-sample.bin");
        let cmd = FlossCli::new("floss")
            .command()
            .arg("--only")
            .args(["static", "decoded"])
            .sample(&sample);
        let prepared = cmd.prepare();
        let args = prepared.args;
        assert!(args.len() >= 2);
        assert_eq!(args[args.len() - 2], OsString::from("--"));
        assert_eq!(args[args.len() - 1], sample.into_os_string());
    }

    #[test]
    fn prepare_appends_args_after_base_args() {
        let cli = FlossCli::python_module_with_args("py", &["-3"]);
        let extra_args = vec![OsString::from("--only"), OsString::from("static")];
        let cmd = cli.command().args(extra_args.clone());
        let expected_prefix = cli.base_args.as_slice();
        let prepared = cmd.prepare();
        assert!(prepared.args.starts_with(expected_prefix));
        assert_eq!(
            &prepared.args[expected_prefix.len()..],
            extra_args.as_slice()
        );
    }

    #[test]
    fn prepare_carries_env_and_current_dir() -> Result<()> {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let tmp = env::temp_dir().join(format!("floss-cli-test-dir-{suffix}"));
        fs::create_dir_all(&tmp)?;
        let cli = FlossCli::new("floss")
            .with_current_dir(&tmp)
            .with_env("FLOSS_CLI_TEST_KEY", "VALUE");
        let prepared = cli.command().prepare();
        assert_eq!(prepared.current_dir, Some(tmp));
        assert_eq!(
            prepared.env,
            vec![(OsString::from("FLOSS_CLI_TEST_KEY"), OsString::from("VALUE"))]
        );
        Ok(())
    }

    #[test]
    fn command_line_includes_sample_and_base_args() {
        let cmd = FlossCli::python_module_with_args("py", &["-3"])
            .command()
            .arg("--only")
            .sample("a.exe");
        let line = cmd.command_line();
        let expected = vec![
            OsString::from("-3"),
            OsString::from("-m"),
            OsString::from("floss"),
            OsString::from("--only"),
            OsString::from("--"),
            OsString::from("a.exe"),
        ];
        assert_eq!(line.program, OsString::from("py"));
        assert_eq!(line.args, expected);
    }

    #[tokio::test]
    async fn run_inherit_returns_success_status() -> Result<()> {
        let status = success_command().run_inherit().await?;
        assert!(status.success());
        Ok(())
    }

    #[tokio::test]
    async fn run_inherit_checked_reports_nonzero() {
        let result = failure_command().run_inherit_checked().await;
        assert!(matches!(result, Err(FlossError::NonZeroExit { .. })));
    }

    #[tokio::test]
    async fn run_allow_exit_codes_accepts_nonzero() -> Result<()> {
        let out = failure_command().run_allow_exit_codes([1]).await?;
        assert_eq!(out.status.code(), Some(1));
        Ok(())
    }

    #[tokio::test]
    async fn spawn_returns_child_with_success_status() -> Result<()> {
        let mut child = success_command().spawn()?;
        let status = child.wait().await?;
        assert!(status.success());
        Ok(())
    }

    #[test]
    fn parse_env_args_splits_whitespace() {
        let args = parse_env_args(OsStr::new("-3   -m floss"));
        let expected = vec![
            OsString::from("-3"),
            OsString::from("-m"),
            OsString::from("floss"),
        ];
        assert_eq!(args, expected);
    }

    #[test]
    fn parse_env_args_supports_double_quotes() {
        let args = parse_env_args(OsStr::new(r#"-m "floss cli""#));
        let expected = vec![OsString::from("-m"), OsString::from("floss cli")];
        assert_eq!(args, expected);
    }

    #[test]
    fn parse_env_args_supports_single_quotes() {
        let args = parse_env_args(OsStr::new(r"--path 'C:\Program Files\Floss'"));
        let expected = vec![
            OsString::from("--path"),
            OsString::from(r"C:\Program Files\Floss"),
        ];
        assert_eq!(args, expected);
    }

    #[test]
    fn parse_env_args_supports_double_quote_escape() {
        let args = parse_env_args(OsStr::new(r#"--name "a\"b c""#));
        let expected = vec![OsString::from("--name"), OsString::from("a\"b c")];
        assert_eq!(args, expected);
    }

    #[test]
    fn parse_env_args_keeps_mixed_tokens() {
        let args = parse_env_args(OsStr::new(r#"a"b c" 'd e' f"#));
        let expected = vec![
            OsString::from("ab c"),
            OsString::from("d e"),
            OsString::from("f"),
        ];
        assert_eq!(args, expected);
    }

    #[tokio::test]
    async fn read_all_limited_truncates() -> Result<()> {
        let data = [1_u8, 2, 3, 4, 5, 6];
        let limited = read_all_limited(&data[..], 4).await?;
        assert_eq!(limited.data, vec![1_u8, 2, 3, 4]);
        assert!(limited.truncated);
        Ok(())
    }
}
