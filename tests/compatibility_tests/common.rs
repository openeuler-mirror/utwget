// 兼容性测试框架 - 与原 GNU wget 1.21.4 行为对比
//
// 本模块提供测试框架，用于验证 utwget 与原 wget 的行为一致性。

use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::{Command, Output};

/// 原 wget 二进制路径
pub const WGET_ORIGINAL: &str = "/usr/local/bin/wget";

/// 获取 utwget 二进制路径
fn get_utwget_binary() -> PathBuf {
    // 尝试几个可能的路径
    let candidates = [
        // 1. CARGO_MANIFEST_DIR 环境变量指向的项目根目录
        std::env::var("CARGO_MANIFEST_DIR")
            .map(|p| PathBuf::from(p).join("target/debug/utwget"))
            .ok(),
        // 2. 当前工作目录
        std::env::current_dir()
            .ok()
            .map(|p| p.join("target/debug/utwget")),
        // 3. 相对于测试文件的路径
        Some(PathBuf::from(file!())
            .parent().and_then(|p| p.parent()).and_then(|p| p.parent())
            .map(|p| p.join("target/debug/utwget"))
            .unwrap_or_else(|| PathBuf::from("target/debug/utwget"))),
    ];

    for candidate in candidates.iter().flatten() {
        if candidate.exists() {
            return candidate.clone();
        }
    }

    // 默认返回相对路径（会在测试时失败并给出清晰错误）
    PathBuf::from("target/debug/utwget")
}

/// 测试临时目录
pub struct TestContext {
    /// 临时目录路径
    pub temp_dir: PathBuf,
    /// 原 wget 工作目录
    pub wget_dir: PathBuf,
    /// utwget 工作目录
    pub utwget_dir: PathBuf,
    /// utwget 二进制路径
    utwget_binary: PathBuf,
}

impl TestContext {
    /// 创建新的测试上下文
    pub fn new(name: &str) -> io::Result<Self> {
        let temp_dir = std::env::temp_dir().join(format!("utwget_test_{}_{}", name, std::process::id()));
        fs::create_dir_all(&temp_dir)?;

        let wget_dir = temp_dir.join("wget");
        let utwget_dir = temp_dir.join("utwget");
        fs::create_dir_all(&wget_dir)?;
        fs::create_dir_all(&utwget_dir)?;

        let utwget_binary = get_utwget_binary();

        Ok(Self { temp_dir, wget_dir, utwget_dir, utwget_binary })
    }

    /// 运行原 wget
    pub fn run_wget(&self, args: &[&str]) -> io::Result<CommandResult> {
        let output = Command::new(WGET_ORIGINAL)
            .args(args)
            .current_dir(&self.wget_dir)
            .output()?;

        Ok(CommandResult::from_output(output))
    }

    /// 运行 utwget
    pub fn run_utwget(&self, args: &[&str]) -> io::Result<CommandResult> {
        let output = Command::new(&self.utwget_binary)
            .args(args)
            .current_dir(&self.utwget_dir)
            .output()?;

        Ok(CommandResult::from_output(output))
    }

    /// 对比两个目录的文件
    pub fn compare_files(&self, filename: &str) -> io::Result<FileComparison> {
        let wget_file = self.wget_dir.join(filename);
        let utwget_file = self.utwget_dir.join(filename);

        let wget_exists = wget_file.exists();
        let utwget_exists = utwget_file.exists();

        let (wget_content, utwget_content) = if wget_exists && utwget_exists {
            (Some(fs::read(&wget_file)?), Some(fs::read(&utwget_file)?))
        } else {
            (None, None)
        };

        let (wget_size, utwget_size) = if wget_exists && utwget_exists {
            (Some(fs::metadata(&wget_file)?.len()), Some(fs::metadata(&utwget_file)?.len()))
        } else {
            (None, None)
        };

        Ok(FileComparison {
            filename: filename.to_string(),
            wget_exists,
            utwget_exists,
            wget_content,
            utwget_content,
            wget_size,
            utwget_size,
        })
    }

    /// 清理临时目录
    pub fn cleanup(&self) -> io::Result<()> {
        fs::remove_dir_all(&self.temp_dir)
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// 命令执行结果
#[derive(Debug)]
pub struct CommandResult {
    /// 退出码
    pub exit_code: i32,
    /// 标准输出
    pub stdout: String,
    /// 标准错误
    pub stderr: String,
    /// 是否成功 (退出码为 0)
    pub success: bool,
}

impl CommandResult {
    fn from_output(output: Output) -> Self {
        Self {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            success: output.status.success(),
        }
    }
}

/// 文件对比结果
#[derive(Debug)]
pub struct FileComparison {
    /// 文件名
    pub filename: String,
    /// 原 wget 是否存在该文件
    pub wget_exists: bool,
    /// utwget 是否存在该文件
    pub utwget_exists: bool,
    /// 原 wget 文件内容
    pub wget_content: Option<Vec<u8>>,
    /// utwget 文件内容
    pub utwget_content: Option<Vec<u8>>,
    /// 原 wget 文件大小
    pub wget_size: Option<u64>,
    /// utwget 文件大小
    pub utwget_size: Option<u64>,
}

impl FileComparison {
    /// 两个文件是否都存在
    pub fn both_exist(&self) -> bool {
        self.wget_exists && self.utwget_exists
    }

    /// 文件大小是否相同
    pub fn same_size(&self) -> bool {
        self.wget_size == self.utwget_size
    }

    /// 文件内容是否相同
    pub fn same_content(&self) -> bool {
        self.wget_content == self.utwget_content
    }

    /// 内容差异（如果都存在）
    pub fn content_diff(&self) -> Option<String> {
        if !self.both_exist() {
            return None;
        }

        let wget = self.wget_content.as_ref()?;
        let utwget = self.utwget_content.as_ref()?;

        if wget == utwget {
            return None;
        }

        // 简单的差异统计
        let diff_count = wget.iter().zip(utwget.iter())
            .filter(|(a, b)| a != b)
            .count();
        let len_diff = (wget.len() as i64 - utwget.len() as i64).abs();

        Some(format!("{} bytes differ, length diff: {}", diff_count, len_diff))
    }
}

/// 对比两个命令的结果
pub struct CommandComparison {
    /// 原 wget 结果
    pub wget: CommandResult,
    /// utwget 结果
    pub utwget: CommandResult,
}

impl CommandComparison {
    /// 退出码是否相同
    pub fn same_exit_code(&self) -> bool {
        self.wget.exit_code == self.utwget.exit_code
    }

    /// 是否都成功
    pub fn both_success(&self) -> bool {
        self.wget.success && self.utwget.success
    }

    /// 是否都失败
    pub fn both_failed(&self) -> bool {
        !self.wget.success && !self.utwget.success
    }

    /// 生成对比报告
    pub fn report(&self) -> String {
        let mut report = String::new();

        report.push_str(&format!("Exit code: wget={}, utwget={} {}\n",
            self.wget.exit_code, self.utwget.exit_code,
            if self.same_exit_code() { "✓" } else { "✗" }));

        report.push_str(&format!("Success: wget={}, utwget={} {}\n",
            self.wget.success, self.utwget.success,
            if self.wget.success == self.utwget.success { "✓" } else { "✗" }));

        report
    }
}

/// 需要网络连接的测试标记
#[macro_export]
macro_rules! require_network {
    () => {
        if std::env::var("SKIP_NETWORK_TESTS").is_ok() {
            println!("SKIP: network test (SKIP_NETWORK_TESTS is set)");
            return;
        }
    };
}

/// 需要本地 HTTP 服务器的测试标记
#[macro_export]
macro_rules! require_http_server {
    () => {
        if std::env::var("SKIP_SERVER_TESTS").is_ok() {
            println!("SKIP: server test (SKIP_SERVER_TESTS is set)");
            return;
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_creation() {
        let ctx = TestContext::new("test_context").expect("Failed to create context");
        assert!(ctx.wget_dir.exists());
        assert!(ctx.utwget_dir.exists());
    }

    #[test]
    fn test_wget_version() {
        let ctx = TestContext::new("version").expect("Failed to create context");
        let result = ctx.run_wget(&["--version"]).expect("Failed to run wget");
        assert!(result.success);
        assert!(result.stdout.contains("GNU Wget"));
    }

    #[test]
    fn test_utwget_version() {
        let ctx = TestContext::new("version").expect("Failed to create context");
        let result = ctx.run_utwget(&["--version"]).expect("Failed to run utwget");
        assert!(result.success);
        // utwget 版本输出包含 "utwget" 和版本号
        assert!(result.stdout.contains("utwget"),
            "Version output should contain 'utwget', got: {}", result.stdout);
        assert!(result.stdout.contains("0.1.0"),
            "Version output should contain '0.1.0', got: {}", result.stdout);
    }
}
