// build.rs - 编译时生成版本信息

use std::env;

fn main() {
    // 获取 Rust 编译器版本
    let v = rustc_version_runtime::version();
    let rustc_version = format!("{}.{}.{}", v.major, v.minor, v.patch);

    // 获取目标平台
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());

    // 写入编译信息到环境变量
    println!("cargo:rustc-env=RUSTC_VERSION={}", rustc_version);
    println!("cargo:rustc-env=TARGET={}", target);

    // 重新运行构建脚本的条件
    println!("cargo:rerun-if-changed=build.rs");
}
