// build.rs - 编译时生成版本信息（utwget-cli）
//
// 与根包 build.rs 相同：为 `--version` 输出导出 RUSTC_VERSION 和 TARGET。
// 该 crate 的 bin 目标（utwget-cli）直接编译 cli/src/main.rs，缺少此脚本时
// `env!("RUSTC_VERSION")` 会在编译期报错，导致 `cargo build --workspace`
// 失败（cargo 只为拥有 build.rs 的包注入这些变量）。

use std::env;

fn main() {
    let v = rustc_version_runtime::version();
    let rustc_version = format!("{}.{}.{}", v.major, v.minor, v.patch);
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());

    println!("cargo:rustc-env=RUSTC_VERSION={}", rustc_version);
    println!("cargo:rustc-env=TARGET={}", target);
    println!("cargo:rerun-if-changed=build.rs");
}
