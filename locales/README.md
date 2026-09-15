# utwget i18n 说明

**翻译的唯一事实来源是 `utwget/core/src/i18n.rs` 中的内嵌表**
（en 与 zh-CN 两个 locale，约 350 条）。

本目录的 `en.yml` / `zh-CN.yml` 是**早期文档性快照，已过期**，
不参与编译或运行时加载（utwget 不使用 gettext/.mo，也没有运行时
YAML 加载）。修改翻译请直接编辑 `utwget/core/src/i18n.rs`。

`tests/unit_tests/i18n.rs` 中的 `yaml_keys_subset_of_table` 测试
会校验 YAML 中出现的键均存在于内嵌表，防止文档性文件进一步漂移
产生误导。
