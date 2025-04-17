# Deb 逆向分析自动化仓库

本项目通过 GitHub Actions + Python 脚本，实现对 `.deb` 包中 Mach-O dylib 插件的自动化逆向分析，并基于分析结果生成 Theos 源代码（Makefile、Tweak.xm、头文件等）。

## 使用方法

1. 将目标 `.deb` 放入 `deb/` 目录（例如 `deb/1.deb`）。
2. 通过 GitHub UI 手动触发 Action，指定输入参数 `deb/1.deb`。
3. Action 完成后，会生成并上传两组 artifact：
   - **raw-results**：原始分析数据（`file_info.txt`、`nm_output.txt`、`lief_export.txt`、`objc_symbols.txt` 等）
   - **src-results**：基于分析结果自动生成的 Theos 源代码（`Makefile`、`Tweak.xm`、`Plugin.h`）

## 本地运行

```bash
bash scripts/run_all.sh deb/1.deb
