项目状态（精简版）
- ELF：支持 REL/RELA；重定位扩展到 ABS64/GLOB_DAT/JUMP_SLOT/RELATIVE/IRELATIVE/TLS*；符号绑定按 sh_link 正确关联。
- ARM64 函数发现：新增序言扫描种子，逻辑已拆到 arch/arm64/；默认启用可关。
- LLIL：覆盖面扩展；SSA + def-use + call clobber 已就绪；可跑常量折叠/拷贝传播/死代码优化。
- MLIL：最小骨架已建立，可从 LLIL SSA 直译生成 CFG 形式 MLIL。
- DWARF：从仅收集 section 升级为解析函数/变量基础信息（subprogram/variable/formal_parameter），包含 low/high pc、name/linkage/type/location。
- EH frame：从只抓 FDE seed 升级为解析 CIE/FDE + CFI 指令，生成粗粒度 CFA 状态。
- Xrefs/Strings：xrefs 支持重定位辅助；strings 可绑定符号名（demangled 优先）。

短板
- DWARF：debug_str_offsets/strx 未解析。
- EH：CFA 规则未按 PC 展开，仅保留最终态。
- Xrefs：间接分支主要靠表达式求值，未做跳转表/动态分析。
- MLIL/HLIR：尚未进入结构化/变量恢复/伪 C 阶段。