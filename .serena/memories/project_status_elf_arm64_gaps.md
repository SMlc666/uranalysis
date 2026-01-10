ELF+ARM64 当前主要不足（优先级顺序）：
1) ELF 处理：仅处理 R_AARCH64_RELATIVE 重定位，未解析 GOT/PLT 动态符号与其他重定位类型。
2) 函数发现：仅直接 call/跳转 + 简单尾跳；无间接分支/跳转表、异常边界、prologue/epilogue 识别，函数边界精度不足。
3) LLIL 语义：指令覆盖与系统/向量语义不完整；flags 用 cmp_res 近似，未建模完整 NZCV。
4) MLIL/HLIR：MLIL 仅最小骨架与直译；缺变量/栈分析、类型推导、结构化控制流；HLIR/伪 C 未开始。
5) DWARF/EH：DWARF 只收集 section 未解析函数/类型/变量；EH frame 仅抓 FDE seed，无 CFA/规则/异常流。
6) Xrefs/字符串：xrefs 偏表达式求值，难覆盖复杂间接目标；字符串扫描未与符号/伪 C 联动。
7) 工程可用性：CLI/GUI 未展示 MLIL/SSA/def-use；测试覆盖弱，缺回归样本与质量基线。