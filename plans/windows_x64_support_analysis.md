# Windows x64 支持分析报告

**日期**: 2026-01-18
**测试样本**: `tests/samples/x64/` 目录下所有 PE 文件
**测试方法**: CLI 客户端实际运行测试

---

## 1. 测试概览

### 测试样本覆盖

| 样本 | 入口点 | 段数 | 节数 | 加载状态 |
|------|--------|------|------|----------|
| `binaryO0.exe` | `0x140002f9f` | 9 | 8 | ✅ 成功 |
| `binaryO1.exe` | `0x140002f9f` | 9 | 8 | ✅ 成功 |
| `binaryO2.exe` | `0x140002f9f` | 9 | 8 | ✅ 成功 |
| `binaryOx.exe` | `0x140002f9f` | 9 | 8 | ✅ 成功 |
| `binaryO2Strip.exe` | `0x140002b4c` | 7 | 6 | ✅ 成功 |

---

## 2. 功能支持状态

### 2.1 完全支持的功能 ✅

| 功能 | 状态 | 说明 |
|------|------|------|
| PE 加载 | ✅ | PE32+ (x64) 格式完全支持 |
| 格式识别 | ✅ | 正确识别为 PE 64-bit Little Endian |
| 入口点解析 | ✅ | 正确解析 AddressOfEntryPoint |
| 段/节解析 | ✅ | `.text`, `.rdata`, `.data`, `.pdata`, `.idata`, `.reloc` 等 |
| 导入表 | ✅ | 标准导入 + 延迟导入完整解析 |
| 导出表 | ✅ | 名称/序数导出支持 |
| 重定位表 | ✅ | `IMAGE_REL_BASED_DIR64` (type=10) 正确解析 |
| 反汇编 | ✅ | Capstone x86-64 指令解码正常 |
| LLIR 提升 | ✅ | 低级 IR 生成正常，SSA 形式，Phi 节点正常 |
| MLIR 提升 | ✅ | 中级 IR 生成正常 |

### 2.2 部分支持 / 有限制 ⚠️

| 功能 | 状态 | 问题描述 |
|------|------|----------|
| 函数发现 (fdisc) | ⚠️ | 大型二进制触发 `instruction limit reached` |
| PDB 符号加载 | ⚠️ | `raw_pdb` 库已集成，但未自动关联 `.pdb` 文件 |

### 2.3 不支持的功能 ❌

| 功能 | 状态 | 问题描述 |
|------|------|----------|
| HLIR 提升 | ❌ | 明确提示 `only arm64 is supported for now` |
| 伪代码生成 | ❌ | 同上，仅支持 ARM64 架构 |
| SEH 解析 | ❌ | `.pdata` 段已识别，但 UNWIND_INFO 未解析 |

---

## 3. 详细分析

### 3.1 PE 加载器 (`src/engine/loader/pe/`)

**优点**:
- 手工实现，跨平台兼容（可在 Linux 上分析 Windows PE）
- 完整支持 PE32/PE32+ 双格式
- 导入/导出/重定位表解析完善
- 边界检查严格，不易崩溃

**缺失**:
- 无 Exception Directory (`.pdata`) 解析
- 无 Debug Directory 解析
- 无 TLS Directory 解析
- 无 Load Config Directory 解析

### 3.2 x86-64 LLIR 提升器 (`src/engine/arch/x86_64/`)

**优点**:
- 常见指令集支持良好
- SSA 构造正常
- 控制流分析正确

**测试观察**:
```
LLIR 输出示例:
  0x14000b144: sub rsp, 0x28
    rsp#1 = sub(rsp#0, 0x28)
  0x14000b148: call 0x140003080
    call 0x140003080
```

### 3.3 HLIR / 伪代码 (关键缺口)

**现状**: 明确不支持 x86-64

```
hlil error: only arm64 is supported for now
pseudoc error: only arm64 is supported for now
```

**影响**: 这是该项目在 Windows x64 分析能力上的最大短板。

---

## 4. 改进计划

### 4.1 高优先级 (P0)

| 任务 | 描述 | 预估工作量 |
|------|------|-----------|
| x86-64 HLIR 支持 | 移植 ARM64 HLIR 逻辑到 x86-64 | 2-3 周 |
| x86-64 伪代码生成 | 基于 HLIR 的 C 代码输出 | 1-2 周 |

### 4.2 中优先级 (P1)

| 任务 | 描述 | 预估工作量 |
|------|------|-----------|
| PDB 自动加载 | 检测同目录 .pdb 文件并自动加载符号 | 2-3 天 |
| 函数发现优化 | 解决 `instruction limit reached` 问题 | 1 周 |
| SEH 解析 | 解析 `.pdata` 段的 RUNTIME_FUNCTION 结构 | 1 周 |

### 4.3 低优先级 (P2)

| 任务 | 描述 | 预估工作量 |
|------|------|-----------|
| Debug Directory | 支持 CodeView/PDB 路径提取 | 2-3 天 |
| TLS Directory | 解析 TLS 回调函数 | 2-3 天 |
| Load Config | 解析 CFG/XFG 相关元数据 | 3-5 天 |

---

## 5. 架构建议

### 5.1 HLIR x86-64 实现路径

```
现有 ARM64 管线:
  arm64/llil_lifter.cpp → mlil_lift.cpp → hlil_lift.cpp → pseudocode.cpp

建议 x86-64 管线:
  x86_64/llil_lifter.cpp (已有)
      ↓
  mlil_lift.cpp (已支持)
      ↓
  hlil_lift.cpp (需扩展: 条件码映射、寄存器别名)
      ↓
  pseudocode.cpp (需扩展: x86 调用约定)
```

### 5.2 关键差异点

| 方面 | ARM64 | x86-64 | 处理建议 |
|------|-------|--------|----------|
| 条件码 | NZCV | EFLAGS (ZF/SF/CF/OF) | 统一抽象层 |
| 调用约定 | AAPCS64 | Microsoft x64 / System V | 参数配置化 |
| 寄存器别名 | 无 | RAX/EAX/AX/AL 重叠 | 子寄存器跟踪 |
| 标志位使用 | 显式 | 隐式 (CMP/TEST 后条件跳转) | 标志位传播分析 |

---

## 6. 测试用例建议

### 6.1 新增测试覆盖

```cpp
// tests/pe_hlir_test.cpp (待创建)
TEST_CASE("x86_64 HLIR basic blocks") {
    // 测试基本块识别
}

TEST_CASE("x86_64 HLIR control flow") {
    // 测试 if/else/loop 结构恢复
}

TEST_CASE("x86_64 pseudocode output") {
    // 测试伪代码生成
}
```

### 6.2 回归测试

确保现有 ARM64 管线不受影响：
```bash
xmake run engine_tests "[hlir]"
xmake run engine_tests "[pseudocode]"
```

---

## 7. 结论

### 当前可用性评估

| 使用场景 | 可行性 |
|----------|--------|
| PE 格式解析与元数据提取 | ✅ 生产就绪 |
| x64 静态反汇编 | ✅ 生产就绪 |
| x64 低/中级 IR 分析 | ✅ 可用 |
| x64 高级反编译 (伪代码) | ❌ **不可用** |
| 带符号调试 (PDB) | ⚠️ 需手动处理 |

### 总体评价

Uranayzle 在 Windows x64 PE 文件的**加载、反汇编、低中级 IR 分析**层面已达到生产可用水平。

**关键短板**: x86-64 架构的 **HLIR 和伪代码生成尚未实现**，这是与 ARM64 相比最大的功能差距，也是后续开发的最高优先级任务。

---

## 8. 深度代码分析 (2026-01-18 更新)

### 8.1 架构限制的确切位置

**文件**: `clients/common/src/commands/ir_commands.cpp`

| 命令 | 限制行号 | 代码 |
|------|---------|------|
| `hlil` | 200-202 | `if (machine != engine::BinaryMachine::kAarch64) { output.write_line("hlil error: only arm64 is supported for now"); }` |
| `hlilraw` | 237-239 | 同上 |
| `pseudoc` | 278-281 | 同上 |

**关键发现**: 这是**人为限制**，不是技术限制。HLIR 和 pseudocode 管线本身是**架构无关的**。

### 8.2 MLIR 提升器的问题

**文件**: `src/engine/ir/mlil/mlil_lift.cpp`

```cpp
// Line 7-22: 仅支持 ARM64 寄存器前缀
std::size_t reg_size_from_name(const std::string& name) {
    switch (name[0]) {
        case 'w': return 4;   // ARM64: w0-w30
        case 'x': return 8;   // ARM64: x0-x30
        case 'b': return 1;   // ARM64: b0-b31
        // ... 无 x86-64 寄存器支持
    }
}
```

**需要添加的 x86-64 寄存器映射**:
- `rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp, r8-r15` → 8 bytes
- `eax, ebx, ecx, edx, esi, edi, esp, ebp, r8d-r15d` → 4 bytes
- `ax, bx, cx, dx, si, di, sp, bp, r8w-r15w` → 2 bytes
- `al, bl, cl, dl, sil, dil, spl, bpl, r8b-r15b` → 1 byte
- `xmm0-xmm15` → 16 bytes

### 8.3 EFLAGS 问题 (严重)

**文件**: `src/engine/arch/x86_64/llil_lifter.cpp`

当前 LLIR 输出显示标志位未正确计算:
```
0x14000aed1: test al, al
    flag_z = flag_z    # ❌ 应该是: flag_z = eq(al, 0)
    flag_s = flag_s
    flag_c = flag_c
    flag_o = flag_o
0x14000aed3: je 0x14000b00f
    if eq(<invalid>, 0x1) -> 0x14000b00f  # ❌ <invalid> 表示条件未正确传播
```

**根本原因**: `lift_cmp_test` 函数将标志位设为自身（占位符），而非实际计算结果。

### 8.4 ABI 参数恢复 (已支持)

**文件**: `src/engine/decompiler/passes/abi_params.cpp`

```cpp
// Line 33-47: 已有 x86-64 调用约定支持
static const std::unordered_map<std::string, int> kSysV = {
    {"reg.rdi", 0}, {"reg.rsi", 1}, {"reg.rdx", 2}, {"reg.rcx", 3},
    {"reg.r8", 4},  {"reg.r9", 5}, ...
};
static const std::unordered_map<std::string, int> kWin64 = {
    {"reg.rcx", 0}, {"reg.rdx", 1}, {"reg.r8", 2}, {"reg.r9", 3}, ...
};
```

✅ **已完成**: Win64 和 System V ABI 的寄存器参数映射已实现。

### 8.5 Session 层接口

**文件**: `src/engine/core/session.cpp`

| 函数 | 状态 |
|------|------|
| `build_llir_ssa_arm64` | ✅ 存在 |
| `build_llir_ssa_x86_64` | ✅ 存在 (Line 364-388) |
| `build_mlil_ssa_arm64` | ✅ 存在 (Line 305-339) |
| `build_mlil_ssa_x86_64` | ❌ **不存在** |
| `build_hlil_arm64` | ✅ 存在 (Line 341-362) |
| `build_hlil_x86_64` | ❌ **不存在** |

---

## 9. 最小可行实现 (MVP) 计划

### Phase 1: 快速解锁 (预计 2-3 天)

| 步骤 | 文件 | 修改内容 |
|------|------|----------|
| 1 | `mlil_lift.cpp` | 添加 x86-64 寄存器大小映射到 `reg_size_from_name()` |
| 2 | `session.cpp` | 添加 `build_mlil_ssa_x86_64()` (复用现有 `build_mlil_from_llil_ssa`) |
| 3 | `session.cpp` | 添加 `build_hlil_x86_64()` (复用 `build_hlil_from_mlil`) |
| 4 | `ir_commands.cpp` | 移除 HLIR/pseudoc 的架构检查，改用通用路径 |

**预期结果**: x86-64 可生成 HLIR 和 pseudocode，但条件跳转显示为 `<invalid>`。

### Phase 2: EFLAGS 支持 (预计 1 周)

| 步骤 | 文件 | 修改内容 |
|------|------|----------|
| 1 | `x86_64/llil_lifter.cpp` | 实现 `lift_cmp_test` 正确计算 ZF/SF/CF/OF |
| 2 | `x86_64/llil_lifter.cpp` | 实现条件码到表达式的转换 (JE→eq(flag_z,1) 等) |
| 3 | `mlil_lift.cpp` 或 新文件 | 可选: 添加标志位传播分析 |

**预期结果**: 条件跳转正确显示 `if (a == 0)` 而非 `<invalid>`。

### Phase 3: 质量提升 (持续)

- 增加 x86-64 特有指令支持 (LEA 优化、REP 前缀等)
- 寄存器别名合并 (RAX/EAX/AX/AL → 同一变量)
- 添加测试用例

---

## 附录: 测试命令参考

```bash
# 加载并查看基本信息
echo "open D:/devs/uranayzle/tests/samples/x64/binaryO0.exe
info
sh
symbols" | xmake run cli -s -

# 反汇编入口点
echo "open D:/devs/uranayzle/tests/samples/x64/binaryO0.exe
seek 0x14000b144
pd 30" | xmake run cli -s -

# LLIR 分析
echo "open D:/devs/uranayzle/tests/samples/x64/binaryO0.exe
llir 0x14000b144" | xmake run cli -s -

# MLIR 分析
echo "open D:/devs/uranayzle/tests/samples/x64/binaryO2.exe
mlil 0x140001000" | xmake run cli -s -
```
