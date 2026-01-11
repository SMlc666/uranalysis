# Clients 全面重构计划

## 1. 现状分析

### 当前目录结构
```
clients/
├── cli/
│   └── main.cpp                    # CLI 入口 (REPL)
├── common/
│   ├── include/client/
│   │   ├── command.h               # 命令框架
│   │   ├── output.h                # 输出抽象
│   │   └── session.h               # Session alias
│   └── src/
│       ├── command.cpp             # 命令执行逻辑
│       ├── default_commands.cpp    # 巨型文件 (~2000行)
│       └── output.cpp              # 输出实现
└── imgui/
    ├── main.cpp                    # GUI 入口
    ├── imgui_app.h/cpp             # Win32 应用框架
    ├── imgui_ui.h/cpp              # 主 UI 渲染
    ├── file_browser.h/cpp          # 文件浏览器
    ├── functions_view.h/cpp        # 函数视图
    ├── names_view.h/cpp            # 符号视图
    ├── strings_view.h/cpp          # 字符串视图
    ├── view_window.h/cpp           # 主视图窗口
    └── win32_dx11.cpp/dx12.cpp     # DX 后端
```

### 主要问题
1. **代码重复**：CLI 和 ImGui 中大量重复的格式化函数
2. **巨型文件**：`default_commands.cpp` 近 2000 行
3. **缺乏抽象**：`session.h` 只是简单 alias
4. **耦合严重**：命令处理与格式化逻辑混合

---

## 2. 重构后目录结构

```
clients/
├── cli/
│   └── main.cpp                    # CLI 入口 (简化后)
├── common/
│   ├── include/client/
│   │   ├── command.h               # 命令框架 (增强)
│   │   ├── output.h                # 输出抽象
│   │   ├── session.h               # 增强的 Session 封装
│   │   ├── formatters/             # 共享格式化层
│   │   │   ├── address.h           # 地址格式化
│   │   │   ├── ir.h                # IR 格式化 (LLIR/MLIL/HLIL)
│   │   │   ├── symbols.h           # 符号格式化
│   │   │   ├── xrefs.h             # 交叉引用格式化
│   │   │   └── utils.h             # 通用工具
│   │   └── services/               # 数据服务层
│   │       ├── disasm_service.h    # 反汇编服务
│   │       ├── ir_service.h        # IR 构建服务
│   │       └── analysis_service.h  # 分析服务
│   └── src/
│       ├── command.cpp             # 命令执行逻辑
│       ├── output.cpp              # 输出实现
│       ├── session.cpp             # 增强的 Session 实现
│       ├── formatters/             # 格式化实现
│       │   ├── address.cpp
│       │   ├── ir.cpp
│       │   ├── symbols.cpp
│       │   ├── xrefs.cpp
│       │   └── utils.cpp
│       ├── services/               # 服务实现
│       │   ├── disasm_service.cpp
│       │   ├── ir_service.cpp
│       │   └── analysis_service.cpp
│       └── commands/               # 按功能拆分的命令
│           ├── file_commands.cpp      # open, close, info, ph, sh, relocs
│           ├── navigation_commands.cpp# seek, pd, px
│           ├── symbol_commands.cpp    # symbols, funcs, names, strings
│           ├── ir_commands.cpp        # llir, mlil, hlil, hlilraw, pseudoc
│           ├── analysis_commands.cpp  # fdisc, franges, xrefs
│           ├── debug_commands.cpp     # dwarf, ehframe
│           └── help_commands.cpp      # help, quit
└── imgui/
    ├── main.cpp
    ├── imgui_app.h/cpp
    ├── imgui_ui.h/cpp              # 使用新格式化层
    ├── ... (其他视图文件保持)
```

---

## 3. 核心模块设计

### 3.1 格式化层 (Formatters)

#### address.h
```cpp
#pragma once
#include <cstdint>
#include <string>

namespace client::fmt {

// 格式化地址
std::string hex(std::uint64_t value);
std::string hex_padded(std::uint64_t value, int width = 16);

// 解析地址
bool parse_u64(const std::string& text, std::uint64_t& out);

}  // namespace client::fmt
```

#### ir.h
```cpp
#pragma once
#include <string>
#include <vector>
#include "engine/llir.h"
#include "engine/mlil.h"
#include "engine/hlil.h"

namespace client::fmt {

// LLIR 格式化
std::string format_llir_expr(const engine::llir::LlilExpr& expr);
std::string format_llir_stmt(const engine::llir::LlilStmt& stmt);
void format_llir_function(const engine::llir::Function& func, std::vector<std::string>& lines);

// MLIL 格式化
std::string format_mlil_expr(const engine::mlil::MlilExpr& expr);
std::string format_mlil_stmt(const engine::mlil::MlilStmt& stmt);
void format_mlil_function(const engine::mlil::Function& func, std::vector<std::string>& lines);

// HLIL 格式化
std::string format_hlil_expr(const engine::hlil::Expr& expr, 
                             const std::unordered_map<std::string, std::string>& renames);
std::string format_hlil_stmt(const engine::hlil::HlilStmt& stmt,
                             const std::unordered_map<std::string, std::string>& renames,
                             int indent = 0);
void format_hlil_function(const engine::hlil::Function& func, std::vector<std::string>& lines);

}  // namespace client::fmt
```

#### symbols.h
```cpp
#pragma once
#include <string>
#include "engine/symbols.h"
#include "engine/dwarf.h"

namespace client::fmt {

std::string symbol_display_name(const engine::symbols::SymbolEntry& entry);
bool symbol_matches_filter(const engine::symbols::SymbolEntry& entry, const std::string& filter);
std::string dwarf_function_name(const engine::dwarf::DwarfFunction& func);
std::string dwarf_variable_name(const engine::dwarf::DwarfVariable& var);

}  // namespace client::fmt
```

#### xrefs.h
```cpp
#pragma once
#include <string>
#include "engine/xrefs.h"
#include "engine/function_discovery.h"

namespace client::fmt {

const char* xref_kind_label(engine::xrefs::XrefKind kind);
const char* seed_kind_label(engine::analysis::SeedKind kind);
const char* range_kind_label(engine::analysis::FunctionRangeKind kind);

}  // namespace client::fmt
```

### 3.2 数据服务层 (Services)

#### disasm_service.h
```cpp
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "engine/session.h"
#include "engine/disasm.h"

namespace client::services {

struct DisasmResult {
    bool success = false;
    std::string error;
    std::vector<engine::DisasmLine> lines;
    std::uint64_t next_address = 0;
};

class DisasmService {
public:
    explicit DisasmService(engine::Session& session);
    
    DisasmResult disassemble(std::uint64_t address, std::size_t count);
    DisasmResult disassemble_bytes(std::uint64_t address, std::size_t max_bytes, std::size_t max_count);

private:
    engine::Session& session_;
};

}  // namespace client::services
```

#### ir_service.h
```cpp
#pragma once
#include <cstdint>
#include <string>
#include "engine/session.h"
#include "engine/llir.h"
#include "engine/mlil.h"
#include "engine/hlil.h"
#include "engine/decompiler.h"

namespace client::services {

struct IrResult {
    bool success = false;
    std::string error;
};

struct LlirResult : IrResult {
    engine::llir::Function function;
};

struct MlilResult : IrResult {
    engine::mlil::Function function;
};

struct HlilResult : IrResult {
    engine::hlil::Function function;
};

struct PseudocResult : IrResult {
    engine::decompiler::Function function;
    std::vector<std::string> lines;
};

class IrService {
public:
    explicit IrService(engine::Session& session);
    
    LlirResult build_llir_ssa(std::uint64_t address, std::size_t max_instructions);
    MlilResult build_mlil_ssa(std::uint64_t address, std::size_t max_instructions);
    HlilResult build_hlil(std::uint64_t address, std::size_t max_instructions, bool optimize = true);
    PseudocResult build_pseudoc(std::uint64_t address, std::size_t max_instructions);

private:
    engine::Session& session_;
};

}  // namespace client::services
```

### 3.3 增强的 Session 封装

#### session.h
```cpp
#pragma once
#include <memory>
#include <string>
#include "engine/session.h"
#include "client/services/disasm_service.h"
#include "client/services/ir_service.h"
#include "client/services/analysis_service.h"

namespace client {

class Session {
public:
    Session();
    ~Session();
    
    // 基础操作
    bool open(const std::string& path, std::string& error);
    void close();
    bool loaded() const;
    const std::string& path() const;
    
    // 引擎访问
    engine::Session& engine();
    const engine::Session& engine() const;
    
    // 服务访问
    services::DisasmService& disasm();
    services::IrService& ir();
    services::AnalysisService& analysis();
    
    // 快捷访问 (委托到 engine)
    std::uint64_t cursor() const;
    void set_cursor(std::uint64_t addr);
    const engine::BinaryInfo& binary_info() const;
    // ... 其他常用方法
    
private:
    engine::Session engine_;
    std::unique_ptr<services::DisasmService> disasm_service_;
    std::unique_ptr<services::IrService> ir_service_;
    std::unique_ptr<services::AnalysisService> analysis_service_;
};

}  // namespace client
```

### 3.4 命令模块化

每个命令文件导出注册函数：

```cpp
// file_commands.cpp
#pragma once
#include "client/command.h"

namespace client::commands {
void register_file_commands(CommandRegistry& registry);
}

// 实现
namespace client::commands {

void register_file_commands(CommandRegistry& registry) {
    registry.register_command(Command{
        "open", {}, "open <path>   load binary file",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            // ...
        }
    });
    
    registry.register_command(Command{
        "close", {}, "close         unload current file",
        // ...
    });
    
    // ... 其他文件相关命令
}

}  // namespace client::commands
```

命令注册表工厂：
```cpp
// command.h (增强)
namespace client {

CommandRegistry make_default_registry();  // 调用所有 register_xxx_commands

}  // namespace client
```

---

## 4. 实施步骤

### 阶段 1：创建格式化层
1. 创建 `clients/common/include/client/formatters/` 目录
2. 从 `default_commands.cpp` 和 `imgui_ui.cpp` 提取格式化函数
3. 创建格式化头文件和实现

### 阶段 2：创建服务层
1. 创建 `clients/common/include/client/services/` 目录
2. 实现 DisasmService、IrService、AnalysisService
3. 封装 engine::Session 的复杂调用

### 阶段 3：重构 Session
1. 扩展 `session.h` 为完整封装
2. 添加服务实例管理
3. 提供便捷的委托方法

### 阶段 4：拆分命令
1. 创建 `clients/common/src/commands/` 目录
2. 将 `default_commands.cpp` 拆分为多个文件
3. 使用格式化层和服务层
4. 更新 `make_default_registry()` 

### 阶段 5：更新 ImGui
1. 使用新的格式化层替换重复代码
2. 使用新的服务层简化数据获取
3. 保持 UI 组件结构基本不变

### 阶段 6：更新构建配置
1. 更新 `xmake.lua` 添加新文件
2. 确保所有模块正确链接

---

## 5. 预期收益

1. **可维护性**：命令按功能分类，易于查找和修改
2. **代码复用**：格式化逻辑统一，CLI 和 GUI 共享
3. **可测试性**：服务层可独立测试
4. **可扩展性**：新命令只需在对应模块添加
5. **清晰架构**：层次分明，职责清晰

---

## 6. 风险与应对

| 风险 | 应对措施 |
|------|----------|
| 重构过程中功能回归 | 保持增量重构，每步验证 |
| 构建配置复杂化 | xmake 支持 glob，可简化配置 |
| ImGui 视图改动过大 | 优先使用新层，保持视图结构 |