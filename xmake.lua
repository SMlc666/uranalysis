
set_project("uranayzle")
set_version("0.1.0")

add_rules("mode.debug", "mode.release")
set_languages("cxx20")

add_requires("capstone")
add_requires("catch2")
add_requires("replxx")
add_requires("sqlite3")

add_requires("spdlog", {configs = {header_only = true}})


includes("third-party/llvm")
includes("third-party/raw_pdb-main")


set_encodings ("utf-8")

option("build_shared")
    set_default(false)
    set_showmenu(true)
    set_description("Build engine as shared library")
option_end()

option("with_imgui_client")
    set_default(true)
    set_showmenu(true)
    set_description("Build the ImGui client (Windows only)")
option_end()

if is_plat("windows") and has_config("with_imgui_client") then
    add_requires("imgui docking", {configs = {win32 = true, dx11 = true, dx12 = true}})
end

if has_config("build_shared") then
    target("engine")
        set_kind("shared")
else
    target("engine")
        set_kind("static")
end

    add_includedirs("src/engine/include", {public = true})
    add_includedirs("src/engine/pass/include", {public = true})
    add_includedirs("src/engine/ir", {public = true})
    add_includedirs("src/engine/debug/include", {public = true})
    add_includedirs("src/engine/emit/include", {public = true})
    add_files("src/engine/**/*.cpp")
    add_packages("capstone")
    add_packages("sqlite3")
    add_deps("raw_pdb")
    add_packages("spdlog")
    add_deps("llvm_demangle")



target("cli")

    set_kind("binary")
    add_files("clients/cli/*.cpp")
    add_deps("engine")
    add_packages("replxx","spdlog")
    add_deps("client_common")

target("client_common")
    set_kind("static")
    add_includedirs("clients/common/include", {public = true})
    add_files("clients/common/src/*.cpp")
    add_files("clients/common/src/formatters/*.cpp")
    add_files("clients/common/src/services/*.cpp")
    add_files("clients/common/src/commands/*.cpp")
    add_files("clients/common/src/args/*.cpp")
    add_files("clients/common/src/util/*.cpp")
    add_deps("engine")
    add_packages("spdlog")

target("engine_tests")
    set_kind("binary")
    add_files("tests/*.cpp")
    add_files("tests/engine/**/*.cpp")
    add_deps("engine", "client_common")
    add_includedirs("tests")
    add_packages("catch2", "sqlite3", "spdlog")

if is_plat("windows") and has_config("with_imgui_client") then
    target("imgui_client")
        set_kind("binary")
        add_deps("engine", "client_common")
        add_packages("imgui","spdlog")
        
        -- Include directories
        add_includedirs("clients/imgui")
        add_includedirs("clients/imgui/views")
        
        add_files("clients/imgui/**.cpp")
        add_links("d3d11", "d3d12", "dxgi")
end