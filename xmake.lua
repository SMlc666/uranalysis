set_project("uranayzle")
set_version("0.1.0")

add_rules("mode.debug", "mode.release")
set_languages("cxx20")

add_requires("capstone")
add_requires("catch2")
add_requires("replxx")
add_requires("sqlite3")
add_requires("raw_pdb")

includes("third-party/llvm")

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
    add_files("src/engine/**/*.cpp")
    add_packages("capstone")
    add_packages("sqlite3")
    add_packages("raw_pdb")
    add_deps("llvm_demangle")

    -- Placeholder for future external deps
    -- add_requires("capstone")
    -- add_packages("capstone")

target("cli")
    set_kind("binary")
    add_files("clients/cli/*.cpp")
    add_deps("engine")
    add_packages("replxx")
    add_deps("client_common")

target("client_common")
    set_kind("static")
    add_includedirs("clients/common/include", {public = true})
    add_files("clients/common/src/*.cpp")
    add_deps("engine")

target("engine_tests")
    set_kind("binary")
    add_files("tests/*.cpp")
    add_deps("engine", "client_common")
    add_includedirs("tests")
    add_packages("catch2", "sqlite3")

if is_plat("windows") and has_config("with_imgui_client") then
    target("imgui_client")
        set_kind("binary")
        add_deps("engine", "client_common")
        add_packages("imgui")
        add_files("clients/imgui/main.cpp", "clients/imgui/imgui_app.cpp", "clients/imgui/imgui_ui.cpp",
                  "clients/imgui/file_browser.cpp", "clients/imgui/functions_view.cpp", "clients/imgui/names_view.cpp",
                  "clients/imgui/view_window.cpp", "clients/imgui/strings_view.cpp")
        add_files("clients/imgui/win32_dx11.cpp", "clients/imgui/win32_dx12.cpp")
        add_links("d3d11", "d3d12", "dxgi")
end
