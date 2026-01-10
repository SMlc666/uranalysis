target("llvm_demangle")
    set_kind("static")
    set_default(false)
    add_includedirs("include", {public = true})
    add_includedirs("Demangle/include", {public = true})
    add_files("Demangle/src/DLangDemangle.cpp",
              "Demangle/src/Demangle.cpp",
              "Demangle/src/ItaniumDemangle.cpp",
              "Demangle/src/MicrosoftDemangle.cpp",
              "Demangle/src/MicrosoftDemangleNodes.cpp",
              "Demangle/src/RustDemangle.cpp")
    add_defines("LLVM_BUILD_STATIC", {public = true})
