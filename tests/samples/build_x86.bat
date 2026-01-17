@echo off
setlocal

call "D:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat" >nul 2>&1
if errorlevel 1 (
    echo Failed to set up MSVC x86 environment
    exit /b 1
)

set SRC=%~dp0binary.cpp
set OUTDIR=%~dp0x86

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

pushd "%OUTDIR%"

echo Compiling x86 O0 (Debug, no optimization)...
cl /nologo /Od /Zi /EHsc /GR /Fe:binaryO0.exe "%SRC%" /link /DEBUG:FULL
if errorlevel 1 echo [WARN] O0 build failed

echo Compiling x86 O2 (Release, full optimization)...
cl /nologo /O2 /Zi /EHsc /GR /Fe:binaryO2.exe "%SRC%" /link /DEBUG:FULL
if errorlevel 1 echo [WARN] O2 build failed

echo Compiling x86 O2 stripped...
cl /nologo /O2 /EHsc /GR /Fe:binaryO2Strip.exe "%SRC%" /link /RELEASE
if errorlevel 1 echo [WARN] O2Strip build failed

popd

echo.
echo x86 Build complete. Output in %OUTDIR%
dir /b "%OUTDIR%\*.exe" 2>nul
