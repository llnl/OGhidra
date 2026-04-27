@echo off
REM Build script for GhidraMCP extension
SETLOCAL

echo Building GhidraMCP extension...

REM Check if GHIDRA_INSTALL_DIR environment variable is set
IF "%GHIDRA_INSTALL_DIR%"=="" (
    echo ERROR: GHIDRA_INSTALL_DIR environment variable not set.
    echo Please set it to your Ghidra installation directory.
    echo Example: set GHIDRA_INSTALL_DIR=C:\path\to\ghidra_12.0_PUBLIC
    exit /b 1
)

REM Check if Ghidra installation exists
IF NOT EXIST "%GHIDRA_INSTALL_DIR%" (
    echo ERROR: Ghidra installation not found at %GHIDRA_INSTALL_DIR%
    exit /b 1
)

REM Create gradle.properties with the correct GHIDRA_INSTALL_DIR
echo # Path to your Ghidra installation directory > OGhidraMCP\gradle.properties
echo GHIDRA_INSTALL_DIR=%GHIDRA_INSTALL_DIR% >> OGhidraMCP\gradle.properties

REM Build the extension
cd OGhidraMCP
call gradle buildExtension
if %ERRORLEVEL% neq 0 (
    echo ERROR: Build failed!
    cd ..
    exit /b 1
)
cd ..

echo.
echo Build completed successfully!
echo.
echo The extension zip file is located in: OGhidraMCP\dist\

ENDLOCAL