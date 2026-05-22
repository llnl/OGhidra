@echo off
REM Build script for GhidraMCP extension
SETLOCAL

echo Building GhidraMCP extension...

echo.
call gradle --version
echo.

REM If GHIDRA_INSTALL_DIR is not set, attempt to read from lastrun file
IF NOT DEFINED GHIDRA_INSTALL_DIR (
    IF DEFINED XDG_CONFIG_HOME (
        SET LASTRUN_FILE=%XDG_CONFIG_HOME%\ghidra\lastrun
    ) ELSE (
        SET LASTRUN_FILE=%APPDATA%\ghidra\lastrun
    )
    IF EXIST "%LASTRUN_FILE%" (
        SET /P GHIDRA_INSTALL_DIR=<"%LASTRUN_FILE%"
        echo Found Ghidra at %GHIDRA_INSTALL_DIR% using %LASTRUN_FILE%
    ) ELSE (
        echo ERROR: GHIDRA_INSTALL_DIR environment variable not set.
        echo Please set it to your Ghidra installation directory.
        echo Example: set GHIDRA_INSTALL_DIR=C:\path\to\ghidra_12.0_PUBLIC
        exit /b 1
    )
)

REM Check if Ghidra installation exists
IF NOT EXIST "%GHIDRA_INSTALL_DIR%" (
    echo ERROR: Ghidra installation not found at %GHIDRA_INSTALL_DIR%
    exit /b 1
)

REM Create gradle.properties with the correct GHIDRA_INSTALL_DIR
echo # Path to your Ghidra installation directory > OGhidraMCP\gradle.properties
REM Convert backslashes to forward slashes for Gradle and ensure no trailing spaces
set "GRADLE_PATH=%GHIDRA_INSTALL_DIR:\=/%"
REM Remove any trailing spaces from the path (this creates the file without trailing spaces)
echo GHIDRA_INSTALL_DIR=%GRADLE_PATH%>> OGhidraMCP\gradle.properties

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
