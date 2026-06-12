@echo off

set INSTALL_DIR=%ProgramFiles%\Cryptum
set LIB_DIR=%INSTALL_DIR%\lib

echo Creating directories...
mkdir "%INSTALL_DIR%" 2>nul
mkdir "%LIB_DIR%" 2>nul

echo Copying files...
copy build\Release\cryptum.exe "%INSTALL_DIR%\" >nul
copy build\Release\vigenere.dll "%LIB_DIR%\" >nul
copy build\Release\des.dll "%LIB_DIR%\" >nul
copy build\Release\shamir.dll "%LIB_DIR%\" >nul

echo Adding to PATH...
setx PATH "%PATH%;%INSTALL_DIR%" /M

echo Installation complete
echo Usage: cryptum --help