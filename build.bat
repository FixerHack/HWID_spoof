@echo off

echo.
echo  === HWID Spoofer - Build ===
echo.

where g++ >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] g++ not found. Install MSYS2/MinGW and add to PATH.
    pause
    exit /b 1
)

echo [*] Compiling manifest (UAC)...
windres resource.rc -O coff -o resource.o
if %errorlevel% neq 0 (
    echo [-] windres failed.
    pause
    exit /b 1
)
echo [+] Manifest compiled.

echo [*] Compiling spoof.cpp...
g++ spoof.cpp resource.o -o spoof.exe -lrpcrt4 -liphlpapi -static-libgcc -static-libstdc++ -static -std=c++17 -O2

if %errorlevel% equ 0 (
    echo [+] Done: spoof.exe
) else (
    echo [-] Compilation failed.
)

echo.
pause
