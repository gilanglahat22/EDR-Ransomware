@echo off
echo === Building RWArmor ===

:: Check if build directory exists, create if not
if not exist build mkdir build

:: Build the project
cd build
cmake ..
cmake --build . --config Release

echo === Build completed successfully ===

:: Check if the binary was created
if exist ".\Release\rwarmor.exe" (
    echo === RWArmor binary created successfully ===
    echo === To run RWArmor, use: .\Release\rwarmor.exe ===
) else if exist ".\rwarmor.exe" (
    echo === RWArmor binary created successfully ===
    echo === To run RWArmor, use: .\rwarmor.exe ===
) else (
    echo ERROR: rwarmor.exe binary not found!
    exit /b 1
)

:: Return to the original directory
cd ..

echo === Build and verification completed ===
echo You can now run RWArmor from the build directory:
echo   cd build
if exist ".\build\Release\rwarmor.exe" (
    echo   .\Release\rwarmor.exe
) else (
    echo   .\rwarmor.exe
)

pause 