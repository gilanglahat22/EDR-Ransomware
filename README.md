# RWArmor: Ransomware Detection System

RWArmor is a static-informed dynamic analysis approach for early detection of cryptographic Windows ransomware, based on the research paper "RWArmor: a static-informed dynamic analysis approach for early detection of cryptographic windows ransomware".

## Features

- Static analysis of executable files
- Dynamic behavioral analysis
- API hooking for monitoring suspicious activities
- Machine learning-based detection
- File system activity monitoring
- Early detection within 30-120 seconds of ransomware execution

## Prerequisites

Before building RWArmor, you need to install:

1. **CMake** (version 3.10 or higher)
   - Linux: `sudo apt-get install cmake` (Ubuntu/Debian) or `sudo yum install cmake` (CentOS/RHEL)
   - macOS: `brew install cmake` (via Homebrew) or download from [cmake.org](https://cmake.org/download/)
   - Windows: Download and install from [cmake.org](https://cmake.org/download/)

2. **C++17 compatible compiler**
   - Linux: GCC 7+ (`sudo apt-get install build-essential`)
   - macOS: Clang comes with Xcode Command Line Tools (`xcode-select --install`)
   - Windows: Visual Studio 2017+ or MinGW-w64

3. **Thread support library**
   - Included in most standard libraries, but may need pthread on some systems

## Building

### Linux/macOS

```bash
# Clone the repository (if using git)
# git clone https://github.com/your-username/rwarmor.git
# cd rwarmor

# Create build directory
mkdir build
cd build

# Configure and build
cmake ..
cmake --build .
```

### Windows (with Visual Studio)

```cmd
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

### Windows (with MinGW)

```cmd
mkdir build
cd build
cmake -G "MinGW Makefiles" ..
cmake --build .
```

## Fast Build (with scripts)

We provide convenience scripts to build RWArmor quickly:

### Linux/macOS
```bash
./build_and_test.sh
```

### Windows
```cmd
build_and_test.bat
```

## Running RWArmor

```bash
# From the build directory
./rwarmor
```

On Windows, use:
```cmd
.\rwarmor.exe
```
or
```cmd
.\Release\rwarmor.exe
```

## Usage Guide

Once RWArmor is running, you'll see a command prompt:

```
RWArmor started successfully. Type 'help' for commands.
RWArmor>
```

### Available Commands

- `help` - Display help message
- `check FILE` - Check if a file is potentially ransomware
  ```
  RWArmor> check /path/to/suspicious/file.exe
  ```
- `threshold N` - Set detection threshold (0.0 to 1.0)
  ```
  RWArmor> threshold 0.8
  ```
- `monitor PID` - Monitor a specific process ID
  ```
  RWArmor> monitor 1234
  ```
- `quit` - Exit the program

## Troubleshooting

### Common Issues

1. **CMake not found**: Make sure CMake is installed and in your PATH. See the Prerequisites section for installation instructions.

2. **Compilation errors**: Ensure you have a C++17 compatible compiler. The code uses C++17 features including `std::filesystem`.

3. **Signature File Missing**: Make sure `signatures.txt` is in the same directory as the executable, or provide the full path.

4. **Permission Errors**: On Linux/macOS, you may need to run with elevated permissions for file system monitoring:
   ```bash
   sudo ./rwarmor
   ```

5. **Windows API Hooking**: For full functionality on Windows, make sure to run with Administrator privileges.

## Extending RWArmor

The current implementation provides a framework for ransomware detection. For production use, consider:

1. Implementing specific PE file parsing using libraries like LIEF or PE-bear
2. Enhancing API hooking with Microsoft Detours or similar libraries
3. Training the ML model with real ransomware samples
4. Implementing real-time file system monitoring

## License

This project is available under the MIT License.
