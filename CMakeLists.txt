cmake_minimum_required(VERSION 3.10)
project(RWArmor VERSION 1.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add source files
set(SOURCES
    main.cpp
    rwarmor.cpp
    rwarmor_components.cpp
)

# Add header files
set(HEADERS
    rwarmor.h
)

# Add executable
add_executable(rwarmor ${SOURCES} ${HEADERS})

# Add include directories
target_include_directories(rwarmor PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Set compiler flags
if(MSVC)
    target_compile_options(rwarmor PRIVATE /W4)
else()
    target_compile_options(rwarmor PRIVATE -Wall -Wextra -pedantic)
endif()

# Add thread library dependency
find_package(Threads REQUIRED)
target_link_libraries(rwarmor PRIVATE Threads::Threads)

# Install target
install(TARGETS rwarmor DESTINATION bin)

# Create README file
file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/README.md "# RWArmor

RWArmor is a static-informed dynamic analysis approach for early detection of cryptographic Windows ransomware.

## Building

```
mkdir build
cd build
cmake ..
cmake --build .
```

## Usage

```
./rwarmor
```

Commands:
- `help` - Display help message
- `check FILE` - Check if a file is ransomware
- `threshold N` - Set detection threshold (0.0 to 1.0)
- `monitor PID` - Monitor a specific process
- `quit` - Exit the program
")

# Generate sample signatures file
file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/signatures.txt "# Sample ransomware signatures (file hashes)
# These are placeholder signatures - replace with real ransomware signatures
123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
") 