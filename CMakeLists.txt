# Modern CMake
cmake_minimum_required(VERSION 3.18)

# Set up a more familiar Visual Studio configuration
# Override these options with -DCMAKE_OPTION=Value
#
# See: https://cmake.org/cmake/help/latest/command/set.html#set-cache-entry
#set(CMAKE_CONFIGURATION_TYPES "Debug;Release" CACHE STRING "")
#set(CMAKE_EXE_LINKER_FLAGS_RELEASE "/DEBUG:FULL /INCREMENTAL:NO" CACHE STRING "")
#set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "/DEBUG:FULL /INCREMENTAL:NO" CACHE STRING "")
#set(CMAKE_BUILD_TYPE "Release" CACHE STRING "")
#set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>" CACHE STRING "")

project(x64dbgpy3)
include(CMakePrintHelpers)

# Add module path for dependencies
list(PREPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Enable solution folder support
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(CMAKE_FOLDER "Dependencies")
include(CPM)

# Provide option for user to specify custom python and x64dbg install path
set(X64DBGPY3_PYTHON_EXECUTABLE "" CACHE FILEPATH "Python executable to use")
#message(STATUS "PYTHON_EXECUTABLE=${X64DBGPY3_PYTHON_EXECUTABLE})
set(X64DBGPY3_X64DBG_INSTALL_PATH "" CACHE FILEPATH "Path where x64dbg is installed")
if(NOT X64DBGPY3_PYTHON_EXECUTABLE)
    set(PYTHON_EXECUTABLE "c:/Python39/python.exe")
else()
    set(PYTHON_EXECUTABLE ${X64DBGPY3_PYTHON_EXECUTABLE})
endif()
#message(STATUS "PYTHON_EXECUTABLE=${PYTHON_EXECUTABLE}")

include(pybind11)
include(x64dbg)

set(CMAKE_FOLDER "")

add_subdirectory ("src/scriptapi")
add_subdirectory ("src/x64dbgpy3")

