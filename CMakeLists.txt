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

project(x64dbgpy)

# Add module path for dependencies
list(PREPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Enable solution folder support
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(CMAKE_FOLDER "Dependencies")
include(CPM)
include(pybind11)
include(x64dbg)

set(CMAKE_FOLDER "")

pybind11_add_module(scriptapi NO_EXTRAS
    src/scriptapi/scriptapi.cpp
)
# Link to the x64dbg SDK
target_link_libraries(scriptapi PRIVATE x64dbg)

install(PROGRAMS
    $<TARGET_FILE:scriptapi>
    DESTINATION .
    COMPONENT pyd
    RENAME scriptapi${EXTENSION}
    )

if(WIN32)
    set(EXTENSION ".pyd")
else()
    set(EXTENSION ".so")
endif()

# Create a plugin
configure_file(src/x64dbgpy/pluginconfig.h.in include/x64dbgpy/pluginconfig.h ESCAPE_QUOTES)
x64dbg_plugin(${PROJECT_NAME}
	src/x64dbgpy/plugin.cpp
	src/x64dbgpy/plugin.h
	src/x64dbgpy/pluginmain.cpp
	src/x64dbgpy/pluginmain.h
	${CMAKE_CURRENT_BINARY_DIR}/include/x64dbgpy/pluginconfig.h
)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/include)
# TODO: add post build step to reload plugin if necessary

# Set the plugin as the startup project
set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT ${PROJECT_NAME})