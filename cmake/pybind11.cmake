# Add pybind11 dependency
if(NOT PYTHON_EXECUTABLE)
    message(FATAL_ERROR "Please specify PYTHON_EXECUTABLE with -DPYTHON_EXECUTABLE=python.exe")
endif()

CPMAddPackage(
    NAME pybind11
    VERSION 2.6.1
    GIT_REPOSITORY https://github.com/pybind/pybind11
)