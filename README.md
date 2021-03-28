# x64dbgpy3

WIP: needs a lot of restructuring, this is just a POC

## Building

```
cmake -Bbuild -DX64DBGPY3_PYTHON_EXECUTABLE="c:/Python39/python.exe" -DX64DBGPY3_X64DBG_INSTALL_PATH="%USERPROFILE%\Programs\x64dbg\snapshot_2021-03-28_17-36"
```

Then open `x64dbgpy3.sln` and change to RelWithDebInfo in Visual Studio, otherwise you get error in runtime:
```
Error: AttributeError: 'NoneType' object has no attribute 'write'
```