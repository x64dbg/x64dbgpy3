# x64dbgpy3

WIP: needs a lot of restructuring, this is just a POC

## Building plugin

```
cmake -Bbuild -DX64DBGPY3_PYTHON_EXECUTABLE="c:/Python39/python.exe" -DX64DBGPY3_X64DBG_INSTALL_PATH="%USERPROFILE%\Programs\x64dbg\snapshot_2021-03-28_17-36"
```

Then open `x64dbgpy3.sln` 

### Python pkg build
python -m build

### Python pkg install
```
python -m pip install --upgrade pip
python -m pip install --upgrade wheel
python -m pip install --upgrade setuptools
python -m pip install --upgrade build

pip install .
```
