

pybind11_add_module(scriptapi NO_EXTRAS
    scriptapi.cpp
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



