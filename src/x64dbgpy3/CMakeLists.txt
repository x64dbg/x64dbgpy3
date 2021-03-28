# Create a plugin
#cmake_print_variables(MSVC MSVC_IDE CMAKE_VERSION CMAKE_GENERATOR CMAKE_BUILD_TYPE PROJECT_SOURCE_DIR PROJECT_BINARY_DIR CMAKE_BINARY_DIR CMAKE_CURRENT_BINARY_DIR)
list                  (APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
configure_file("pluginconfig.h.in" "pluginconfig.h" ESCAPE_QUOTES)


file(GLOB_RECURSE PLUGIN_PUBLIC_HEADERS include/*.h include/*.hpp)
file(GLOB_RECURSE PLUGIN_PRIVATE_HEADERS *.h *.hpp)
file(GLOB_RECURSE PLUGIN_SOURCES *.c *.cpp)
file(GLOB_RECURSE PLUGIN_CMAKE_UTILS cmake/*.cmake)
file(GLOB_RECURSE PLUGIN_MISC *.md *.txt)

set (PLUGIN_FILES 
  ${PLUGIN_PUBLIC_HEADERS}
  ${PLUGIN_PRIVATE_HEADERS}
  ${PLUGIN_SOURCES} 
  ${PLUGIN_CMAKE_UTILS} 
  ${PLUGIN_MISC} 
  ${PLUGIN_EXPORT_HPP})

#include (assign_source_group)
#assign_source_group(${PLUGIN_FILES})

source_group("Header Files/include" FILES ${PLUGIN_PUBLIC_HEADERS})
source_group("Header Files" FILES ${PLUGIN_PRIVATE_HEADERS})
source_group("Source Files" FILES ${PLUGIN_SOURCES})
x64dbg_plugin(${PROJECT_NAME} ${PLUGIN_FILES}
)

target_include_directories(${PROJECT_NAME} PUBLIC 
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
  $<INSTALL_INTERFACE:include> PRIVATE source)
target_include_directories(${PROJECT_NAME} PUBLIC ${PLUGIN_INCLUDE_DIRS})
target_link_libraries     (${PROJECT_NAME} PUBLIC ${PLUGIN_LIBRARIES})
target_compile_definitions(${PROJECT_NAME} PUBLIC ${PLUGIN_COMPILE_DEFINITIONS})
#set_target_properties     (${PROJECT_NAME} PROPERTIES LINKER_LANGUAGE CXX)

#target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
#target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/include)

target_link_libraries(${PROJECT_NAME} PRIVATE pybind11::embed)

# TODO: add post build step to reload plugin if necessary

# Set Visual Studio startup project
set_property(DIRECTORY ${PROJECT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT ${PROJECT_NAME})

get_target_property(PLUGIN_SUFFIX ${PROJECT_NAME} SUFFIX)
#add_custom_target("deploy")
if(NOT X64DBGPY3_X64DBG_INSTALL_PATH) 
	message(STATUS "AUTO Deploy DISABLED, call cmake with -DX64DBGPY3_X64DBG_INSTALL_PATH=c:/x64dbg to auto copy plugin binary to x64dbg folder")
else()
	message(STATUS "AUTO Deploy ENABLED, plugin will be deployed to ${X64DBGPY3_X64DBG_INSTALL_PATH}")
	if(MSVC_IDE)
		set_property(TARGET ${PROJECT_NAME} PROPERTY VS_DEBUGGER_WORKING_DIRECTORY "${X64DBGPY3_X64DBG_INSTALL_PATH}/release/x64/")
		set_property(TARGET ${PROJECT_NAME} PROPERTY VS_DEBUGGER_COMMAND "${X64DBGPY3_X64DBG_INSTALL_PATH}/release/x64/x64dbg.exe")
		add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_if_different 
				"${CMAKE_CURRENT_BINARY_DIR}/$(Configuration)/${PROJECT_NAME}${PLUGIN_SUFFIX}"
				"${X64DBGPY3_X64DBG_INSTALL_PATH}/release/x64/plugins"
			COMMAND ${CMAKE_COMMAND} -E copy_if_different 
				"${CMAKE_CURRENT_BINARY_DIR}/$(Configuration)/${PROJECT_NAME}.pdb"
				"${X64DBGPY3_X64DBG_INSTALL_PATH}/release/x64/plugins"		
			COMMENT "Copying plugin to x64dbg" VERBATIM
		)
	else()
		add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_if_different 
				"${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}${PLUGIN_SUFFIX}"
				"${X64DBGPY3_X64DBG_INSTALL_PATH}/release/x64/plugins"
			COMMAND ${CMAKE_COMMAND} -E copy_if_different 
				"${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pdb"
				"${X64DBGPY3_X64DBG_INSTALL_PATH}/release/x64/plugins"		
			COMMENT "Copying plugin to x64dbg" VERBATIM
		)
	endif()
endif()



#[[cmake_print_variables(PLUGIN_PUBLIC_HEADERS CMAKE_CURRENT_BINARY_DIR PLUGIN_INCLUDE_DIRS PLUGIN_LIBRARIES PLUGIN_COMPILE_DEFINITIONS PLUGIN_CMAKE_UTILS)
cmake_print_properties(
    TARGETS x64dbg
    PROPERTIES 
		INCLUDE_DIRECTORIES
		SUFFIX 
		INTERFACE_SOURCES
		x64dbg_SOURCE_DIR
)]]
install(TARGETS ${PROJECT_NAME} EXPORT ${PROJECT_NAME}-config
  ARCHIVE DESTINATION ${PROJECT_NAME}/lib
  LIBRARY DESTINATION ${PROJECT_NAME}/lib
  RUNTIME DESTINATION ${PROJECT_NAME}/bin)
install(DIRECTORY include/ DESTINATION ${PROJECT_NAME}/include)
install(EXPORT  ${PROJECT_NAME}-config DESTINATION ${PROJECT_NAME}/cmake)
export (TARGETS ${PROJECT_NAME}        FILE        ${PROJECT_NAME}-config.cmake)

INSTALL(FILES  ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pdb DESTINATION ${PROJECT_NAME}/bin
)

