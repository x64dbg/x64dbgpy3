#include "plugin.h"

#include <pybind11/embed.h>
//#include <pybind11/iostream.h>
namespace py = pybind11;

enum menu_entry
{
    MENU_ABOUT
};

void pluginHandleMenuCommand(CBTYPE cbType, PLUG_CB_MENUENTRY * info)
{
    // dprintf("pluginHandleMenuCommand hEntry = %d\n", info->hEntry);
    switch (info->hEntry)
    {
    case menu_entry::MENU_ABOUT:
    default:
        MessageBoxA(hwnd_dlg, "Made by ripperuts, mrexodia", PLUGIN_NAME " Plugin", MB_ICONINFORMATION);
        break;
    }
}


bool executeScriptCommand(const char* text)
{
    py::exec(text);
    return true;
}
py::scoped_interpreter* pGuard = nullptr;

PYBIND11_EMBEDDED_MODULE(ui, m) {
    // `m` is a `py::module_` which is used to bind functions and classes
    m.def("log", _plugin_logprint);
}

// Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    dprintf("Loading...\n");
	
    // start the interpreter and keep it alive
    pGuard = new py::scoped_interpreter{};
    try
    {
    	// redirect pythons stdout and stderr to x64dbg logfile
        const auto sys = py::module_::import("sys");
        const auto ui = py::module_::import("ui");
        auto py_stdout = sys.attr("stdout");
        auto py_stderr = sys.attr("stderr");

    	if(py_stdout.is_none())
    	{
			// https://github.com/pybind/pybind11/issues/1622
            // https://pybind11.readthedocs.io/en/stable/advanced/pycpp/utilities.html
            const auto StringIO = py::module::import("io").attr("StringIO");
            py_stdout = StringIO(); // Other filelike object can be used here as well, such as objects created by pybind11
            py_stderr = StringIO();
            sys.attr("stdout") = py_stdout;
            sys.attr("stderr") = py_stderr;
    	}
        py_stdout.attr("write") = ui.attr("log");
        py_stderr.attr("write") = ui.attr("log");


    	// auto load scriptapi module
        // const auto scriptapi = py::module_::import("scriptapi");
        executeScriptCommand("import scriptapi");    	
    }
    catch (std::exception& ex)
    {
        dprintf("Error: %s\n", ex.what());
        return false; // Return false to cancel loading the plugin.
    }

	// Register python3 command handler
    SCRIPTTYPEINFO info;
    strcpy_s(info.name, "Python3");
    info.id = 0;
    info.execute = executeScriptCommand;
    info.completeCommand = nullptr;
    GuiRegisterScriptLanguage(&info);
	
    return true;
}

// Deinitialize your plugin data here.
void pluginStop()
{
    dprintf("Unloading...\n");
    delete pGuard;
    pGuard = nullptr;
}

// Do GUI/Menu related things here.
void pluginSetup()
{
	_plugin_menuaddentry(h_menu, menu_entry::MENU_ABOUT, "&About");
}