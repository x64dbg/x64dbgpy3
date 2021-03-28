#include "plugin.h"
#include <pybind11/embed.h>
namespace py = pybind11;



enum menu_entry
{
    MENU_ABOUT
};

void pluginHandleMenuCommand(CBTYPE cbType, PLUG_CB_MENUENTRY * info)
{
    //dprintf("pluginHandleMenuCommand hEntry = %d\n", info->hEntry);
    switch (info->hEntry)
    {
    case menu_entry::MENU_ABOUT:
    default:
        MessageBoxA(hwnd_dlg, "Made By ripperuts", PLUGIN_NAME " Plugin", MB_ICONINFORMATION);
        break;
    }
}


bool executeScriptCommand(const char* text)
{
    //dprintf("Executing %s\n", text);
    py::exec(text);
    return true;
}
py::scoped_interpreter* pGuard = nullptr;

FILE* f;

//Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    dprintf("Loading...\n");

    AllocConsole();
    freopen_s(&f, "CONOUT$", "w", stdout);
    printf("test\n");
    


    // start the interpreter and keep it alive
    pGuard = new py::scoped_interpreter{};
    try
    {
        py::print("Hello, World from python3!\n"); 
    }
    catch (std::exception& ex)
    {
        dprintf("Error: %s\n", ex.what());
        return false;
    }

    // 
// Register python3 command handler
    SCRIPTTYPEINFO info;
    strcpy_s(info.name, "Python3");
    info.id = 0;
    info.execute = executeScriptCommand;
    info.completeCommand = nullptr;
    GuiRegisterScriptLanguage(&info);
	
    return true; //Return false to cancel loading the plugin.
}

//Deinitialize your plugin data here.
void pluginStop()
{
    delete pGuard;
    pGuard = nullptr;
    dprintf("Unloading...\n");
    fclose(f);
    FreeConsole();
}

//Do GUI/Menu related things here.
void pluginSetup()
{
	_plugin_menuaddentry(h_menu, menu_entry::MENU_ABOUT, "&About");
}


