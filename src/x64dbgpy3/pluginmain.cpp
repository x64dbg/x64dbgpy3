#include "pluginmain.h"
#include "plugin.h"

int gHandleToShit;
int plugin_handle;
HWND hwnd_dlg;
int h_menu;
int h_menu_disasm;
int h_menu_dump;
int h_menu_stack;

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
    pluginHandleMenuCommand(cbType, info);
}

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, PLUGIN_NAME, _TRUNCATE);
    plugin_handle = initStruct->pluginHandle;
    return pluginInit(initStruct);
}

PLUG_EXPORT bool plugstop()
{
    pluginStop();
    return true;
}

PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    hwnd_dlg = setupStruct->hwndDlg;
    h_menu = setupStruct->hMenu;
    h_menu_disasm = setupStruct->hMenuDisasm;
    h_menu_dump = setupStruct->hMenuDump;
    h_menu_stack = setupStruct->hMenuStack;
    pluginSetup();
}