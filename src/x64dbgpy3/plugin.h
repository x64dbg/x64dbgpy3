#pragma once

#include "pluginmain.h"

//functions
void pluginHandleMenuCommand(CBTYPE cbType, PLUG_CB_MENUENTRY* info);
bool pluginInit(PLUG_INITSTRUCT* initStruct);
void pluginStop();
void pluginSetup();
