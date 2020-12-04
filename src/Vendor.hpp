#pragma once

//WinAPI stuff.
#include <Windows.h>
#include <iterator>
#include <iostream>
#include <iomanip>
#include <vector>
#include <map>
#include <string>
#include <fstream>
#include <sstream>
#include <Psapi.h>
#include <tlhelp32.h>
#include <libloaderapi.h>
#include <tchar.h>
#include <time.h>

//Legacy utils.
#include "primal/util/CommonUtil.hpp"
#include "primal/util/PanicUtil.hpp"
#include "primal/util/stuff/Singleton.hpp"
#include "primal/util/stuff/RuntimeDefinitions.hpp"