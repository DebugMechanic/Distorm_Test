#ifndef LOG_H
#define LOG_H

#include <Windows.h>

#pragma warning( disable: 4996 )

VOID WINAPIV Log( CHAR* szFormat, ... );
VOID WINAPIV ClearLog();

#endif