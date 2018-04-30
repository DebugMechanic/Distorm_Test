#include "Log.h"
#include <fstream>


VOID WINAPIV ClearLog()
{
	FILE *fp;
	fp = fopen("c://disasmtest.log", "w");
	fclose(fp);
	return;
}


VOID WINAPIV Log(CHAR* szFormat, ...)
{
	FILE *fp = NULL;
	int len = 0;
	PCHAR szBuf = NULL;
	errno_t err;

	va_list list;
	va_start(list, szFormat);

	len = _vscprintf(szFormat, list) + 1; // doesn't count terminating '\0'
	szBuf = (PCHAR)calloc(len, sizeof(char));
	if (szBuf != NULL)
	{
		vsprintf_s(szBuf, len, szFormat, list);

		fp = fopen("c://disasmtest.log", "a+");
		if (fp == NULL)
			return;

		fprintf(fp, szBuf);

		if (fp != NULL)
		{
			err = fclose(fp);
			if (err == 0)
			{
				//fprintf_s(stdout, "File Was Closed\n");
			}
			else {
				//fprintf_s(stdout, "File Was Not Closed\n");
			}
		}

		if (szBuf != NULL)
			free(szBuf);

		va_end(list); /*Reset argument list*/
	}

	return;
}

