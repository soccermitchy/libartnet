// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the ARTNETWIN32DLL_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// ARTNETWIN32DLL_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef ARTNETWIN32DLL_EXPORTS
#define ARTNETWIN32DLL_API __declspec(dllexport)
#else
#define ARTNETWIN32DLL_API __declspec(dllimport)
#endif

// This class is exported from the artnetWin32DLL.dll
class ARTNETWIN32DLL_API CartnetWin32DLL {
public:
	CartnetWin32DLL(void);
	// TODO: add your methods here.
};

extern ARTNETWIN32DLL_API int nartnetWin32DLL;

ARTNETWIN32DLL_API int fnartnetWin32DLL(void);
