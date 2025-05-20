// 下列 ifdef 块是创建使从 DLL 导出更简单的
// 宏的标准方法。此 DLL 中的所有文件都是用命令行上定义的 STITCHESAPI_EXPORTS
// 符号编译的。在使用此 DLL 的
// 任何项目上不应定义此符号。这样，源文件中包含此文件的任何其他项目都会将
// STITCHESAPI_API 函数视为是从 DLL 导入的，而此 DLL 则将用此宏定义的
// 符号视为是被导出的。
#ifdef STITCHESAPI_EXPORTS
#define STITCHESAPI_API __declspec(dllexport)
#else
#define STITCHESAPI_API __declspec(dllimport)
#endif

#ifndef _C_API
namespace StitchesApi
{
#define STITCHESAPI_NS	StitchesApi::
#define STITCHESAPI_CC	
#else // _C_API
#define NFAPI_CC __cdecl
#define NFAPI_NS
#ifdef __cplusplus
extern "C"
{
#endif
#endif // _C_API



// 此类是从 dll 导出的
class STITCHESAPI_API CStitchesApi {
public:
	CStitchesApi(void);
	// TODO: 在此处添加方法。

	BOOLEAN STITCHESAPI_CC AddTrustProcess(CONST std::wstring& ProcessPath);
};


//STITCHESAPI_API BOOLEAN STITCHESAPI_CC AddTrustProcess(CONST std::wstring& ProcessPath);


#ifdef __cplusplus
}
#endif

