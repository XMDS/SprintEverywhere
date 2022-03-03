#pragma once
#include <vector>
#include <sys/mman.h>

struct bytePattern
{
	struct byteEntry
	{
		uint8_t nValue;
		bool bUnknown;
	};
	std::vector<byteEntry> vBytes;
};

class ARMHook
{
public:
	static uintptr_t GetLibraryAddress(const char* library);
	static uintptr_t GetLibraryLength(const char* library);
	static uintptr_t InitialiseTrampolines(uintptr_t dest, uintptr_t size);
	
	static void ReplaceThumbCall(uintptr_t addr, uintptr_t func);
	static void ReplaceArmCall(uintptr_t addr, uintptr_t func);
	static void HookThumbFunc(void* func, uint32_t startSize, void* func_to, void** func_orig);
	static void HookArmFunc(void* func, uint32_t startSize, void* func_to, void** func_orig);

	static uintptr_t GetThumbCallAddr(uintptr_t addr, bool mode);

	static uintptr_t GetSymbolAddress(uintptr_t LibAddr, const char* name);
	static void Unprotect(uintptr_t ptr, size_t size);
	static void WriteMemory(void* addr, void* data, size_t size);
	static void* ReadMemory(void* addr, void* data, size_t size);
	static void HookPLTInternal(void* addr, void* func, void** original);
	static uintptr_t GetAddressFromPatter(const char* pattern, const char* library);
};