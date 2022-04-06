#include <unistd.h>

#ifdef AML //use AML
#include "AML/amlmod.h"
#include "AML/logger.h"
MYMOD(net.xmds.SprintEverywhere, SprintEverywhere, 1.0, XMDS)
#else
#include "CLEO_SDK/cleo.h" //use CLEO sdk
#endif 
#include "ARMHook/ARMHook.h"

uintptr_t LibAddr;

int ret()
{
	return 0;
}

#ifdef AML
//AML plugin entrance
extern "C" void OnModLoad()
{
	logger->SetTag("SprintEverywhere");
	logger->Info("'SprintEverywhere.so' init!!!");
	LibAddr = ARMHook::GetLibraryAddress("libGTASA.so");
	ARMHook::HookPLTInternal((void*)(LibAddr + 0x0066FD60), (void*)ret, NULL);
}
#else
//cleo plugin entrance
extern "C" __attribute__((visibility("default"))) void plugin_init(cleo_ifs_t * ifs)
{
	cleo_ifs_t* cleo = ifs;
	cleo->PrintToCleoLog("'SprintEverywhere.so' init!!!");
	LibAddr = reinterpret_cast<uintptr_t>(cleo->GetMainLibraryLoadAddress());
	ARMHook::HookPLTInternal((void*)(LibAddr + 0x0066FD60), (void*)ret, NULL);
}
#endif