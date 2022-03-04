#include <unistd.h>
#include "CLEO_SDK/cleo.h" //use CLEO sdk
#include "ARMHook/ARMHook.h"

//use AML
#include "AML/amlmod.h"
#include "AML/logger.h"

MYMOD(net.xmds.SprintEverywhere, SprintEverywhere, 1.0, XMDS)

cleo_ifs_t* cleo;
uintptr_t LibAddr;

int ret()
{
	return 0;
}

//cleo plugin entrance
extern "C" __attribute__((visibility("default"))) void plugin_init(cleo_ifs_t * ifs)
{
	cleo = ifs;
	cleo->PrintToCleoLog("'SprintEverywhere.so' init!!!");
	LibAddr = reinterpret_cast<uintptr_t>(cleo->GetMainLibraryLoadAddress());
	ARMHook::HookPLTInternal((void*)(LibAddr + 0x0066FD60), (void*)ret, NULL);
}

//AML plugin entrance
extern "C" void OnModLoad()
{
	logger->SetTag("SprintEverywhere");
	logger->Info("'SprintEverywhere.so' init!!!");
	LibAddr = ARMHook::GetLibraryAddress("libGTASA.so");
	ARMHook::HookPLTInternal((void*)(LibAddr + 0x0066FD60), (void*)ret, NULL);
}