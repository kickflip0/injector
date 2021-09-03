#include <stdio.h>
#include "injector.h"

int main(int argc, char** argv) {

    SetConsoleTitleA(util::RandomString(26).c_str());
    
    Injector* hardcore = new Injector(util::get_pid("notepad.exe"), "random.dll");
    
    if (hardcore->inject()) 
    {
        std::printf("[+] Injected\n");
        system("Pause");
        ExitProcess(0);
    }
    else 
    {

        std::printf("[-] Injection failed\n");
    }

    return 0;

}
