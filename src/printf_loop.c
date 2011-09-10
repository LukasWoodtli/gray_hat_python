#include <stdio.h>
#include <Windows.h>

static void delay(DWORD Delay);


int main(int argc, char** argv)
{
    while (1)
    {
        printf("Loop\n");
        delay(5);
    }

}

void delay(DWORD Delay)
 {
 DWORD dwTicks = GetTickCount();
 while (GetTickCount()-dwTicks < Delay);
 }

 
