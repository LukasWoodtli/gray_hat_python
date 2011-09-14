#include <stdio.h>
#include <Windows.h>

static void delay(DWORD Delay);


int main(int argc, char** argv)
{
    int counter = 0;
    while (1)
    {
        printf("Loop iteration %i\n", counter);
        delay(200);
        counter += 1;
    }

}

void delay(DWORD Delay)
 {
 DWORD dwTicks = GetTickCount();
 while (GetTickCount()-dwTicks < Delay);
 }

 
