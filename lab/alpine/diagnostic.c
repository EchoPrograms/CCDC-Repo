/* Harmless executable used for the world-writable SUID metadata exercise. */
#include <stdio.h>
int main(void)
{
    puts("CCDC practice diagnostic: this program performs no privileged action.");
    return 0;
}
