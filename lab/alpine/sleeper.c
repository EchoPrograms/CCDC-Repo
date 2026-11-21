/* Persistent dynamic process for the LD_PRELOAD environment/maps exercise. */
#include <unistd.h>
int main(void)
{
    for (;;) {
        pause();
    }
    return 0;
}
