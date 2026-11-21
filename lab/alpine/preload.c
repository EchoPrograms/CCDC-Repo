/* A real musl-loadable marker library. It does not hook, hide or intercept APIs. */
#include <stdio.h>
#include <unistd.h>

__attribute__((constructor)) static void lab_marker(void)
{
    FILE *log = fopen("/var/log/ccdc-lab/preload-events.log", "a");
    if (log != NULL) {
        fprintf(log, "CCDC_LAB_PRELOAD_MARKER pid=%ld\n", (long)getpid());
        fclose(log);
    }
}
