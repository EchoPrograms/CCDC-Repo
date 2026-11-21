#include <fcntl.h>
#include <unistd.h>
__attribute__((constructor)) static void record_load(void) {
    int fd = open("/var/lib/site-cache/preload.log", O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd >= 0) { (void)write(fd, "loaded\n", 7); close(fd); }
}
