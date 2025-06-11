#include <lib.h>

void touch(char *path) {
    int fd;
    if ((fd = open(path, O_RDONLY)) >= 0) {
        close(fd);
        return;
    }
    fd = open(path, O_CREAT);
    if (fd == -10) {
        printf("touch: cannot touch '%s': No such file or directory\n", path);
    } else if (fd < 0) {
        printf("other error when touch %s, error code is %d\n", path, fd);
    } else {
        close(fd);
    }
    return;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("nothing to touch\n");
    } else {
        for (int i = 1; i < argc; ++i) {
            touch(argv[i]);
        }
    }
    return 0;
}
