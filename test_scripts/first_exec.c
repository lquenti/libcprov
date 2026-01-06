#include <stdio.h>

#define BASE_PATH "/dev/shm"

int main() {
    FILE* fp;
    char filename[256];
    for (int i = 1; i <= 10; i++) {
        snprintf(filename, sizeof(filename), "%s/file%d.txt", BASE_PATH, i);
        fp = fopen(filename, "w");
        if (fp == NULL) {
            printf("Failed to create %s\n", filename);
            return 1;
        }
        fprintf(fp, "This is file number %d\n", i);
        fclose(fp);
    }
    printf("10 files created in %s\n", BASE_PATH);
    return 0;
}
