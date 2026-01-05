#include <stdio.h>

#define BASE_PATH "/dev/shm"

int main() {
    FILE* fp;
    char filename[256];
    char buffer[100];

    for (int i = 2; i <= 10; i += 2) {
        snprintf(filename, sizeof(filename), "%s/file%d.txt", BASE_PATH, i);

        fp = fopen(filename, "r");
        if (fp == NULL) {
            printf("Could not open %s\n", filename);
            continue;
        }

        printf("Contents of %s:\n", filename);
        while (fgets(buffer, sizeof(buffer), fp)) {
            printf("%s", buffer);
        }
        printf("\n");

        fclose(fp);
    }

    return 0;
}
