#include <stdio.h>
#include <unistd.h>

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
    snprintf(filename, sizeof(filename), "%s/file2.txt", BASE_PATH);
    if (unlink(filename) != 0) {
        perror("unlink file2.txt");
    } else {
        printf("Deleted %s\n", filename);
    }
    snprintf(filename, sizeof(filename), "%s/file6.txt", BASE_PATH);
    fp = fopen(filename, "a");
    if (fp == NULL) {
        perror("fopen file6.txt");
        return 1;
    }
    fprintf(fp, "Appended by second_exec (write to file6)\n");
    fclose(fp);
    printf("Wrote to %s\n", filename);
    return 0;
}
