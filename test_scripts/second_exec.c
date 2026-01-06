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
    unlink(filename);
    printf("Deleted %s\n", filename);
    snprintf(filename, sizeof(filename), "%s/file4.txt", BASE_PATH);
    fp = fopen(filename, "a");
    fprintf(fp, "Appended by second_exec (write to file4)\n");
    fclose(fp);
    unlink(filename);
    printf("Deleted %s\n", filename);
    snprintf(filename, sizeof(filename), "%s/file6.txt", BASE_PATH);
    fp = fopen(filename, "a");
    fprintf(fp, "Appended by second_exec (write to file6)\n");
    fclose(fp);
    printf("Wrote to %s\n", filename);
    return 0;
}
