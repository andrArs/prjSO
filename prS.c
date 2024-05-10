#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdbool.h>

#define MAX_PATH 4096
#define CONTENT 4096
#define STAT_LENGTH 4096
#define LENGTH 4096

typedef struct Stat {
    char dirMatrix[CONTENT][STAT_LENGTH];
    long int nrFiles;
    char dir[LENGTH];
    struct Stat* next;
} Stat;

Stat* head = NULL;
Stat* current = NULL;
Stat* before = NULL;
FILE* file;

Stat* allocNode() {
    Stat* node = (Stat*)malloc(sizeof(Stat));
    if (node == NULL) {
        perror("Error at malloc\n");
        exit(EXIT_FAILURE);
    }
    node->next = NULL;
    return node;
}

void printStatOfDirs(const char* dirPath, FILE* file) {//snapshot
    DIR* directory;
    directory = opendir(dirPath);
    if (directory == NULL) {
        perror("No directory1\n");
        exit(EXIT_FAILURE);
    }
    struct dirent* entry;
    struct stat attrib;
    if (chdir(dirPath) == -1) {
        perror("Can't change directory\n");
        exit(EXIT_FAILURE);
    }
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            char path[MAX_PATH];
            snprintf(path, sizeof(path), "%s/%s", dirPath, entry->d_name);
            if (stat(path, &attrib) == 0) {
                printf("%s\n", entry->d_name);
                fprintf(file, "%s\t\t\t\t---st_dev<<<%ld>>> st_mode<<<%d>>> st_nlink<<<%ld>>> st_uid<<<%d>>> st_rdev<<<%ld>>> st_size<<<%ld>>>---\n", entry->d_name, attrib.st_dev, attrib.st_mode, attrib.st_nlink, attrib.st_uid, attrib.st_rdev, attrib.st_size);
                if (S_ISDIR(attrib.st_mode)) {
                    printStatOfDirs(path, file);
                }
            }
        }
    }
    closedir(directory);
}

void printDirArgs(int argc, char* argv[]) {
    for (int i = 3; i < argc; i++) {
        printStatOfDirs(argv[i], file);
    }
}

void storeStat(const char* dirPath, FILE* file, Stat* node) {
    DIR* directory;
    directory = opendir(dirPath);
    if (directory == NULL) {
        perror("No directory2\n");
        exit(EXIT_FAILURE);
    }
    struct dirent* entry;
    struct stat attrib;
    if (chdir(dirPath) == -1) {
        perror("Can't change directory\n");
        exit(EXIT_FAILURE);
    }
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            char path[MAX_PATH];
            snprintf(path, sizeof(path), "%s/%s", dirPath, entry->d_name);
            if (stat(path, &attrib) == 0) {
                printf("%s\n", entry->d_name);
                sprintf(current->dirMatrix[current->nrFiles], "%s\t\t\t\t---st_dev<<<%ld>>> st_mode<<<%d>>> st_nlink<<<%ld>>> st_uid<<<%d>>> st_rdev<<<%ld>>> st_size<<<%ld>>>---\n", entry->d_name, attrib.st_dev, attrib.st_mode, attrib.st_nlink, attrib.st_uid, attrib.st_rdev, attrib.st_size);
                current->nrFiles++;
                if (S_ISDIR(attrib.st_mode)) {
                    storeStat(path, file, node);
                }
            }
        }
    }
    closedir(directory);
}

void storeInList(int argc, char* argv[]) {
    for (int i = 3; i < argc; i++) {
        current = allocNode();
        current->nrFiles = 0;
        storeStat(argv[i], file, current);
        strcpy(current->dir, argv[i]);
        if (head == NULL) {
            head = current;
            before = head;
        }
        else {
            before->next = current;
            before = current;
            current = NULL;
        }
    }
}

void writeInfo() {
    current = head;
    while (current != NULL) {
        for (int i = 0; i < current->nrFiles; i++) {
            fprintf(file, "%s ", current->dirMatrix[i]);
        }
        fprintf(file, "\t files \t <<<%s>>>\n", current->dir);
        current = current->next;
    }
}

void compareAndUpdate(int argc, char* statFile, char* argv[]) {
    file = fopen(statFile, "r");
    if (file == NULL) {
        perror("Error opening the file for reading\n");
        exit(EXIT_FAILURE);
    }

    bool difference = false;
    char buf[MAX_PATH];
    while (fgets(buf, MAX_PATH, file) != NULL) {
        for (int i = 3; i < argc; i++) {
            if (strstr(buf, argv[i]) != NULL) {
                difference = true;
                break;
            }
        }
        if (difference) {
            break;
        }
    }
    fclose(file);

    if (!difference) {
        printf("No difference found\n");
    }
    else {
        file = fopen(statFile, "w");
        if (file == NULL) {
            perror("Error opening the file for writing\n");
            exit(EXIT_FAILURE);
        }
        writeInfo();
        fclose(file);
    }
}

int main(int argc, char* argv[]) {
    pid_t pid[argc - 3], wpid;
    int i, status;

    if (argc <3 || argc>11 ) {
        perror("Wrong number of arguments!\n");
        exit(EXIT_FAILURE);
    }

    if (strcmp(argv[1], "-o") != 0) {
        perror("First argument must be -o.\n");
        exit(EXIT_FAILURE);
    }

    FILE* file = fopen(argv[2], "w");
    if (file == NULL) {
        perror("No file\n");
        exit(EXIT_FAILURE);
    }
   /* if(strcmp(argv[3],"-s")!=0){
        perror("Third argument must be -s.\n");
        exit(EXIT_FAILURE);
    }
*/
    printDirArgs(argc, argv);
    storeInList(argc, argv);
    compareAndUpdate(argc, argv[2], argv);

    for (i = 0; i < argc - 3; i++) {
        if ((pid[i] = fork()) < 0) {
            perror("Error at fork\n");
            exit(EXIT_FAILURE);
        }

        if (pid[i] == 0) {
            printStatOfDirs(argv[i + 3], file);
            exit(0);
        }
    }

    for (i = 0; i < argc - 3; i++) {
        wpid = wait(&status);
        if (WIFEXITED(status))
            printf("Child %d ended with code %d\n", wpid, WEXITSTATUS(status));
        else
            printf("Child %d ended abnormally\n", wpid);
    }

    fclose(file);

    return 0;
}