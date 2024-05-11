#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

#define MAX_PATH_LENGTH 1024

typedef struct {
    char name[MAX_PATH_LENGTH];
    mode_t mode;
    off_t size;
    time_t mtime;
} FileMetadata;

void get_file_metadata(const char *path, FileMetadata *metadata) {
    struct stat file_stat;
    if (stat(path, &file_stat) == -1) {
        perror("Error getting file metadata");
        exit(EXIT_FAILURE);
    }

    strncpy(metadata->name, path, MAX_PATH_LENGTH);
    metadata->mode = file_stat.st_mode;
    metadata->size = file_stat.st_size;
    metadata->mtime = file_stat.st_mtime;
}

void capture_directory(const char *dir_path, const char *output_dir, const char *isolated_dir, int *corrupt_count) {
    DIR *dir;
    struct dirent *entry;

    if ((dir = opendir(dir_path)) == NULL) {
        perror("Error opening directory");
        exit(EXIT_FAILURE);
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char path[MAX_PATH_LENGTH];
        snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);

        FileMetadata metadata;
        get_file_metadata(path, &metadata);

        if ((metadata.mode & (S_IRWXU | S_IRWXG | S_IRWXO)) == 0) {
            int pipe_fd[2];
            if (pipe(pipe_fd) == -1) {
                perror("Error creating pipe");
                exit(EXIT_FAILURE);
            }

            pid_t child_pid = fork();
            if (child_pid == -1) {
                perror("Error creating child process");
                exit(EXIT_FAILURE);
            } else if (child_pid == 0) {
                close(pipe_fd[0]);
                execl("./verify_for_malicious.sh", "./verify_for_malicious.sh", path, isolated_dir, "corrupted", "dangerous", "risk", "attack", "malware", "malicious", NULL);
                perror("Error executing script");
                exit(EXIT_FAILURE);
            } else { 
                close(pipe_fd[1]);

                char result[20];
                ssize_t read_bytes = read(pipe_fd[0], result, sizeof(result) - 1);
                if (read_bytes == -1) {
                    perror("Error reading from pipe");
                    exit(EXIT_FAILURE);
                }
                result[read_bytes] = '\0';

                close(pipe_fd[0]);

                if (strcmp(result, "SAFE") == 0) {
                    printf("File '%s' is safe.\n", metadata.name);
                } else {
                    printf("File '%s' is potentially malicious.\n", metadata.name);
                    (*corrupt_count)++;
                    /*char new_path[MAX_PATH_LENGTH];
                    snprintf(new_path, sizeof(new_path), "%s/%s", isolated_dir, entry->d_name);
                    if (rename(path, new_path) == -1) {
                        perror("Error moving file to isolated directory");
                        exit(EXIT_FAILURE);
                    }*/
                }
            }
        }
    }

    closedir(dir);
}

int main(int argc, char *argv[]) {
    if (argc < 5 || argc > 15) {
        printf("Error: Invalid number of arguments. Usage: %s -o output_dir -s isolated_space_dir dir1 dir2 ...\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-o") != 0) {
        printf("Error: First argument must be -o for specifying the output directory.\n");
        return 1;
    }

    const char *output_dir = argv[2];
    const char *isolated_space_dir = argv[4];

    struct stat st;
    if (stat(output_dir, &st) == -1) {
        printf("Error: Output directory does not exist.\n");
        return 1;
    }
    if (stat(isolated_space_dir, &st) == -1) {
        printf("Error: Isolated space directory does not exist.\n");
        return 1;
    }

    int corrupt_count = 0;

    for (int i = 5; i < argc; i++) {
        struct stat st2;
        if (stat(argv[i], &st2) == -1) {
            printf("Error: Cannot access %s\n", argv[i]);
            continue;
        }

        if (!S_ISDIR(st2.st_mode)) {
            printf("Error: %s is not a directory. Ignored.\n", argv[i]);
            continue;
        }

        pid_t child_pid = fork();
        if (child_pid == -1) {
            perror("Error creating child process");
            return 1;
        } else if (child_pid == 0) { 
            capture_directory(argv[i], output_dir, isolated_space_dir, &corrupt_count);
            exit(corrupt_count); 
        }
    }

    int status;
    pid_t pid;
    int total_corrupt = 0;

    while ((pid = wait(&status)) != -1) {
        if (WIFEXITED(status)) {
            total_corrupt += WEXITSTATUS(status);
            printf("Child process terminated with PID %d and %d files potentially malicious.\n", pid, WEXITSTATUS(status));
        } else {
            printf("Child process terminated abnormally.\n");
        }
    }

    printf("Total number of potentially malicious files found: %d\n", total_corrupt);

    return 0;
}