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
#define MAX_FILE_METADATA_LENGTH 256

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

/*void capture_directory(const char *dir_path, const char *output_dir) {
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

        char snapshot_path[MAX_PATH_LENGTH];
        snprintf(snapshot_path, sizeof(snapshot_path), "%s/%s.snapshot", output_dir, entry->d_name);

        FILE *snapshot_file = fopen(snapshot_path, "r");
        if (snapshot_file != NULL) {
            FileMetadata snapshot_metadata;
            fread(&snapshot_metadata, sizeof(FileMetadata), 1, snapshot_file);
            fclose(snapshot_file);

            if (metadata.mode != snapshot_metadata.mode ||
                metadata.size != snapshot_metadata.size ||
                metadata.mtime != snapshot_metadata.mtime) {
                printf("Modifications detected in file: %s\n", path);
            }
        } else {
            snapshot_file = fopen(snapshot_path, "w");
            if (snapshot_file != NULL) {
                fwrite(&metadata, sizeof(FileMetadata), 1, snapshot_file);
                fclose(snapshot_file);
            }
        }
    }

    closedir(dir);
}*/


/*void check_missing_permissions(const char *dir_path, const char *output_dir, const char *isolated_space_dir) {
    DIR *dir;
    struct dirent *entry;

    if ((dir = opendir(dir_path)) == NULL) {
        perror("Error opening directory");
        exit(EXIT_FAILURE);
    }

    while ((entry = readdir(dir)) != NULL) {
        char path[MAX_PATH_LENGTH];
        snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);

        struct stat st;
        if (stat(path, &st) == -1) {
            perror("Error accessing file");
            continue;
        }

        if (S_ISREG(st.st_mode) && (st.st_mode & S_IRUSR) == 0 && (st.st_mode & S_IWUSR) == 0 && (st.st_mode & S_IXUSR) == 0) {
            pid_t pid = fork();
            if (pid == -1) {
                perror("Error creating child process");
                exit(EXIT_FAILURE);
            } else if (pid == 0) {
                char script_path[MAX_PATH_LENGTH];
                snprintf(script_path, sizeof(script_path), "%s/verify_for_malicious.sh", output_dir);
                execl(script_path, "verify_for_malicious.sh", path, (char *)NULL);
                perror("Error executing script");
                exit(EXIT_FAILURE);
            } else {
                int status;
                waitpid(pid, &status, 0);
                if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                    char dst_path[MAX_PATH_LENGTH];
                    snprintf(dst_path, sizeof(dst_path), "%s/%s", isolated_space_dir, entry->d_name);
                    if (rename(path, dst_path) == -1) {
                        perror("Error moving file to isolated space");
                    }
                }
            }
        }
    }

    closedir(dir);
}*/

void capture_directory(const char *dir_path, const char *output_dir, const char *isolated_dir) {
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
            pid_t child_pid = fork();
            if (child_pid == -1) {
                perror("Error creating child process");
                exit(EXIT_FAILURE);
            } else if (child_pid == 0) {
                printf("Analyzing file: %s\n", path);
                execl("./verify_for_malicious.sh", "./verify_for_malicious.sh", path, isolated_dir, "corrupted", "dangerous", "risk", "attack", "malware", "malicious", NULL);
                perror("Error executing script");
                exit(EXIT_FAILURE);
            }
        }

        char snapshot_path[MAX_PATH_LENGTH];
        snprintf(snapshot_path, sizeof(snapshot_path), "%s/%s_snapshot.txt", output_dir, entry->d_name);

        FILE *snapshot_file = fopen(snapshot_path, "r");
        if (snapshot_file != NULL) {
            FileMetadata snapshot_metadata;
            fread(&snapshot_metadata, sizeof(FileMetadata), 1, snapshot_file);
            fclose(snapshot_file);

            if (metadata.mode != snapshot_metadata.mode ||
                metadata.size != snapshot_metadata.size ||
                metadata.mtime != snapshot_metadata.mtime) {
                printf("Modifications detected in file: %s\n", path);
            }
        } else {
            snapshot_file = fopen(snapshot_path, "w");
            if (snapshot_file != NULL) {
                fwrite(&metadata, sizeof(FileMetadata), 1, snapshot_file);
                fclose(snapshot_file);
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

    int i, status;
    pid_t child_pid;
    for (i = 5; i < argc; i++) {
        struct stat st2;
        if (stat(argv[i], &st2) == -1) {
            printf("Error: Cannot access %s\n", argv[i]);
            continue;
        }

        if (!S_ISDIR(st2.st_mode)) {
            printf("Error: %s is not a directory. Ignored.\n", argv[i]);
            continue;
        }

        child_pid = fork();
        if(child_pid == -1){
            perror("Error creating child process");
            return 1;
        }
        else if(child_pid == 0){
            printf("Child process with PID %d started.\n", getpid());
            capture_directory(argv[i], output_dir, isolated_space_dir);
            printf("Child process with PID %d terminated.\n", getpid());
            exit(EXIT_SUCCESS);
        }
    }

    for (i = 5; i < argc; i++) {
        if (waitpid(-1, &status, 0) > 0) {
            if (WIFEXITED(status)) {
                printf("Child process %d terminated with PID %d and exit code %d.\n", i - 2, child_pid, WEXITSTATUS(status));
            } else {
                printf("Child process %d terminated abnormally.\n", i - 2);
            }
        } else {
            perror("Error waiting for child process");
            return 1;
        }
    }

    return 0;
}