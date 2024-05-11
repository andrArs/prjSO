#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <libgen.h>

#define PATH_SIZE 1024
#define METADATA_SIZE 256

typedef struct {
    char name[PATH_SIZE];
    mode_t mode;
    off_t size;
    time_t mtime;
}Metadata;

void getMetadata(const char *path,Metadata *metadata) {
    struct stat file_stat;
    if (stat(path, &file_stat) == -1) {
        perror("Eroare la obtinerea metadatelor\n");
        exit(EXIT_FAILURE);
    }

    strncpy(metadata->name, path,PATH_SIZE);
    metadata->mode = file_stat.st_mode;
    metadata->size = file_stat.st_size;
    metadata->mtime = file_stat.st_mtime;
}   

void processDirectory(const char *dirPath, const char *outDir, const char *isolatedDir,char *snapshotPath,FILE *snapshot,int *corruptedFiles) {
    DIR *dir;
    struct dirent *entry;
   // int knt=1;
    if ((dir = opendir(dirPath)) == NULL) {
        perror("Eroare la deschiderea directorului.\n");
        exit(EXIT_FAILURE);
    }
char path[PATH_SIZE];
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
    
        
        snprintf(path, sizeof(path), "%s/%s", dirPath, entry->d_name);

        Metadata metadata;
        getMetadata(path, &metadata);
     
/*
       if ((metadata.mode & (S_IRWXU | S_IRWXG | S_IRWXO)) == 0) {// adica e posibil sa fie corupt
            //if (!(metadata.mode & S_IRUSR) || !(metadata.mode & S_IWUSR) || !(metadata.mode & S_IXUSR)) {
           
            pid_t child_pid = fork();
            if (child_pid<0) {
                perror("Procesul copil-nepot? nu s a creat cum trebuie.\n");
                exit(-1);
            } else if (child_pid == 0) {
                printf("Analiza fisierului: %s\n", path);
                char IsolatedDirPath[256];
                snprintf(IsolatedDirPath, sizeof(IsolatedDirPath), "%s/", isolatedDir);
                //perror("Error executing script");
                dup2(pfd[1], STDOUT_FILENO);
                execl("./verify_for_malicious.sh", "./verify_for_malicious.sh", path, IsolatedDirPath, "corrupted", "dangerous", "risk", "attack", "malware", "malicious", NULL);
 
                exit(0);
            }
            wait(NULL);
            /*pid_t wpid;
            int nr=0,status;
             if((wpid=waitpid(-1,&status,0))>0){
                if(WIFEXITED(status)){
	                printf("Nepo process terminated with PID %d and exit code %d.\n",wpid,WEXITSTATUS(status));
                        }
                else{
                    printf("Nepo %d ended abnormally\n", wpid);
                }
                }*/
                //}*/
        if ((metadata.mode & (S_IRWXU | S_IRWXG | S_IRWXO)) == 0) {
            int pfd[2];
            if (pipe(pfd) < 0) {
                printf("Eroare la crearea pipe-ului.\n");
                exit(EXIT_FAILURE);
            }
            pid_t child_pid = fork();
            if (child_pid < 0) {
                perror("Eroare la crearea procesului copil.\n");
                exit(-1);
            } else if (child_pid == 0) {
                printf("Analiza fisierului: %s\n", path);
                close(pfd[0]);//inchid capatul de citire pt ca o sa scriu in pipe
                char IsolatedDirPath[256];
                snprintf(IsolatedDirPath, sizeof(IsolatedDirPath), "%s/", isolatedDir);
               if (dup2(pfd[1], STDOUT_FILENO) == -1) {
                perror("Eroare la redirectarea stdout");
                exit(EXIT_FAILURE);
                }
                execl("./verify_for_malicious.sh", "./verify_for_malicious.sh", path, IsolatedDirPath, "corrupted", "dangerous", "risk", "attack", "malware", "malicious", NULL);
                close(pfd[1]);//inchid si capatul utilizat
                exit(0);
            } else {
                close(pfd[1]);
                char buffer[1024];
                int bytes_read = read(pfd[0], buffer, sizeof(buffer));
                if (bytes_read==-1) {
                    printf("Nu s-a putut citi din pipe.\n");
                    exit(EXIT_FAILURE);
                }else if (bytes_read == 0) {
                    printf("Nimic de citit din pipe.\n");
                    }else{
                    buffer[bytes_read] = '\0';
                    //printf("%s,%s\n", buffer,path);
                   if(strstr(buffer,"SAFE")){
                    printf("File %s is safe.\n", path);
                   }else{printf("%s \n",buffer);
                    printf("File %s may be corrupted.\n",path);
                    (*corruptedFiles)++;
                    /*char command[PATH_SIZE + 50];
                    snprintf(command, sizeof(command), "mv %s %s", path, isolatedDir);
                    system(command);*/
                    char IsolatedDirPath[256];
                    snprintf(IsolatedDirPath, sizeof(IsolatedDirPath), "%s/", isolatedDir);
                    char command[PATH_SIZE + 50];
                    snprintf(command, sizeof(command), "./moveCorruptedFileToDirectory.sh %s %s", path, isolatedDir);
                    system(command);
                    
                    }
                    close(pfd[0]);
                    }
                
               
            }
             wait(NULL);
        }
        else{

       // char snapshotPath[PATH_SIZE];
       // snprintf(snapshotPath, sizeof(snapshotPath), "%s/%d_snapshot.txt", outDir, knt);
        //knt++;

        //parte asta-i pentru comparare

        /*
        FILE *snapshotFile = fopen(snapshotPath, "r");
        if (snapshotFile != NULL) {
            Metadata snapshotMetadata;
            fread(&snapshotMetadata, sizeof(Metadata), 1, snapshotFile);
            fclose(snapshotFile);

            if (metadata.mode != snapshotMetadata.mode ||
                metadata.size != snapshotMetadata.size ||
                metadata.mtime != snapshotMetadata.mtime) {
                printf("Modifications detected in file: %s\n", path);
                snapshotFile = fopen(snapshotPath, "w");
            if (snapshotFile != NULL) {
                fwrite(&metadata, sizeof(Metadata), 1, snapshotFile);
                fclose(snapshotFile);
            }
            }
        } else{
            snapshotFile = fopen(snapshotPath, "w");
            if (snapshotFile != NULL) {
                fwrite(&metadata, sizeof(Metadata), 1, snapshotFile);
                fclose(snapshotFile);
            }
        }
        */
        
         int snapshotFile = open(snapshotPath, O_RDONLY);
        if (snapshotFile != -1)
        {
            Metadata snapshotMetadata;
            read(snapshotFile, &snapshotMetadata, sizeof(Metadata));
            close(snapshotFile);

            if (metadata.mode != snapshotMetadata.mode ||
                metadata.size != snapshotMetadata.size ||
                metadata.mtime != snapshotMetadata.mtime)
            {//printf("Modifications detected in file: %s\n", path);
                snapshotFile = open(snapshotPath, O_WRONLY | O_CREAT | O_TRUNC, 0644); 
                // Deschide fisierul de snapshot pentru scriere si il creaza daca nu exista
                if (snapshotFile != -1)
                {
                    dprintf(snapshotFile, "File: %s\n", metadata.name);
                    dprintf(snapshotFile, "Size: %ld bytes\n", (long)metadata.size);
                    dprintf(snapshotFile, "Last modified time: %s", ctime(&metadata.mtime));
                    dprintf(snapshotFile, "Path: %s\n", path);
                    dprintf(snapshotFile, "st_mode: %d\n\n\n", metadata.mode);
                    close(snapshotFile);
                    //printf("Snapshot for Directory %s updated successfully.\n", dirPath);
                     
                }
                else
                {
                    perror("Error updating snapshot file");
                }
            }
        }
        else
        {
            int snapshotFile = open(snapshotPath, O_WRONLY | O_CREAT | O_TRUNC, 0644); 
            // Deschide fisierul de snapshot pentru scriere si il creaza daca nu exista
            if (snapshotFile != -1)
            {

                write(snapshotFile, &metadata, sizeof(Metadata));
                close(snapshotFile);
            }
        }

        //aici creez snapshotul pt director
         struct stat st;
         if (stat(path, &st) != -1) {
                // Afiseaza numele fisierului/directorului  
                fprintf(snapshot, "%s -> ", entry->d_name);

                // Afiseaza tipul fisierului/directorului
                if (S_ISDIR(st.st_mode)) {
                    fprintf(snapshot, "Director\n");
                } else if (S_ISREG(st.st_mode)) {
                    fprintf(snapshot, "Fisier\n");
		    
                }
                // Afiseaza drepturile fisierului/directorului
                fprintf(snapshot, "Drepturi: ");
                fprintf(snapshot, (st.st_mode & S_IRUSR) ? "r" : "-");
                fprintf(snapshot, (st.st_mode & S_IWUSR) ? "w" : "-");
                fprintf(snapshot, (st.st_mode & S_IXUSR) ? "x" : "-");
                fprintf(snapshot, (st.st_mode & S_IRGRP) ? "r" : "-");
                fprintf(snapshot, (st.st_mode & S_IWGRP) ? "w" : "-");
                fprintf(snapshot, (st.st_mode & S_IXGRP) ? "x" : "-");
                fprintf(snapshot, (st.st_mode & S_IROTH) ? "r" : "-");
                fprintf(snapshot, (st.st_mode & S_IWOTH) ? "w" : "-");
                fprintf(snapshot, (st.st_mode & S_IXOTH) ? "x" : "-");
                fprintf(snapshot, "\n");
                // Afiseaza metadatele (de exemplu, dimensiunea, data ultimei modificari)
                    fprintf(snapshot, "File: %s\n", metadata.name);
                    fprintf(snapshot, "Size: %ld bytes\n", (long)metadata.size);
                    fprintf(snapshot, "Last modified time: %s", ctime(&metadata.mtime));
                    fprintf(snapshot, "Path: %s\n", path);
                    fprintf(snapshot, "st_mode: %d\n\n\n", metadata.mode);
                //fprintf(snapshot, "Dimensiune: %ld bytes, Ultima modificare: %s\n", st.st_size, ctime(&st.st_mtime));
            } else {
                // Afiseaza eroarea daca nu s-au putut obtine metadatele
                perror("Eroare la obtinerea metadatelor");
            }
            if(S_ISDIR(st.st_mode)){
            processDirectory(path, outDir, isolatedDir,snapshotPath,snapshot,corruptedFiles);
        }
    }
     
    }
    
    if(closedir(dir) == -1){
     fprintf(stderr, "Eroare la inchiderea directorului!\n");
     exit(EXIT_FAILURE);
    }
}

/* nu i buna
int verificareDrepturiLipsa(const char* numeDirector,const char *isolatedSpaceDir) {
    DIR* dirID = opendir(numeDirector);
    struct dirent* entry;
    struct stat st;
    char filePath[SIZE_PATH];
    int ok=0;
    if (!dirID) {
        fprintf(stderr, "Eroare la deschiderea directorului, e posibil sa nu ai dreptul sa l deschizi %s\n",numeDirector);
        exit(-1);
    }

    while ((entry = readdir(dirID)) != NULL) {
        sprintf(filePath, "%s/%s", numeDirector, entry->d_name);
        if (stat(filePath, &st) == 0 && S_ISREG(st.st_mode)) {
            if (!(st.st_mode & S_IRUSR) || !(st.st_mode & S_IWUSR) || !(st.st_mode & S_IXUSR)) {
                ok++;//inseamna ca poate fi corupt
                pid_t pid = fork();
                if (pid < 0) {
                    perror("Eroare la crearea procesului\n");
                    exit(-1);
                } else if (pid == 0) {
                    printf("Incep analiza sinactica a directorului: %s\n",numeDirector);
                    execl("./verify_for_malicious.sh", "./verify_for_malicious.sh", filePath, isolatedSpaceDir, "corrupted", "dangerous", "risk", "attack", "malware", "malicious", NULL);

                    exit(0);
                }
               
            }
        }
    }
    int status;
    pid_t wpid;
    wpid=wait(&status);
    if(WIFEXITED(status)){
        printf(" s a terminat cum trb procesul nepot al directorului :%s.\n",numeDirector);
    }
    else{
       printf("Nu s a terminat cum trb procesulnepot al directorului :%s.\n",numeDirector);
    }
    closedir(dirID);
    return ok;// este un fisier ok daca ok=0; daca ok!=0 nu este, este corupt
}

*/



void procesareaArgumentelor(int argc,char *argv[],char *outputDir,char *isolatedSpaceDir)
 {

    if(argc<5 || argc >15){
        fprintf(stderr, "Numar invalid de argumente!\n");
        exit(EXIT_FAILURE);
    }

    for(int i=0;i<argc;i++){
        for(int j=i+1;j<argc;j++){
            if(strcmp(argv[i],argv[j])==0){
                printf("exista doua argumente cu acelasi nume, reintrodu datele \n");
                exit(EXIT_FAILURE);
            }
        }
    }
    /*
    caut in lista de argumente directorul de ieșire în care vor fi stocate
    toate snapshot-urile intrărilor din directoarele specificate( se afla dupa -o de aia verific i+1 e still in range)
    ->cand il gasesc il retin in outputDir si ies din for
    Fac la fel si pentru directorul pentru fisierele corupte;
    */
   outputDir=NULL;
   isolatedSpaceDir=NULL;
    for(int i=1;i<argc;i++){
        if(strcmp(argv[i],"-o")==0 && i+1<argc){
            outputDir=argv[i+1];
            break;
        }
    }

    //verific daca exista sau nu directorul in lista de argumente
    if(outputDir==NULL){
        fprintf(stderr,"Nu s-a gasit directorul de iesire! \n");
        exit(EXIT_FAILURE);
    }

    for(int i=1;i<argc;i++){
      if(strcmp(argv[i],"-s")==0 && i+1<argc){
	    isolatedSpaceDir=argv[i+1];
	    break;
      }
    }

    if(isolatedSpaceDir==NULL){
      perror("Nu s-a gasit directorul pentru fisierele corupte.\n");
      exit(EXIT_FAILURE);
    }
    struct stat stt;
    if (stat(outputDir, &stt) == -1) {
        printf("Error: Output directory nu exista.\n");
        exit(EXIT_FAILURE);
    }
    if (stat(isolatedSpaceDir, &stt) == -1) {
        printf("Error: Isolated space directory nu exista.\n");
        exit(EXIT_FAILURE);
    }

    // Adăugăm aici procesarea fisierelor corupte prin comunicare cu pipe
   /*int pipes[2];
    if (pipe(pipes) == -1) {
        perror("Eroare la crearea pipe-ului.\n");
        exit(EXIT_FAILURE);
    }*/
    //aici creez procesele
    pid_t pid[11],wpid;
    int status;
    int nr=0;
    //parcurg argumentele pentru a procesa doar directoarele
    for(int i=5;i<argc;i++){
        struct stat st;
        if(stat(argv[i],&st)==0 && S_ISDIR(st.st_mode)){
            //procesul parinte
            int corruptedFiles=0;
	        pid[i]=fork();
        if(pid[i]<0){
            perror("Eroare la crearea procesului copil\n");
            exit(-1);
        }
	    else if(pid[i]==0){//pt copil
            char caleCatreSnapshot[256];
            snprintf(caleCatreSnapshot, sizeof(caleCatreSnapshot), "%s/snapshot%d.txt", outputDir, i);
            FILE *fisSnapshot = fopen(caleCatreSnapshot, "w");
            if (fisSnapshot == NULL) {
                fprintf(stderr, "Nu s-a deschis corect fisierul pentru snapshot %d\n", i);
                exit(EXIT_FAILURE);
            }
            snprintf(caleCatreSnapshot, sizeof(caleCatreSnapshot), "%s/snapshotComparare%s.txt", outputDir, argv[i]);
            processDirectory(argv[i], outputDir, isolatedSpaceDir,caleCatreSnapshot,fisSnapshot,&corruptedFiles);
            fclose(fisSnapshot);
	        printf("Snapshot for Directory %s created successfully.\n",argv[i]);
            exit(corruptedFiles);
	         //exit(0);
	         }
        /* else{
        // Proces părinte
            close(pipes[1]); // Închidem capătul de scriere al pipe-ului în procesul părinte
            char buffer[PATH_SIZE];
            ssize_t bytes_read;
            while ((bytes_read = read(pipes[0], buffer, sizeof(buffer))) > 0) {
                buffer[bytes_read] = '\0';
                printf("File moved to isolated space: %s\n", buffer);
            }
             close(pipes[0]); // Închidem capătul de citire al pipe-ului în procesul părinte
        }
        } else {
            fprintf(stderr, "%s nu este un director valid\n", argv[i]);
        }*/
    }
    }

    int totalFisCor=0;
    //verific daca s-au terminat procesele
     for (int i = 5; i < argc; i++){
    if((wpid=waitpid(-1,&status,0))!=-1){nr++;
        if(WIFEXITED(status)){
            totalFisCor+=WEXITSTATUS(status);
            printf("Child process%d terminated with PID %d and %d files potentially malicious.\n",nr,wpid,WEXITSTATUS(status));
        }
        else{
            printf("Child %d ended abnormally\n", wpid);
        }
      }
      else{
        perror("Error waiting for child process");
        exit(EXIT_FAILURE);
      }
     }
     printf("Total number of potentially malicious files found: %d\n", totalFisCor);
    
}

    int main(int argc, char* argv[]){

    char *outputDir=NULL;
    char *isolatedSpaceDir=NULL;
    procesareaArgumentelor(argc,argv,outputDir,isolatedSpaceDir);

    return 0;
    }