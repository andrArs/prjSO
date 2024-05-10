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
#define SIZE_PATH 512

    typedef struct {
        char name[1024];
        mode_t mode;
        off_t size;
        time_t mtime;
    }Date;

    void getData(const char *cale,Date *metadate){
      /*  struct stat file_stat;
    if (stat(cale, &file_stat) == -1) {
        perror("Error getting file metadata");
        exit(EXIT_FAILURE);
    }*/

    strncpy(metadata->name, path, MAX_PATH_LENGTH);
    metadate->mode = file_stat.st_mode;
    metadate->size = file_stat.st_size;
    metadate->mtime = file_stat.st_mtime;
}
    

    void Snapshot(DIR* dirID, const char* numeFolder, FILE* fisierStare) {
    /* Parcurg directorul atata timp cat am ceva in el */
    char caleCatreFisierSauFolder[SIZE_PATH];
    struct stat st;
    caleCatreFisierSauFolder[0] = 0;
    fprintf(fisierStare, "Director: %s\n", numeFolder);
    struct dirent* date = NULL;
    while ((date = readdir(dirID)) != NULL) {
        if (strcmp(date->d_name, "..") != 0 && strcmp(date->d_name, ".") != 0) {
            // copiez calea catre fisier/folder
            strcpy(caleCatreFisierSauFolder, numeFolder);
            strcat(caleCatreFisierSauFolder, "/");
            strcat(caleCatreFisierSauFolder, date->d_name);

            // Obțin metadatele fișierului/directorului
            if (stat(caleCatreFisierSauFolder, &st) != -1) {
                // Afiseaza numele fisierului/directorului
                Date metadate;
                getData(caleCatreFisierSauFolder,&metadate);
                
                fprintf(fisierStare, "%s -> ", date->d_name);

                // Afiseaza tipul fisierului/directorului
                if (S_ISDIR(st.st_mode)) {
                    fprintf(fisierStare, "Director\n");
                } else if (S_ISREG(st.st_mode)) {
                    fprintf(fisierStare, "Fisier\n");
		    
                }
                // Afiseaza drepturile fișierului/directorului
                fprintf(fisierStare, "Drepturi: ");
                fprintf(fisierStare, (st.st_mode & S_IRUSR) ? "r" : "-");
                fprintf(fisierStare, (st.st_mode & S_IWUSR) ? "w" : "-");
                fprintf(fisierStare, (st.st_mode & S_IXUSR) ? "x" : "-");
                fprintf(fisierStare, (st.st_mode & S_IRGRP) ? "r" : "-");
                fprintf(fisierStare, (st.st_mode & S_IWGRP) ? "w" : "-");
                fprintf(fisierStare, (st.st_mode & S_IXGRP) ? "x" : "-");
                fprintf(fisierStare, (st.st_mode & S_IROTH) ? "r" : "-");
                fprintf(fisierStare, (st.st_mode & S_IWOTH) ? "w" : "-");
                fprintf(fisierStare, (st.st_mode & S_IXOTH) ? "x" : "-");
                fprintf(fisierStare, "\n");
                // Afiseaza metadatele (de exemplu, dimensiunea, data ultimei modificări)
                fprintf(fisierStare, "Dimensiune: %ld bytes, Ultima modificare: %s\n", st.st_size, ctime(&st.st_mtime));
            } else {
                // Afiseaza eroarea daca nu s-au putut obține metadatele
                perror("Eroare la obținerea metadatelor");
            }

            // Dacă este un director, apelăm recursiv Snapshot pentru a parcurge și acest director
            if (S_ISDIR(st.st_mode)) {
                DIR* dirIDAux = opendir(caleCatreFisierSauFolder);
                if (dirIDAux) {
                    Snapshot(dirIDAux, caleCatreFisierSauFolder, fisierStare);
                    closedir(dirIDAux);
                } else {
                    perror("Eroare la deschiderea directorului");
                }
            }
        }
    }
}



    void deschideDirector(char* path, const char* numeFolder, FILE* fisierStare){
    DIR* dirID = opendir(path);
    if(!dirID){
        fprintf(stderr, "Eroare la deschiderea directorului\n");
        exit(EXIT_FAILURE);
    }

    Snapshot(dirID, numeFolder, fisierStare);

    if(closedir(dirID) == -1){
     fprintf(stderr, "Eroare la inchiderea directorului!\n");
     exit(EXIT_FAILURE);
    }
    }
/*
void izoleazaFisier(const char* numeFisier, const char* directorIzolare) {
    // Construim calea către noul loc de izolare
    char caleNoua[PATH_MAX];
    snprintf(caleNoua, sizeof(caleNoua), "%s/%s", directorIzolare,basename(numeFisier));

    // Mutăm fișierul în directorul de izolare
    if (rename(numeFisier, caleNoua) != 0) {
        perror("Eroare la mutarea fișierului");
    } else {
        printf("Fișierul %s a fost izolat cu succes în directorul %s\n", numeFisier, directorIzolare);
    }
}*/

void analizaSintacticaFisier(const char* numeFisier, const char* numeFisierSh, const char* verifyScript, const char *izolatedSpaceDir)
 {
    FILE* fisier = fopen(numeFisier, "r");
    if (!fisier) {
        perror("Eroare la deschiderea fisierului");
        return;
    }

    int numarLinii = 0;
    int numarCuvinte = 0;
    int numarCaractere = 0;
    bool fisierPericulos = false;

    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), fisier) != NULL) {
        // Incrementăm numărul de linii
        numarLinii++;

        // Căutăm cuvinte cheie
        if (strstr(buffer, "corrupted") != NULL ||
            strstr(buffer, "dangerous") != NULL ||
            strstr(buffer, "risk") != NULL ||
            strstr(buffer, "attack") != NULL ||
            strstr(buffer, "malware") != NULL ||
            strstr(buffer, "malicious") != NULL) {
            fisierPericulos = true;
            break; // Dacă găsim o cuvânt cheie, nu mai avem nevoie să căutăm în continuare
        }

        // Numărăm cuvintele și caracterele
        char* token = strtok(buffer, " ");
        while (token != NULL) {
            numarCuvinte++;
            numarCaractere += strlen(token);
            token = strtok(NULL, " ");
        }
    }

    // Inchidem fișierul
    fclose(fisier);

    // Dacă fișierul este periculos, îl izolăm
     if (fisierPericulos) {
       // izoleazaFisier(numeFisier, izolatedSpaceDir);
        //izoleazaFisier(numeFisierSh, izolatedSpaceDir); // Izolează și fișierul .sh
    
    // Dacă fișierul este periculos, îl izolăm
   /* FILE* outputSh = fopen(numeFisierSh, "w");
    if (!outputSh) {
        perror("Eroare la deschiderea fisierului .sh pentru scriere");
        return;
    }*/
   
    printf("Analiza sintactica a fisierului %s:\n", numeFisier);
    printf("Numar de linii: %d\n", numarLinii);
    printf("Numar de cuvinte: %d\n", numarCuvinte);
    printf("Numar de caractere: %d\n", numarCaractere);
    if (fisierPericulos) {
        printf("Fisierul este considerat periculos!\n");
	//izolareFisier(numeFisier,izolatedSpaceDir);
    } else {
        printf("Fisierul este considerat sigur.\n");
    }

    // Scriem rezultatele analizei sintactice în fișierul .sh
    /*fprintf(outputSh, "#!/bin/bash\n");
    fprintf(outputSh, "echo \"Analiza sintactica a fisierului %s:\" >> output.log\n", numeFisier);
    fprintf(outputSh, "echo \"Numar de linii: %d\" >> output.log\n", numarLinii);
    fprintf(outputSh, "echo \"Numar de cuvinte: %d\" >> output.log\n", numarCuvinte);
    fprintf(outputSh, "echo \"Numar de caractere: %d\" >> output.log\n", numarCaractere);
    if (fisierPericulos) {
        fprintf(outputSh, "echo \"Fisierul este considerat periculos!\" >> output.log\n");
    } else {
        fprintf(outputSh, "echo \"Fisierul este considerat sigur.\" >> output.log\n");
    }

    fclose(outputSh);
    // Apelează scriptul de verificare pentru fisierul .sh*/
    execlp(verifyScript, verifyScript, numeFisierSh, NULL);}
}

int verificareDrepturiLipsa(const char* numeDirector,const char *izolatedSpaceDir) {
    DIR* dirID = opendir(numeDirector);
    struct dirent* entry;
    struct stat st;
    char filePath[SIZE_PATH];
    int ok=0;
    if (!dirID) {
        fprintf(stderr, "Eroare la deschiderea directorului\n");
        exit(-1);
    }

    while ((entry = readdir(dirID)) != NULL) {
        sprintf(filePath, "%s/%s", numeDirector, entry->d_name);
        if (stat(filePath, &st) == 0 && S_ISREG(st.st_mode)) {
            if (!(st.st_mode & S_IRUSR) || !(st.st_mode & S_IWUSR) || !(st.st_mode & S_IXUSR)) {
                ok++;//inseamna ca poate fi corupt
                int pfd[2];
                int pid;
                if(pipe(pfd)<0){
                    printf("Eroare la crearea pipe ului.\n");
                    exit(EXIT_FAILURE);
                }

                pid_t pid = fork();
                if (pid < 0) {
                    perror("Eroare la crearea procesului\n");
                    exit(-1);
                } else if (pid == 0) {
                    close(pfd[0]);//inchid capatul de citire pt ca o sa scriu in pipe
                    analizaSintacticaFisier(filePath, "output.sh", "./verify_for_malicious.sh", izolatedSpaceDir); // Transmite calea către verify_for_malicious.sh
                   // execlp("./verify_for_malicious.sh", "verify_for_malicious.sh", filePath, NULL);
                   write(pfd[1],buffer,size);
                   close(pfd[1]);//inchid si capatul utilizat
                    exit(0);
                }
                else{//codul parintelui
                    close(pfd[1]);//inchid capatul de scriere, pt ca voi citi
                    read(pfd[0],buffer,size);
                    close(pfd[0]);
                    exit(0);
                }
            }
        }
    }

    closedir(dirID);
    return ok;// este un fisier ok daca ok=0; daca ok!=0 nu este, este corupt
}




void procesareaArgumentelor(int argc,char *argv[],char *outputDir,char *izolatedSpaceDir)
 {

    if(argc<5 || argc >11){
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
    toate snapshot-urile intrărilor din directoarele specificate( se afla dupa -o de aia verific
    i+1 e still in range)
    ->cand il gasesc il retin in outputDir si ies din for
    Fac la fel si pentru directorul pentru fisierele corupte;
    */
   outputDir=NULL;
   izolatedSpaceDir=NULL;
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
	    izolatedSpaceDir=argv[i+1];
	    break;
      }
    }

    if(izolatedSpaceDir==NULL){
      perror("Nu s-a gasit directorul pentru fisierele corupte.\n");
      exit(EXIT_FAILURE);
    }
    //aici creez procesele
    pid_t pid[11],wpid;
    int status;
    int nr=0;
    //parcurg argumentele pentru a procesa doar directoarele
    for(int i=5;i<argc;i++){
        struct stat st;
        printf("%s \n",argv[i]);
        if(stat(argv[i],&st)==0 && S_ISDIR(st.st_mode)){
	  pid[i]=fork();
	  if(pid[i]<0){
	    perror("Eroare la crearea procesului\n");
	    exit(-1);
	  }else{
	    if(pid[i]==0){//pt copil
        //int ok=verificareDrepturiLipsa(argv[i],izolatedSpaceDir);
	      // if(ok==0){
                // aici directez fisierul txt de snapshot catre directorul de output
            char caleCatreSnapshot[256];
            snprintf(caleCatreSnapshot, sizeof(caleCatreSnapshot), "%s/snapshot%d.txt", outputDir, i);
            //sprintf(snapshotArgv,"snapshot%d.txt",i);
            FILE *fisSnapshot = fopen(caleCatreSnapshot, "w");
            if (fisSnapshot == NULL) {
                fprintf(stderr, "Nu s-a deschis corect fișierul pentru snapshot %d\n", i);
                exit(-2);
            }
            //fprintf(fisSnapshot,"Director Principal: %s\n",argv[i]);
            deschideDirector(argv[i], argv[i], fisSnapshot);

            fclose(fisSnapshot);
	    printf("Snapshot for Directory %s created successfully.\n",argv[i]);
        //}

	    exit(0);
	   }
	  }
            
        } else {
            fprintf(stderr, "%s nu este un director valid\n", argv[i]);
        }
    }
    
    //verific daca s-au terminat procesele
    while((wpid=waitpid(-1,&status,0))>0){nr++;
      if(WIFEXITED(status)){
	printf("Child process%d terminated with PID %d and exit code %d.\n",nr,wpid,WEXITSTATUS(status));
      }
      else{
         printf("Child %d ended abnormally\n", wpid);
      }
      }
    
    
}

    int main(int argc, char* argv[]){

    char *outputDir=NULL;
    char *izolatedSpaceDir=NULL;
    procesareaArgumentelor(argc,argv,outputDir,izolatedSpaceDir);

    return 0;
    }