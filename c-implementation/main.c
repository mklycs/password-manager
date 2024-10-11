#include <stdio.h>
#include <string.h>
#include <sqlcipher/sqlite3.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/evp.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <conio.h>   // Windows for masking input
    #include <windows.h>
    void copyToClipboard(const char* text){
        if(OpenClipboard(NULL)){                                       // Open the clipboard
            EmptyClipboard();                                          // Clear the clipboard
            HGLOBAL hGlob = GlobalAlloc(GMEM_FIXED, strlen(text) + 1); // Allocate global memory for the text
            if(hGlob){
                char* pGlob = (char*)GlobalLock(hGlob);                // Lock the global memory and copy the text
                strcpy(pGlob, text);
                GlobalUnlock(hGlob);
                SetClipboardData(CF_TEXT, hGlob);                      // Set the clipboard data
            }
            CloseClipboard();
        }
    }
#else
    #include <unistd.h>  // Unix-like systems for masking input 
    #include <termios.h>
    char getch(){                                
        struct termios oldt, newt;               // decleration of two variables (termios struct). oldt will be used to save the current terminal settings and newt to save the modified terminal settings
        char ch;
        tcgetattr(STDIN_FILENO, &oldt);          // calls curent terminal settings and saves them in oldt
        newt = oldt;                             // copies current terminal settings into new vairables so it can be modified without loosing the oiriginal / previous settings
        newt.c_lflag &= ~(ICANON | ECHO);        // modifies terminal settings by deactivating ICANON(input is processed line by line (until ENTER is pressed)) and ECHO(for displaying characters on screen while input) flags 
        tcsetattr(STDIN_FILENO, TCSANOW, &newt); // immediately(because TCSANOW) applies new terminal settings
        ch = getchar();                          // simply stores input character into variable
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // immediately(because TCSANOW) applies old terminal settings
        return ch;
    }
    void copyToClipboard(const char* text){
        char command[1024];                      // Create a command to echo the text and pipe it to xclip
        snprintf(command, sizeof(command), "printf '%%s' '%s' | xclip -selection clipboard", text);
        system(command);                         // Execute the command 
    }
#endif
#define LEN 20
#define AES_BLOCK_SIZE 16

void sha256(const char *str, char outputBuffer[65]){
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)){ //initialising sha-256 algorithm
        perror("EVP_DigestInit_ex failed");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    if(1 != EVP_DigestUpdate(mdctx, str, strlen(str))){ //adding data to hash
        perror("EVP_DigestUpdate failed");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    if(1 != EVP_DigestFinal_ex(mdctx, hash, &length)){ //final hash calculations
        perror("EVP_DigestFinal_ex failed");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_MD_CTX_free(mdctx);

    for(unsigned int i = 0; i < length; i++)
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);

    outputBuffer[64] = 0;
}

int file_exists(const char *filename){
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
}

void writeIntoFile(char *text){
    FILE *keyfile = fopen("key.key", "w");
    fprintf(keyfile, text);
    fclose(keyfile); 
}

void input(char *string, unsigned int password){
    char ch;
    for(int i = 0; i < LEN - 1; i++){
        if(password == 1){
            ch = getch();
            if(ch == 127){             //ASCII for backspace
                if(i == 0) i--;        //reduce index to overwrite the character
                else if(i > 0) i -= 2; //reduce index to overwrite the character
                    
                printf("\b \b ");      //move cursor back, overwrite the last character and move cursor back again to write next char properly
                continue;
            }
        }else
            ch = getchar();

        if(ch == '\n'){
            string[i] = '\0';
            break;
        }

        string[i] = ch;
    }
    printf("\n");
}

unsigned int validateInput(const char *input){
    if(strlen(input) < 8){
        printf("Password must contain atleast 8 characters.\n");
        return 0;
    }

    int lowercase = 0;
    int uppercase = 0; 
    int number = 0; 
    int specialcharacter = 0;

    for(size_t i = 0; i < strlen(input); i++){
        if((input[i] >= 97) && (input[i] <= 122))
            lowercase = 1;

        if((input[i] >= 65) && (input[i] <= 90))
            uppercase = 1;

        if((input[i] >= 48) && (input[i] <= 57))
            number = 1;

        if(((input[i] >= 33) && (input[i] <= 47)) || ((input[i] >= 58) && (input[i] <= 64)) || ((input[i] >= 91) && (input[i] <= 96)) || ((input[i] >= 123) && (input[i] <= 126)))
            specialcharacter = 1;
    }

    if(lowercase == 0 || uppercase == 0 || number == 0 || specialcharacter == 0){
        printf("Not a valid password.\nA password must contain at least one lowercase letter, uppercase letter, number and one specialcharacter.\nNote: Letters from an alphabet other than english are not processed by the program. Passwords containing letters from other alphabets may not be valid.\n");
        return 0;
    }

    return 1;
}

void generatePassword(char *string){
    unsigned int random = 0;
    for(int i = 0; i < 4; i++){
        random = (rand() % 25) + 65; //range: 65 - 90 (only capital letters for the beginning of the password)
        string[i] = random;
    }

    for(int i = 4; i < LEN; i++){
        while(1){
            random = (rand() % 93) + 33; //range: 33 - 126 (for the rest uppercase and lowercase letters as well as numbers and special characters)
            if(random != 34 && random != 39 && random != 96) break;
        }
        string[i] = random;
    }
    string[LEN-1] = '\0';
}

void enterPassword(char *string, const unsigned int status){
    if(status == 1)
        printf("Enter masterpassword: ");
    else printf("Enter password (leave blank if you want to generate a random password): ");
    
    while(1){
        input(string, 1);
        if(strlen(string) == 0 && status != 1){
            generatePassword(string);
            break;
        }
        int valid = validateInput(string);
        if(valid == 1)
            break;
    }
}

sqlite3* createDatabase(const char *dbName, char *key){
    sqlite3 *db;
    sqlite3_open(dbName, &db);

    char sql_pragmakey[256];
    snprintf(sql_pragmakey, sizeof(sql_pragmakey), "PRAGMA key = '%s';", key);
    sqlite3_exec(db, sql_pragmakey, NULL, NULL, NULL);

    const char *sqlCreateTable = "CREATE TABLE IF NOT EXISTS Services ("
                                 "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
                                 "Service TEXT NOT NULL,"
                                 "Password TEXT NOT NULL);";

    sqlite3_exec(db, sqlCreateTable, 0, 0, NULL);
    return db;
}

void prepareStatement(sqlite3 *db, const char *sqlMethod, int length, sqlite3_stmt **stmt, const char **pointerToBuffer){
    int rc = sqlite3_prepare_v2(db, sqlMethod, length, stmt, pointerToBuffer);
    if(rc != SQLITE_OK){
        fprintf(stderr, "Error while preparing statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
    }
}

void insertInto(sqlite3 *db, const char *service, const char *password){
    sqlite3_stmt *stmt; int rc;
    const char *sqlInsert = "INSERT INTO Services (Service, Password) VALUES (?, ?);";
    prepareStatement(db, sqlInsert, -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, service, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if(rc != SQLITE_DONE)
        fprintf(stderr, "Couldnt execute SQL-statement: %s\n", sqlite3_errmsg(db));

    sqlite3_finalize(stmt);
}

unsigned int checkifServiceExist(sqlite3 *db, const char *service){
    sqlite3_stmt *stmt; int rc;
    const char *sqlCheck = "SELECT Service FROM Services WHERE Service = ?;";
    prepareStatement(db, sqlCheck, -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, service, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if(rc == SQLITE_ROW){
        printf("A service with this name does already exist with a password in the database.\n");
        sqlite3_finalize(stmt);
        return 1;
    }
    sqlite3_finalize(stmt);
    return 0;
}

void deleteFrom(sqlite3 *db, unsigned int id){
    sqlite3_stmt *stmt; int rc;
    const char *sqlDelete = "DELETE FROM Services WHERE ID = ?;";
    prepareStatement(db, sqlDelete, -1, &stmt, 0);
    sqlite3_bind_int(stmt, 1, id);
    rc = sqlite3_step(stmt);
    if(rc != SQLITE_DONE)
        fprintf(stderr, "Couldnt execute SQL-statement: %s\n", sqlite3_errmsg(db));
    sqlite3_finalize(stmt);
}

unsigned int displayServices(sqlite3 *db){
    sqlite3_stmt *stmt; int rc = 0;
    const char *sqlSelectAllServices = "SELECT ID, Service FROM Services;";
    prepareStatement(db, sqlSelectAllServices, -1, &stmt, 0);
    rc = sqlite3_step(stmt);
    if(rc == SQLITE_ROW){
        while(rc == SQLITE_ROW){
            int id = sqlite3_column_int(stmt, 0);
            const unsigned char *service = sqlite3_column_text(stmt, 1);
            printf("%d. %s\n", id, service);
            rc = sqlite3_step(stmt);
        }
    }else{
        printf("No entries found in the database.\n");
        return 0;
    }

    sqlite3_finalize(stmt);
    return 1;
}

void selectFrom(sqlite3 *db, unsigned int id){
    sqlite3_stmt *stmt;
    const char *sqlSelect = "SELECT Password FROM Services WHERE ID = ?;";
    prepareStatement(db, sqlSelect, -1, &stmt, 0);
    sqlite3_bind_int(stmt, 1, id);
    int rc = sqlite3_step(stmt);
    if(rc == SQLITE_ROW){
        const char *password = sqlite3_column_text(stmt, 0);
        copyToClipboard(password);
        printf("Password copied successfully to clipboard.\n");
    }else
        fprintf(stderr, "Couldnt execute SQL-statement: %s\n", sqlite3_errmsg(db));
    sqlite3_finalize(stmt);
}

void updatePassword(sqlite3 *db, int id, const char *password){
    sqlite3_stmt *stmt;
    const char *sqlUpdate = "UPDATE Services SET Password = ? WHERE ID = ?;";
    prepareStatement(db, sqlUpdate, -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, password, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, id);
    int rc = sqlite3_step(stmt);
    if(rc != SQLITE_DONE)
        fprintf(stderr, "Couldnt execute SQL-statement: %s\n", sqlite3_errmsg(db));
    else
        printf("Password updated successfully.\n");
    sqlite3_finalize(stmt);
}

void copyPassword(sqlite3 *db){
    printf("Enter the numeric value of the service you would like to copy the password to clipboard.\n");
    int status = displayServices(db);
    if(status == 0)
        return;
    unsigned int service; printf("Service id: "); scanf("%d", &service);
    selectFrom(db, service);
}

void addService(sqlite3 *db){
    printf("Enter the name of the service you would like to add: ");
    char service[LEN]; input(service, 0);
    int status = checkifServiceExist(db, service);
    if(status == 1)
        return;

    char password[LEN];
    enterPassword(password, 0);
    insertInto(db, service, password);
}

void changePassword(sqlite3 *db){
    printf("Enter the numeric value of the service you would like to change the password.\n");
    int status = displayServices(db);
    if(status == 0)
        return;
    int service; printf("Service id: "); scanf("%d", &service);
    
    getchar(); //to skip backslash buffer
    char newPassword[LEN];
    enterPassword(newPassword, 0);
    updatePassword(db, service, newPassword);
}

void deleteService(sqlite3 *db){
    printf("Enter the numeric value of the service which you would like to delete.\n");
    int status = displayServices(db);
    if(status == 0)
        return; 
    unsigned int choice; printf("Service id: "); scanf("%d", &choice);
    deleteFrom(db, choice);
}

void changeMasterpassword(){
    char masterpassword[LEN];
    enterPassword(masterpassword, 1);

    char masterpassword_repeated[LEN];
    printf("Repeat the masterpassword: ");
    input(masterpassword_repeated, 1);

    if(strcmp(masterpassword, masterpassword_repeated) != 0){
        printf("Masterpasswords dont match.\n");
        return;
    }

    char hashedMasterpassword[65];
    sha256(masterpassword, hashedMasterpassword);
    writeIntoFile(hashedMasterpassword);
    printf("Masterpassword updated successfully.\n");
}

int main(){
    srand(time(NULL));
    char masterpassword[LEN];
    enterPassword(masterpassword, 1);
    char hashedMasterpassword[65];

    if(!file_exists("key.key")){
        char masterpassword_repeated[LEN];
        printf("Repeat the masterpassword: ");
        input(masterpassword_repeated, 1);

        if(strcmp(masterpassword, masterpassword_repeated) != 0){
            printf("Masterpasswords dont match.\n");
            return 0;
        }
        
        sha256(masterpassword, hashedMasterpassword);
        writeIntoFile(hashedMasterpassword);
        printf("The masterpassword was successfully stored in \"key.key\". Restart the programm to be able to further use the password manager.\n");
        return 0;
    }else{
        char hashedInput[65];
        sha256(masterpassword, hashedInput);
        FILE * keyfile = fopen("key.key", "r");
        
        fgets(hashedMasterpassword, 65, keyfile);
        if(strcmp(hashedInput, hashedMasterpassword) != 0){
            printf("Masterpasswords dont match.\n");
            return 0;
        }

        fclose(keyfile);
    }
    sqlite3 *db = createDatabase("database.db", hashedMasterpassword);

    while(1){
        printf("Choose an option:\n1. Copy password for a service\n2. Add new service\n3. Change password for a service\n4. Delete a service\n5. Change masterpassword\n6. Exit program\n");
        int choice = 0; printf("Choice: "); 

        if(scanf("%d", &choice) != 1){ //if its not int
            while(getchar() != '\n');  //reads all chars till new line and discards them
            printf("Only option 1-6 available.\n");
            continue;
        }

        getchar(); //to skip backslash buffer

        if(choice == 1){
            copyPassword(db);
        }else if(choice == 2){
            addService(db);
        }else if(choice == 3){
            changePassword(db);
        }else if(choice == 4){
            deleteService(db);
        }else if(choice == 5){
            changeMasterpassword();
        }else if(choice == 6){
            break;
        }else
            printf("Only option 1-6 available.\n");
    }

    sqlite3_close(db);
    copyToClipboard("");
}