#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/stat.h>
#ifdef _WIN32
    #include <direct.h>
    #define MKDIR(path) _mkdir(path)
    #define CLEAR_CMD "cls"
#else
    #include <dirent.h>
    #define MKDIR(path) mkdir(path, 0700)
    #define CLEAR_CMD "clear"
#endif

#define DATA_DIR "locker_data"
#define MASTER_FILE "locker_master.txt"
#define LOG_FILE "locker_access.log"
#define NAME_LEN 100
#define MAX_LINE 512

typedef struct {
    char filename[NAME_LEN];
    long size;
    char timestamp[32];
} FileMetadata;

static char master_password[128];
static uint32_t master_salt = 0;
static uint32_t master_hash = 0;

static void pause_enter(void) {
    printf("\nPress Enter to continue...");
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
    getchar();
}

static void read_line(const char *prompt, char *buffer, size_t size) {
    printf("%s", prompt);
    if (!fgets(buffer, (int)size, stdin)) {
        buffer[0] = '\0';
        return;
    }
    buffer[strcspn(buffer, "\r\n")] = '\0';
}

static int valid_filename(const char *name) {
    size_t n = strlen(name);
    if (n == 0 || n >= NAME_LEN || name[0] == '.') return 0;
    for (size_t i = 0; i < n; i++) {
        if (!(isalnum((unsigned char)name[i]) || name[i] == '_' ||
              name[i] == '-' || name[i] == '.')) return 0;
    }
    return 1;
}

static void make_path(char *out, size_t size, const char *name) {
#ifdef _WIN32
    snprintf(out, size, "%s\\%s.lock", DATA_DIR, name);
#else
    snprintf(out, size, "%s/%s.lock", DATA_DIR, name);
#endif
}

/* A salted custom checksum for the classroom project, not a secure password hash. */
static uint32_t password_checksum(const char *password, uint32_t salt) {
    uint32_t h = 2166136261u ^ salt;
    while (*password) {
        h ^= (unsigned char)*password++;
        h *= 16777619u;
        h ^= h >> 13;
    }
    h ^= salt + 0x9e3779b9u;
    return h;
}

/* Simple password-derived XOR stream: reversible, but NOT real encryption. */
static void xor_crypt(unsigned char *data, size_t len, const char *password,
                      uint32_t salt) {
    uint32_t state = password_checksum(password, salt) ^ 0xA5C39E17u;
    for (size_t i = 0; i < len; i++) {
        state = state * 1664525u + 1013904223u;
        unsigned char key_byte = (unsigned char)(state >> 24);
        data[i] ^= key_byte;
    }
}

static void log_event(const char *event, const char *detail) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (!fp) return;
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char stamp[32] = "unknown-time";
    if (tm_info) strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(fp, "[%s] %-18s %s\n", stamp, event, detail ? detail : "");
    fclose(fp);
}

static int save_master(const char *password, uint32_t salt) {
    FILE *fp = fopen(MASTER_FILE, "w");
    if (!fp) {
        perror("Could not save master password file");
        return 0;
    }
    fprintf(fp, "%u %u\n", salt, password_checksum(password, salt));
    fclose(fp);
    master_salt = salt;
    master_hash = password_checksum(password, salt);
    return 1;
}

static int load_master(void) {
    FILE *fp = fopen(MASTER_FILE, "r");
    if (!fp) return 0;
    int ok = fscanf(fp, "%u %u", &master_salt, &master_hash) == 2;
    fclose(fp);
    return ok;
}

static int verify_password(const char *password) {
    return password_checksum(password, master_salt) == master_hash;
}

static int file_exists(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;
    fclose(fp);
    return 1;
}

static unsigned char *read_all_bytes(const char *path, size_t *length) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    long size = ftell(fp);
    if (size < 0 || fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return NULL; }
    unsigned char *data = (unsigned char *)malloc((size_t)size + 1);
    if (!data) { fclose(fp); return NULL; }
    size_t got = fread(data, 1, (size_t)size, fp);
    fclose(fp);
    if (got != (size_t)size) { free(data); return NULL; }
    data[got] = '\0';
    *length = got;
    return data;
}

static int write_all_bytes(const char *path, const unsigned char *data, size_t len) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return 0;
    int ok = fwrite(data, 1, len, fp) == len;
    if (fclose(fp) != 0) ok = 0;
    return ok;
}

static int read_encrypted_file(const char *name, unsigned char **data,
                               size_t *len, uint32_t *salt_out) {
    char path[256];
    make_path(path, sizeof(path), name);
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;
    uint32_t salt;
    if (fread(&salt, sizeof(salt), 1, fp) != 1) { fclose(fp); return 0; }
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return 0; }
    long total = ftell(fp);
    if (total < (long)sizeof(salt) || fseek(fp, (long)sizeof(salt), SEEK_SET) != 0) {
        fclose(fp); return 0;
    }
    size_t n = (size_t)(total - (long)sizeof(salt));
    unsigned char *buf = (unsigned char *)malloc(n + 1);
    if (!buf) { fclose(fp); return 0; }
    if (fread(buf, 1, n, fp) != n) { free(buf); fclose(fp); return 0; }
    fclose(fp);
    buf[n] = '\0';
    xor_crypt(buf, n, master_password, salt);
    *data = buf;
    *len = n;
    if (salt_out) *salt_out = salt;
    return 1;
}

static int save_encrypted_file(const char *name, const unsigned char *plain,
                               size_t len, const char *password) {
    char path[256];
    make_path(path, sizeof(path), name);
    unsigned char *copy = (unsigned char *)malloc(len + 1);
    if (!copy) return 0;
    memcpy(copy, plain, len);
    uint32_t salt = (uint32_t)time(NULL) ^ (uint32_t)rand();
    xor_crypt(copy, len, password, salt);
    FILE *fp = fopen(path, "wb");
    if (!fp) { free(copy); return 0; }
    int ok = fwrite(&salt, sizeof(salt), 1, fp) == 1 &&
             fwrite(copy, 1, len, fp) == len;
    if (fclose(fp) != 0) ok = 0;
    free(copy);
    return ok;
}

static void setup_master(void) {
    char p1[128], p2[128];
    printf("Welcome! This appears to be your first run.\n");
    do {
        read_line("Create a master password (at least 6 characters): ", p1, sizeof(p1));
        if (strlen(p1) < 6) printf("Please use at least 6 characters.\n");
    } while (strlen(p1) < 6);
    read_line("Confirm master password: ", p2, sizeof(p2));
    if (strcmp(p1, p2) != 0) {
        printf("Passwords did not match. Please restart and try again.\n");
        exit(1);
    }
    uint32_t salt = (uint32_t)time(NULL) ^ (uint32_t)rand() ^ 0x73A2B19Du;
    if (!save_master(p1, salt)) exit(1);
    strncpy(master_password, p1, sizeof(master_password) - 1);
    master_password[sizeof(master_password) - 1] = '\0';
    log_event("SETUP", "Master password created");
    printf("Master password created.\n");
}

static int authenticate(void) {
    char entered[128];
    for (int tries = 0; tries < 3; tries++) {
        read_line("Enter master password: ", entered, sizeof(entered));
        if (verify_password(entered)) {
            strncpy(master_password, entered, sizeof(master_password) - 1);
            master_password[sizeof(master_password) - 1] = '\0';
            log_event("LOGIN_SUCCESS", "Password accepted");
            return 1;
        }
        log_event("LOGIN_FAILED", "Incorrect password");
        printf("Incorrect password. Attempts remaining: %d\n", 2 - tries);
    }
    return 0;
}

static void create_or_write_file(void) {
    char name[NAME_LEN], path[256], text[MAX_LINE];
    read_line("Filename (letters, digits, . _ - only; no folders): ", name, sizeof(name));
    if (!valid_filename(name)) { printf("Invalid filename.\n"); return; }
    make_path(path, sizeof(path), name);
    int exists = file_exists(path);
    printf("%s\n", exists ? "This file exists; its contents will be replaced." :
                            "Creating a new file.");
    printf("Enter text. Finish by entering a single line containing END.\n");
    size_t cap = 1024, len = 0;
    char *content = (char *)malloc(cap);
    if (!content) { printf("Out of memory.\n"); return; }
    content[0] = '\0';
    while (1) {
        if (!fgets(text, sizeof(text), stdin)) break;
        if (strcmp(text, "END\n") == 0 || strcmp(text, "END") == 0) break;
        size_t add = strlen(text);
        if (len + add + 1 > cap) {
            size_t newcap = cap * 2;
            while (newcap < len + add + 1) newcap *= 2;
            char *temp = (char *)realloc(content, newcap);
            if (!temp) { free(content); printf("Out of memory.\n"); return; }
            content = temp; cap = newcap;
        }
        memcpy(content + len, text, add);
        len += add;
        content[len] = '\0';
    }
    if (save_encrypted_file(name, (unsigned char *)content, len, master_password)) {
        printf("File saved in encrypted form.\n");
        log_event(exists ? "WRITE_FILE" : "CREATE_FILE", name);
    } else {
        printf("Could not save file.\n");
    }
    free(content);
}

static void read_file_menu(void) {
    char name[NAME_LEN];
    read_line("Filename to read: ", name, sizeof(name));
    if (!valid_filename(name)) { printf("Invalid filename.\n"); return; }
    unsigned char *data = NULL;
    size_t len = 0;
    if (!read_encrypted_file(name, &data, &len, NULL)) {
        printf("File not found or could not be opened.\n");
        log_event("READ_FAILED", name);
        return;
    }
    printf("\n----- %s -----\n", name);
    if (len) fwrite(data, 1, len, stdout);
    if (!len || data[len - 1] != '\n') putchar('\n');
    printf("----- end -----\n");
    log_event("READ_FILE", name);
    free(data);
}

static void delete_file_menu(void) {
    char name[NAME_LEN], path[256], confirm[16];
    read_line("Filename to delete: ", name, sizeof(name));
    if (!valid_filename(name)) { printf("Invalid filename.\n"); return; }
    make_path(path, sizeof(path), name);
    if (!file_exists(path)) { printf("File not found.\n"); return; }
    read_line("Type YES to confirm deletion: ", confirm, sizeof(confirm));
    if (strcmp(confirm, "YES") != 0) { printf("Deletion cancelled.\n"); return; }
    if (remove(path) == 0) {
        printf("File deleted.\n");
        log_event("DELETE_FILE", name);
    } else printf("Could not delete file.\n");
}

static void list_files(void) {
    printf("\nFiles in your locker:\n");
#ifdef _WIN32
    /* Portable fallback: scan numbered names is not available without WinAPI.
       Users can still use the known filenames. */
    printf("(On Windows, use the filenames you created; stored files end in .lock.)\n");
#else
    DIR *dir = opendir(DATA_DIR);
    if (!dir) { printf("(No files yet.)\n"); return; }
    struct dirent *entry;
    int count = 0;
    while ((entry = readdir(dir)) != NULL) {
        size_t n = strlen(entry->d_name);
        if (n > 5 && strcmp(entry->d_name + n - 5, ".lock") == 0) {
            entry->d_name[n - 5] = '\0';
            printf(" - %s\n", entry->d_name);
            count++;
        }
    }
    if (!count) printf("(No files yet.)\n");
    closedir(dir);
#endif
    log_event("LIST_FILES", "Listed locker files");
}

static void show_metadata(void) {
    char name[NAME_LEN];
    read_line("Filename for metadata: ", name, sizeof(name));
    if (!valid_filename(name)) { printf("Invalid filename.\n"); return; }
    unsigned char *data = NULL;
    size_t len = 0;
    if (!read_encrypted_file(name, &data, &len, NULL)) {
        printf("File not found.\n"); return;
    }
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char stamp[32] = "unknown";
    if (tm_info) strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", tm_info);
    FileMetadata meta;
    snprintf(meta.filename, sizeof(meta.filename), "%s", name);
    meta.size = (long)len;
    snprintf(meta.timestamp, sizeof(meta.timestamp), "%s (checked)", stamp);
    printf("Filename: %s\nPlaintext size: %ld bytes\nTimestamp: %s\n",
           meta.filename, meta.size, meta.timestamp);
    free(data);
    log_event("METADATA", name);
}

static int reencrypt_all_files(const char *old_password, const char *new_password) {
    /* Rename files are not changed. Each file contains its own salt before ciphertext. */
#ifdef _WIN32
    printf("Password change on Windows requires manual re-encryption in this demo.\n");
    (void)old_password; (void)new_password;
    return 0;
#else
    DIR *dir = opendir(DATA_DIR);
    if (!dir) return 1;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        size_t n = strlen(entry->d_name);
        if (n <= 5 || strcmp(entry->d_name + n - 5, ".lock") != 0) continue;
        char name[NAME_LEN];
        size_t base_len = n - 5;
        if (base_len >= sizeof(name)) continue;
        memcpy(name, entry->d_name, base_len); name[base_len] = '\0';
        char path[256];
        make_path(path, sizeof(path), name);
        FILE *fp = fopen(path, "rb");
        if (!fp) { closedir(dir); return 0; }
        uint32_t salt;
        if (fread(&salt, sizeof(salt), 1, fp) != 1) { fclose(fp); closedir(dir); return 0; }
        if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); closedir(dir); return 0; }
        long total = ftell(fp);
        if (total < (long)sizeof(salt)) { fclose(fp); closedir(dir); return 0; }
        size_t len = (size_t)(total - (long)sizeof(salt));
        if (fseek(fp, (long)sizeof(salt), SEEK_SET) != 0) { fclose(fp); closedir(dir); return 0; }
        unsigned char *buf = (unsigned char *)malloc(len + 1);
        if (!buf) { fclose(fp); closedir(dir); return 0; }
        int ok = fread(buf, 1, len, fp) == len;
        fclose(fp);
        if (!ok) { free(buf); closedir(dir); return 0; }
        xor_crypt(buf, len, old_password, salt);
        xor_crypt(buf, len, new_password, salt);
        fp = fopen(path, "wb");
        if (!fp) { free(buf); closedir(dir); return 0; }
        ok = fwrite(&salt, sizeof(salt), 1, fp) == 1 && fwrite(buf, 1, len, fp) == len;
        if (fclose(fp) != 0) ok = 0;
        free(buf);
        if (!ok) { closedir(dir); return 0; }
    }
    closedir(dir);
    return 1;
#endif
}

static void change_password(void) {
    char oldp[128], newp[128], confirm[128];
    read_line("Current password: ", oldp, sizeof(oldp));
    if (!verify_password(oldp)) { printf("Incorrect password.\n"); log_event("PASSWORD_CHANGE_FAILED", "Wrong current password"); return; }
    read_line("New password (at least 6 characters): ", newp, sizeof(newp));
    if (strlen(newp) < 6) { printf("Password must be at least 6 characters.\n"); return; }
    read_line("Confirm new password: ", confirm, sizeof(confirm));
    if (strcmp(newp, confirm) != 0) { printf("Passwords do not match.\n"); return; }
    if (!reencrypt_all_files(oldp, newp)) {
        printf("Could not re-encrypt all files; password was not changed.\n");
        return;
    }
    uint32_t salt = (uint32_t)time(NULL) ^ (uint32_t)rand() ^ 0xD1B54A35u;
    if (!save_master(newp, salt)) { printf("Could not save new password.\n"); return; }
    strncpy(master_password, newp, sizeof(master_password) - 1);
    master_password[sizeof(master_password) - 1] = '\0';
    printf("Master password changed.\n");
    log_event("PASSWORD_CHANGED", "Master password updated");
}

static void view_logs(void) {
    FILE *fp = fopen(LOG_FILE, "r");
    if (!fp) { printf("No access log yet.\n"); return; }
    char line[256];
    printf("\n--- Access log ---\n");
    while (fgets(line, sizeof(line), fp)) fputs(line, stdout);
    printf("--- End log ---\n");
    fclose(fp);
}

int main(void) {
    srand((unsigned int)time(NULL));
    if (MKDIR(DATA_DIR) != 0) {
        /* The directory may already exist; this is expected on later runs. */
    }
    if (!load_master()) setup_master();
    else if (!authenticate()) {
        printf("Too many failed attempts. Exiting.\n");
        return 1;
    }

    int choice;
    do {
        printf("\n========== SECURE FILE LOCKER ==========\n");
        printf("1. Create / write a text file\n");
        printf("2. Read a text file\n");
        printf("3. List files\n");
        printf("4. Delete a file\n");
        printf("5. Show file metadata\n");
        printf("6. View access log\n");
        printf("7. Change master password\n");
        printf("0. Exit\n");
        printf("Choose an option: ");
        if (scanf("%d", &choice) != 1) {
            int c; while ((c = getchar()) != '\n' && c != EOF) {}
            choice = -1;
        } else {
            int c; while ((c = getchar()) != '\n' && c != EOF) {}
        }

        switch (choice) {
            case 1: create_or_write_file(); break;
            case 2: read_file_menu(); break;
            case 3: list_files(); break;
            case 4: delete_file_menu(); break;
            case 5: show_metadata(); break;
            case 6: view_logs(); break;
            case 7: change_password(); break;
            case 0: log_event("LOGOUT", "Application closed"); printf("Goodbye!\n"); break;
            default: printf("Please enter a valid menu option.\n");
        }
    } while (choice != 0);
    return 0;
}
