/**
 * J E N N I F E R
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>

#define VERSION "1.0"
#define MAX_PASSWORD_LENGTH 256
#define DEFAULT_WORDLIST "src/wordlists.txt"
#define BUFFER_SIZE 4096
#define NUM_THREADS 4

#define KDBX3_SIG1 0x9AA2D903
#define KDBX3_SIG2 0xB54BFB67
#define KDBX4_SIG1 0x9AA2D903
#define KDBX4_SIG2 0xB54BFB67

typedef enum {
    KDBX_VERSION_UNKNOWN = 0,
    KDBX_VERSION_3 = 3,
    KDBX_VERSION_4 = 4
} kdbx_version;

typedef struct {
    kdbx_version version;
    uint8_t master_seed[32];
    uint8_t transform_seed[32];
    uint8_t encryption_iv[16];
    uint8_t protected_stream_key[32];
    uint8_t stream_start_bytes[32];
    uint32_t transform_rounds;
    uint32_t kdf_parameters[16];
    bool is_argon2;
} kdbx_header;

typedef struct {
    char *password;
    int result;
} password_result;

typedef struct {
    FILE *kdbx_file;
    FILE *wordlist_file;
    char **passwords;
    int start_idx;
    int end_idx;
    bool verbose;
    kdbx_header *header;
    password_result *result;
    pthread_mutex_t *result_mutex;
} crack_thread_args;

volatile sig_atomic_t running = 1;
volatile uint64_t attempts = 0;
volatile uint64_t total_passwords = 0;
time_t start_time;

bool parse_kdbx_header(FILE *file, kdbx_header *header);
bool attempt_password(FILE *file, const kdbx_header *header, const char *password);
void *crack_thread(void *arg);
void print_progress(uint64_t current, uint64_t total, time_t start_time, bool verbose, const char *current_password);
void handle_interrupt(int sig);
uint64_t count_lines(FILE *file);
bool is_file(const char *path);
void print_banner();
void print_usage(const char *program_name);

int main(int argc, char *argv[]) {
    signal(SIGINT, handle_interrupt);
    
    print_banner();
    
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    char *kdbx_path = argv[1];
    char *wordlist_path = NULL;
    bool verbose = false;
    
    if (argc >= 3) {
        if (strcmp(argv[2], "-v") == 0) {
            verbose = true;
        } else {
            wordlist_path = argv[2];
            if (argc >= 4 && strcmp(argv[3], "-v") == 0) {
                verbose = true;
            }
        }
    }
    
    if (!wordlist_path) {
        wordlist_path = DEFAULT_WORDLIST;
    }
    
    FILE *kdbx_file = fopen(kdbx_path, "rb");
    if (!kdbx_file) {
        fprintf(stderr, "[!] Error: Could not open KeePass database file: %s\n", kdbx_path);
        return 1;
    }
    
    FILE *wordlist_file = fopen(wordlist_path, "r");
    if (!wordlist_file) {
        fprintf(stderr, "[!] Error: Could not open wordlist file: %s\n", wordlist_path);
        fclose(kdbx_file);
        return 1;
    }
    
    kdbx_header header;
    if (!parse_kdbx_header(kdbx_file, &header)) {
        fprintf(stderr, "[!] Error: Failed to parse KeePass database header\n");
        fclose(kdbx_file);
        fclose(wordlist_file);
        return 1;
    }
    
    printf("[+] KeePass database detected (version %d)\n", header.version);
    if (header.version == KDBX_VERSION_4) {
        printf("[+] Using %s key derivation\n", header.is_argon2 ? "Argon2" : "AES-KDF");
    }
    
    total_passwords = count_lines(wordlist_file);
    rewind(wordlist_file);
    
    printf("[+] Starting password cracking with %lu passwords\n", total_passwords);
    start_time = time(NULL);
    
    char **passwords = (char **)malloc(total_passwords * sizeof(char *));
    if (!passwords) {
        fprintf(stderr, "[!] Error: Memory allocation failed\n");
        fclose(kdbx_file);
        fclose(wordlist_file);
        return 1;
    }
    
    char line[MAX_PASSWORD_LENGTH];
    for (uint64_t i = 0; i < total_passwords; i++) {
        if (fgets(line, MAX_PASSWORD_LENGTH, wordlist_file)) {
            size_t len = strlen(line);
            if (len > 0 && line[len-1] == '\n') {
                line[len-1] = '\0';
            }
            
            passwords[i] = strdup(line);
        }
    }
    
    pthread_t threads[NUM_THREADS];
    crack_thread_args thread_args[NUM_THREADS];
    password_result result = {NULL, 0};
    pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
    
    uint64_t chunk_size = total_passwords / NUM_THREADS;
    
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_args[i].kdbx_file = kdbx_file;
        thread_args[i].wordlist_file = wordlist_file;
        thread_args[i].passwords = passwords;
        thread_args[i].start_idx = i * chunk_size;
        thread_args[i].end_idx = (i == NUM_THREADS - 1) ? total_passwords : (i + 1) * chunk_size;
        thread_args[i].verbose = verbose;
        thread_args[i].header = &header;
        thread_args[i].result = &result;
        thread_args[i].result_mutex = &result_mutex;
        
        pthread_create(&threads[i], NULL, crack_thread, &thread_args[i]);
    }
    
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    if (result.password) {
        printf("\n[+] Password found: %s\n", result.password);
        free(result.password);
    } else {
        printf("\n[!] Wordlist exhausted, no match found\n");
    }
    
    for (uint64_t i = 0; i < total_passwords; i++) {
        free(passwords[i]);
    }
    free(passwords);
    fclose(kdbx_file);
    fclose(wordlist_file);
    
    return result.password ? 0 : 1;
}

void *crack_thread(void *arg) {
    crack_thread_args *args = (crack_thread_args *)arg;
    FILE *kdbx_file_thread = fopen(args->kdbx_file == stdin ? "/dev/stdin" : "/proc/self/fd/0", "rb");
    
    for (int i = args->start_idx; i < args->end_idx && running; i++) {
        const char *password = args->passwords[i];
        
        pthread_mutex_lock(args->result_mutex);
        attempts++;
        
        if (args->verbose) {
            print_progress(attempts, total_passwords, start_time, true, password);
        } else if (attempts % 100 == 0) {
            print_progress(attempts, total_passwords, start_time, false, NULL);
        }
        
        if (args->result->result) {
            pthread_mutex_unlock(args->result_mutex);
            break;
        }
        pthread_mutex_unlock(args->result_mutex);
        
        if (attempt_password(kdbx_file_thread, args->header, password)) {
            pthread_mutex_lock(args->result_mutex);
            if (!args->result->result) {
                args->result->password = strdup(password);
                args->result->result = 1;
                running = 0;
            }
            pthread_mutex_unlock(args->result_mutex);
            break;
        }
    }
    
    fclose(kdbx_file_thread);
    return NULL;
}

bool parse_kdbx_header(FILE *file, kdbx_header *header) {
    uint32_t sig1, sig2, version;
    
    fread(&sig1, sizeof(sig1), 1, file);
    fread(&sig2, sizeof(sig2), 1, file);
    fread(&version, sizeof(version), 1, file);
    
    if ((sig1 == KDBX3_SIG1 && sig2 == KDBX3_SIG2) || 
        (sig1 == KDBX4_SIG1 && sig2 == KDBX4_SIG2)) {
        
        if ((version & 0xFFFF0000) == 0x00030000) {
            header->version = KDBX_VERSION_3;
        } else if ((version & 0xFFFF0000) == 0x00040000) {
            header->version = KDBX_VERSION_4;
        } else {
            header->version = KDBX_VERSION_UNKNOWN;
        }
        
        if (header->version == KDBX_VERSION_3) {
            fseek(file, 12, SEEK_SET);  
            
            uint8_t field_id;
            uint16_t field_size;
            
            while (1) {
                fread(&field_id, 1, 1, file);
                if (field_id == 0) break;  
                
                fread(&field_size, 2, 1, file);
                
                switch (field_id) {
                    case 4:  
                        fread(header->master_seed, 1, field_size, file);
                        break;
                    case 5:  
                        fread(header->transform_seed, 1, field_size, file);
                        break;
                    case 6:  
                        fread(&header->transform_rounds, 1, field_size, file);
                        break;
                    case 7:  
                        fread(header->encryption_iv, 1, field_size, file);
                        break;
                    case 8:  
                        fread(header->protected_stream_key, 1, field_size, file);
                        break;
                    case 9:  
                        fread(header->stream_start_bytes, 1, field_size, file);
                        break;
                    default:
                        fseek(file, field_size, SEEK_CUR);
                        break;
                }
            }
            
            header->is_argon2 = false;
            
        } else if (header->version == KDBX_VERSION_4) {
            fseek(file, 12, SEEK_SET);
            
            uint8_t field_id;
            uint32_t field_size;
            
            while (1) {
                fread(&field_id, 1, 1, file);
                if (field_id == 0) break;
                
                fread(&field_size, 4, 1, file);
                
                switch (field_id) {
                    case 4:  
                        fread(header->master_seed, 1, field_size, file);
                        break;
                    case 7:  
                        fread(header->encryption_iv, 1, field_size, file);
                        break;
                    case 11: 
                        uint8_t kdf_uuid[16];
                        long pos = ftell(file);
                        fread(kdf_uuid, 1, 16, file);
                        
                        header->is_argon2 = (kdf_uuid[0] == 0xEF && kdf_uuid[1] == 0x63);
                        
                        fseek(file, pos, SEEK_SET);
                        fseek(file, field_size, SEEK_CUR);
                        break;
                    default:
                        fseek(file, field_size, SEEK_CUR);
                        break;
                }
            }
        }
        
        rewind(file);
        return true;
    }
    
    return false;
}

bool attempt_password(FILE *file, const kdbx_header *header, const char *password) {
    char cmd[1024];
    sprintf(cmd, "echo \"%s\" | keepassxc-cli open -q %s > /dev/null 2>&1", 
            password, "/proc/self/fd/0");
    
    int result = system(cmd);
    return (result == 0);
}

void print_progress(uint64_t current, uint64_t total, time_t start_time, bool verbose, const char *current_password) {
    time_t current_time = time(NULL);
    int elapsed_time = (int)difftime(current_time, start_time);
    
    if (elapsed_time <= 0) elapsed_time = 1;
    
    int attempts_per_second = current / elapsed_time;
    uint64_t remaining_attempts = total - current;
    int estimated_time_remaining = attempts_per_second > 0 ? remaining_attempts / attempts_per_second : 0;
    
    int eta_days = estimated_time_remaining / 86400;
    int eta_hours = (estimated_time_remaining % 86400) / 3600;
    int eta_minutes = (estimated_time_remaining % 3600) / 60;
    int eta_seconds = estimated_time_remaining % 60;
    
    char eta_str[100];
    if (eta_days > 0) {
        sprintf(eta_str, "%dd %dh %dm %ds", eta_days, eta_hours, eta_minutes, eta_seconds);
    } else if (eta_hours > 0) {
        sprintf(eta_str, "%dh %dm %ds", eta_hours, eta_minutes, eta_seconds);
    } else if (eta_minutes > 0) {
        sprintf(eta_str, "%dm %ds", eta_minutes, eta_seconds);
    } else {
        sprintf(eta_str, "%ds", eta_seconds);
    }
    
    printf("\r[+] Progress: %lu/%lu (%.2f%%) - %d p/s - ETA: %s", 
           current, total, (float)current / total * 100, 
           attempts_per_second, eta_str);
    
    if (verbose && current_password) {
        printf(" - Current: %s", current_password);
    }
    
    fflush(stdout);
}

void handle_interrupt(int sig) {
    printf("\n[!] Interrupted by user\n");
    running = 0;
}

uint64_t count_lines(FILE *file) {
    uint64_t count = 0;
    char buffer[BUFFER_SIZE];
    
    while (fgets(buffer, BUFFER_SIZE, file)) {
        count++;
    }
    
    return count;
}

bool is_file(const char *path) {
    struct stat path_stat;
    if (stat(path, &path_stat) != 0) {
        return false;
    }
    return S_ISREG(path_stat.st_mode);
}

void print_banner() {
    printf("\n");
    printf("                               ⠀⣀⣀⣀⣀⣀⣀⡀⢰⠆⠂⠄⡀⠀⠀⠀⠀⠀⠀\n");
    printf("⠁⠀⠀⠀⠀⠀⠈⢀⢠⠴⠒⢿⣉⣦⣱⡇⣧⢼⣯⣿⠲⣥⣀⡀⠁⠠⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⡀⢎⠰⣈⣵⣾⣿⣿⣿⣿⣿⣿⣿⣷⣿⣷⣯⡴⢆⡤⠀⡄⠀⠀\n");
    printf("⠀⠀⠀⠀⡀⢆⠱⣨⣶⠿⣿⠟⠋⣿⣿⣿⣿⣿⣿⣯⠛⠿⣿⣿⣷⣒⣩⠄⠀⠀\n");
    printf("⠀⠀⠐⠊⡴⢬⡾⠛⠁⠀⣿⣷⣼⣿⣿⣿⣿⣿⣿⣿⠀⠀⢈⠛⣻⡶⠶⠗⠂⠀\n");
    printf("⠀⠀⠐⢀⣴⠛⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⡠⢀⣴⡿⠉⠡⠀⠀⠀\n");
    printf("⠀⠈⠀⠺⠕⠒⠂⠀⡀⠀⠀⠈⠙⠛⠻⠛⡛⠋⠀⠀⣠⣶⣿⠿⡣⠐⠀⠀⠀⠀\n");
    printf("⠃⢀⠀⠀⠀⠀⠀⠀⠐⠀⠠⢠⡴⢦⣤⣄⣶⡶⣾⢿⠛⠟⠂⠓⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠈⠐⠀⠄⢀⠀⠀⠀⠒⠁⠊⠉⡇⢛⠾⠑⠁⠉⠀⠀⠠⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀\n");
    printf("⠀⠀⠐⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂\n");
    printf("\nJennifer - KeePass Password Cracker v%s\n", VERSION);
    printf("Current User: %s | %s UTC\n\n", "byt3n33dl3", "2025-08-19 13:22:23");
}

void print_usage(const char *program_name) {
    printf("Usage:\n");
    printf("  %s <kdbx-file>                 (uses default wordlist)\n", program_name);
    printf("  %s <kdbx-file> <wordlist>      (uses specified wordlist)\n", program_name);
    printf("  %s <kdbx-file> <wordlist> -v   (with verbose output)\n", program_name);
    printf("\n");
}