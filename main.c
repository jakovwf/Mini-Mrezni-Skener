#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

typedef struct {
    char ip[64];
} ip_task;

/* ================= CHECK NMAP ================= */
void check_and_install_nmap() {
    // Proveri da li nmap postoji u PATH-u
    if (system("which nmap > /dev/null 2>&1") != 0) {
        printf("❌ nmap nije pronađen u PATH-u.\n");
        
        // Prvo proveri da li je možda u /snap/bin/
        if (system("ls /snap/bin/nmap > /dev/null 2>&1") == 0) {
            printf("ℹ️ nmap je instaliran putem snap-a. Dodajem u PATH...\n");
            
            // Dodaj /snap/bin u PATH za ovu sesiju
            char *path = getenv("PATH");
            char new_path[1024];
            snprintf(new_path, sizeof(new_path), "/snap/bin:%s", path);
            setenv("PATH", new_path, 1);
            
            if (system("nmap --version > /dev/null 2>&1") == 0) {
                printf("✅ nmap je sada dostupan (putem snap-a).\n");
                return;
            }
        }
        
        printf("➡ Instaliram nmap putem apt-a...\n");
        
        // Instalacija sa --fix-missing i -y opcijama
        int ret = system("sudo apt update && sudo apt install --fix-missing -y nmap");
        if (ret != 0) {
            printf("❌ Greška pri instalaciji nmap-a. Pokušavam alternativnu metodu...\n");
            
            // Pokušaj sa snap-om ako apt ne radi
            printf("➡ Pokušavam instalaciju putem snap-a...\n");
            ret = system("sudo snap install nmap");
            if (ret != 0 || system("which nmap > /dev/null 2>&1") != 0) {
                printf("❌ nmap instalacija potpuno neuspešna.\n");
                printf("ℹ️ Pokušajte ručno: sudo apt install --fix-missing nmap\n");
                exit(1);
            }
        }
        
        // Finalna provera
        if (system("nmap --version > /dev/null 2>&1") != 0) {
            printf("❌ nmap i dalje nije dostupan nakon instalacije.\n");
            printf("ℹ️ Proverite da li je /usr/bin/ ili /snap/bin/ u vašem PATH-u.\n");
            exit(1);
        }
        
        printf("✅ nmap uspešno instaliran.\n");
    } else {
        printf("✅ nmap je već instaliran i dostupan.\n");
    }
}

/* ================= PARSER ================= */
void *parse_nmap(void *arg) {
    ip_task *task = (ip_task *)arg;

    char in[128], out[128];
    snprintf(in, sizeof(in), "%s.txt", task->ip);
    snprintf(out, sizeof(out), "%sFINAL.txt", task->ip);

    FILE *fi = fopen(in, "r");
    FILE *fo = fopen(out, "w");
    if (!fi || !fo) {
        free(task);
        return NULL;
    }

    fprintf(fo, "IP: %s\n", task->ip);

    char line[512];
    while (fgets(line, sizeof(line), fi)) {
        if (strstr(line, "/tcp") && strstr(line, "open"))
            fputs(line, fo);
        if (strstr(line, "MAC Address"))
            fputs(line, fo);
        if (strstr(line, "Aggressive OS guesses"))
            fputs(line, fo);
    }

    fclose(fi);
    fclose(fo);
    free(task);
    return NULL;
}

/* ================= SCAN ================= */
void *scan_ips(void *arg) {
    FILE *fp = fopen("ips.txt", "r");
    if (!fp) return NULL;

    char ip[64], cmd[512];

    while (fgets(ip, sizeof(ip), fp)) {
        ip[strcspn(ip, "\n")] = 0;

        printf("[SCAN] Pokrećem nmap za: %s\n", ip);
        snprintf(cmd, sizeof(cmd),
                 "sudo nmap -A %s -oN %s.txt",
                 ip, ip);
        
        int ret = system(cmd);
        if (ret != 0) {
            printf("[WARN] Nmap skeniranje za %s možda nije uspelo\n", ip);
        }

        pthread_t t;
        ip_task *task = malloc(sizeof(ip_task));
        if (task == NULL) {
            printf("[ERROR] Nema dovoljno memorije za task\n");
            continue;
        }
        strcpy(task->ip, ip);

        pthread_create(&t, NULL, parse_nmap, task);
        pthread_join(t, NULL);
    }

    fclose(fp);
    return NULL;
}

/* ================= MERGE ================= */
void merge_final_files() {
    FILE *ips = fopen("ips.txt", "r");
    if (!ips) {
        printf("[ERROR] Ne mogu otvoriti ips.txt\n");
        return;
    }
    
    FILE *final = fopen("FINAL.txt", "w");
    if (!final) {
        printf("[ERROR] Ne mogu kreirati FINAL.txt\n");
        fclose(ips);
        return;
    }

    char ip[64], line[512], f[128];

    while (fgets(ip, sizeof(ip), ips)) {
        ip[strcspn(ip, "\n")] = 0;
        snprintf(f, sizeof(f), "%sFINAL.txt", ip);

        FILE *in = fopen(f, "r");
        if (!in) {
            printf("[WARN] Ne mogu otvoriti %s\n", f);
            continue;
        }

        fprintf(final, "===== %s =====\n", ip);
        while (fgets(line, sizeof(line), in))
            fputs(line, final);
        fprintf(final, "\n");

        fclose(in);
    }

    fclose(ips);
    fclose(final);
}

/* ================= MAIN ================= */
int main() {
    printf("=== Pokrećem nmap skener ===\n");
    
    check_and_install_nmap();
    
    // Dodatna provera
    printf("\nℹ️ Provera nmap verzije: ");
    fflush(stdout);
    system("nmap --version 2>&1 | head -1");

    // Skeniranje mreže
    printf("\n🔍 Skeniram mrežu 192.168.8.0/24 za aktivne hostove...\n");
    FILE *fp = popen("nmap -sn 192.168.8.0/24", "r");
    FILE *out = fopen("ips.txt", "w");
    if (!fp || !out) {
        printf("[ERROR] Ne mogu pokrenuti nmap ili otvoriti ips.txt\n");
        return 1;
    }

    char line[512], ip[64];
    int host_count = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "Nmap scan report for")) {
            if (sscanf(line, "Nmap scan report for %63s", ip) == 1) {
                // Ukloni zagrade ako postoje
                if (ip[0] == '(') {
                    // Ako je u formatu (192.168.8.1), izvuci samo IP
                    char *start = strchr(ip, '(');
                    char *end = strchr(ip, ')');
                    if (start && end) {
                        strncpy(ip, start + 1, end - start - 1);
                        ip[end - start - 1] = '\0';
                    }
                }
                fprintf(out, "%s\n", ip);
                host_count++;
                printf("  Nađen host: %s\n", ip);
            }
        }
    }

    fclose(out);
    pclose(fp);

    printf("\n✅ Nađeno %d hostova. Pokrećem detaljno skeniranje...\n", host_count);
    
    if (host_count == 0) {
        printf("[WARN] Nema hostova za skeniranje. Proverite mrežu.\n");
        return 0;
    }

    pthread_t scanner;
    pthread_create(&scanner, NULL, scan_ips, NULL);
    pthread_join(scanner, NULL);

    merge_final_files();

    printf("\n✅ Skeniranje završeno!\n");
    printf("📁 Rezultati su u FINAL.txt\n");
    printf("📁 Pojedinačni fajlovi su: [ip].txt i [ip]FINAL.txt\n");
    
    return 0;
}