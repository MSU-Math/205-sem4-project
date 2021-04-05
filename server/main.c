#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>

static struct {
    int server_fd;
    int is_in_process;
    int is_terminating;
} STATE = {0};

void sigint_handler(int signal)
{
    STATE.is_terminating = 1;
    if (!STATE.is_in_process && STATE.server_fd != -1) {
        write(0, "closing\n", 8);
        close(STATE.server_fd);
    }
    write(0, "terminating\n", 12);
}

int main(void)
{
    int error;
    struct addrinfo *result;

    char *last;
    size_t last_size;
    FILE *last_file = open_memstream(&last, &last_size);

    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE,
        .ai_protocol = IPPROTO_TCP,
    };

    error = getaddrinfo(NULL, "10000", &hints, &result);
    if (error) {
        printf("Error: %s", gai_strerror(error));
        return 1;
    }

    STATE.server_fd = -1;

    struct sigaction sa;

    sa.sa_handler = sigint_handler;
    sa.sa_flags = 0; // or SA_RESTART
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    struct addrinfo *current = result;
    while (current) {
        for (int i = 0; i < 14; i++) {
            printf("%x ", (unsigned char)current->ai_addr->sa_data[i]);
        }
        printf("\n");

        STATE.server_fd = socket(current->ai_family, current->ai_socktype, current->ai_protocol);
        
        if (STATE.server_fd == -1) {
            current = result->ai_next;
            continue;
        }

        int reuseaddr = 1;
        int err = setsockopt(STATE.server_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));

        if (!bind(STATE.server_fd, result->ai_addr, result->ai_addrlen)) {
            break;
        } else {
            perror("Unable to listen/bind");
        }

        close(STATE.server_fd);
        current = result->ai_next;
    }

    if (STATE.server_fd == -1) {
        perror("Unable to listen");
        return EXIT_FAILURE;
    }

    freeaddrinfo(result);

    if (listen(STATE.server_fd, 4)) {
        perror("Unable to listen");
        return EXIT_FAILURE;
    }

    printf("Socket: %d\n", STATE.server_fd);
    while (!STATE.is_terminating) {
        struct sockaddr client_address;
        socklen_t length;
        int client = accept(STATE.server_fd, &client_address, &length);
        STATE.is_in_process = 1;

        if (STATE.is_terminating) {
            break;
        } else if (client == -1) {
            perror("Unable to connect");
            sleep(1);
            continue;
        }

        printf("Connected: ");
        for (int i = 0; i < length; i++) {
            printf("%x ", client_address.sa_data[i]);
        }
        printf("\n");

        FILE *f = fdopen(client, "r+");

        char method[8] = {0};
        char path[PATH_MAX+1] = {0};
        int result = fscanf(f, "%7[A-Z] %4096[^ ] HTTP", method, path);
        if (result == 2) {
            printf("Client asks to %s path: %s\n", method, path);
            fputs(path, last_file);
            fputs("<br/>", last_file);
            fflush(last_file);
            const char *response = "HTTP/1.1 200 OK\n"
                "Content-Type: text/html; charset=UTF-8\n"
                "\n"
                "Hello, world!\nТест\n<a href=\"test\">test</a>\n\n<h1>Last paths:</h1><br/><pre>\n\n<";
            send(client, response, strlen(response), 0);
            send(client, last, last_size, 0);
            send(client, "</pre>", strlen("</pre>"), 0);
            if (last_size > 1 * 1024 * 1024) {
                printf("Resetting buffer\n");
                fclose(last_file);
                free(last);
                last = NULL;
                last_size = 0;
                last_file = open_memstream(&last, &last_size);
            }
        } else {
            printf("Fscanf read %d patterns\n", result);
        }
        close(client);
        STATE.is_in_process = 0;
    }

    close(STATE.server_fd);

    return EXIT_SUCCESS;
}