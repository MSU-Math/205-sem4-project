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

struct request {
    int authorization_size;
    char *authorization;
    char *method;
    char *path;
};

int return_401(int client);
int return_200(int client, const struct request *request);
int parse_request(ssize_t size, const char buffer[size], struct request *request);
#define REQUEST_SIZE 4096

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
    char *buffer = malloc(REQUEST_SIZE * sizeof(char));
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

        ssize_t size = read(client, buffer, REQUEST_SIZE * sizeof(char));
        struct request request;
        parse_request(size, buffer, &request);
        if (!request.authorization) {
            return_401(client);
        } else {
            return_200(client, &request);
            free(request.authorization);
        }
        fclose(f);
        close(client);
        STATE.is_in_process = 0;
    }

    free(buffer);
    close(STATE.server_fd);

    return EXIT_SUCCESS;
}

int return_401(int client)
{
    const char *response = "HTTP/1.1 401  Unauthorized\r\n"
        "WWW-Authenticate: Basic realm=\"Access to the staging site\", charset=\"UTF-8\"\r\n\r\n";
    return send(client, response, strlen(response), 0) > 0;
}

#define AUTH_SIZE 256
#define REQUEST_END 1
int parse_request(ssize_t size, const char buffer[size], struct request *request)
{
    int offset = 0;
    while (offset < size) {
        while (buffer[offset] != '\n') {
            offset += 1;
        }
        offset += 1;
        if (!strncmp("Authorization: ", buffer+offset, sizeof("Authorization: "))) {
            offset += sizeof("Authorization: ");
            while (buffer[offset] == ' ') {
                offset += 1;
            }
            request->authorization = &buffer[offset];
        }
    }
    while ((c = fgetc(stream)) > 0) {
        if (c != '\n') {
            fputc(c, stdout);
            continue;
        }
        fputc('\n', stdout);
        // ищем: \nAuthorization: 
        if (!request->authorization && fscanf(stream, "Authorization: %256s", authorization) == 1) {
            // сохраняем то, что идёт дальшe, пропустив все пробелы
            request->authorization = authorization;
        }
    }
    return 0;
}

int return_200(int client, const struct request *request)
{
    const char *response = "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain, encoding=utf-8\r\n"
        "\r\n"
        "Hello, ";
    int status = 0;
    status |= send(client, response, strlen(response), 0) > 0;
    status |= send(client, request->authorization, strlen(request->authorization), 0) > 0;
    return status;
}