#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
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

#define METHOD_LENGTH 8

struct request {
    int authorization_size;
    char *authorization;
    char method[METHOD_LENGTH];
    char *path;
    int content_length;
};

struct message {
    char *username;
    char *text;
    struct timeval time;
};

struct message_list {
    struct message *messages;
    int size;
    int capacity;
};

#define BLOCK 8
// Добавить сообщение к списку
int message_list_add(struct message_list *list, char *username, char *text)
{
    if (list->capacity <= list->size) {
        struct message *expanded = realloc(list->messages, (list->capacity + BLOCK) * sizeof(struct message));
        if (expanded) {
            list->messages = expanded;
        } else {
            return 1;
        }
    }

    struct message *new_message = &list->messages[list->size];
    new_message->username = username;
    new_message->text = text;
    list->size += 1;
    gettimeofday(&new_message->time, NULL);
}

int return_401(FILE *output);
int return_200(FILE *output, const struct request *request, const struct message_list *messages);
int add_message(FILE *input, const struct request *request, struct message_list *messages);
int parse_request(FILE *input, struct request *request);
#define REQUEST_SIZE 4096

#define xstr(s) str(s)
#define str(s) #s

void sigint_handler(int signal)
{
    (void)signal;
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
    struct message_list messages = { 0 };

    message_list_add(&messages, "admin", "server started");

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
        error = setsockopt(STATE.server_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));

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

        struct request request = {0};
        
        FILE *input = fdopen(client, "r");
        parse_request(input, &request);
        
        FILE *output = fdopen(client, "w");
        if (!request.authorization) {
            return_401(output);
        } else {
            if (!strcmp("POST", &request.method)) {
                add_message(input, &request, &messages);
            }
            return_200(output, &request, &messages);
            free(request.authorization);
        }
        fclose(output);
        fclose(input);
        
        close(client);
        STATE.is_in_process = 0;
    }

    close(STATE.server_fd);

    return EXIT_SUCCESS;
}

int return_401(FILE *output)
{
    const char *response = "HTTP/1.1 401  Unauthorized\r\n"
        "WWW-Authenticate: Basic realm=\"Access to the staging site\", charset=\"UTF-8\"\r\n\r\n";
    return fputs(response, output) > 0;
}

#define AUTH_SIZE 256
#define REQUEST_END 1
int parse_request(FILE *input, struct request *request)
{
    request->authorization = NULL;

    // считываем метод HTTP-запроса
    fscanf(input, "%8[^ ]", &request->method);
    // пропускаем символы до конца строки
    while (fgetc(input) > '\n') { }

    char *line = NULL;
    size_t size = 0;
    while (getline(&line, &size, input) > 0 && line[0] > ' ') {
        if (!strncmp(line, "Authorization: ", sizeof("Authorization: ") - 1)) {
            request->authorization = line;
            line = NULL;
            size = 0;
        } else {
            if (sscanf(line, "Content-Length: %d", &request->content_length) == 1) {
                // printf("Read Content-Length: %d\n", request->content_length);
            }
        }
        // printf("Header: %s\n", line);
    }
    return 0;
}

int return_200(FILE *output, const struct request *request, const struct message_list *messages)
{
    const char *response = "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain, encoding=utf-8\r\n"
        "\r\n"
        "Hello, ";
     
    int status = fputs(response, output) > 0;
    status |= fputs(request->authorization, output) > 0;
    status |= fputs("\n", output) > 0;

    for (int i = 0; i < messages->size; i++)
    {
        const struct message *message = &messages->messages[i];
        fprintf(output, "%ld: %s: %s\n", message->time.tv_sec, message->username, message->text);
    }
    return status;
}

int add_message(FILE *input, const struct request *request, struct message_list *messages)
{
    char *text = malloc(request->content_length + 1);
    memset(text, 0, request->content_length + 1);
    fread(text, request->content_length, 1, input);
    
    // домашнее задание про base64-декодирование подключать здесь:
    char *username = strdup(request->authorization);
    return message_list_add(messages, username, text);
}
