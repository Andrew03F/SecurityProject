#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8080
#define AES_KEY_SIZE 128

void handle_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

int main() {
    struct sockaddr_in address;
    int sock = 0;
    char *hello = "Hello from client";
    char buffer[1024] = {0};

    SSL_CTX *ctx;
    SSL *ssl;

    // Initialize the SSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_client_method());

    // Create a new SSL structure for a connection
    ssl = SSL_new(ctx);

    // Creating socket file descriptor
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    memset(&address, '0', sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&address, sizeof(address)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    // Set up SSL connection
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        handle_error();
    }

    // Send message to the server
    SSL_write(ssl, hello, strlen(hello));
    printf("Hello message sent\n");

    // Receive response from the server
    int valread;
    if ((valread = SSL_read(ssl, buffer, 1024)) < 0) {
        handle_error();
    }
    printf("%s\n", buffer);

    // Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    return 0;
}
