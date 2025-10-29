#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

/* Error handling function */
void DieWithError(char *errorMessage) {
    perror(errorMessage);
    exit(1);
}

int main(int argc, char *argv[]) {
    int sock;
    struct sockaddr_in serverAddr;
    unsigned int serverPort;
    
    // Check command line arguments
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <Server Port>\n", argv[0]);
        exit(1);
    }
    
    serverPort = atoi(argv[1]);
    printf("PKE Server starting on port %u...\n", serverPort);
    
    // Create socket for incoming datagrams
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("socket() failed");
    
    printf("Socket created successfully!\n");
    
    // Construct local address structure
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port = htons(serverPort);
    
    printf("Address structure configured!\n");
    
    // Bind to the local address
    if (bind(sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
        DieWithError("bind() failed");
    
    printf("Socket bound to port %u!\n", serverPort);
    printf("PKE Server ready and listening...\n");
    
    // Run forever - keep the port bound!
    for (;;) {
        // For now, just sleep
        // Later we'll add code to receive messages here
        sleep(1);
    }
    //need to add receiving functionality
    // NOT REACHED
    close(sock);
    return 0;
}