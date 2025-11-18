#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

#define BUFFER_SIZE 1024

void DieWithError(char *errorMessage)
{
	perror(errorMessage);
	exit(1);
}

// Messages to PKE Server
typedef struct {
    enum {registerKey, requestKey} messageType;
    unsigned int userID;
    unsigned int publicKey;
} PClientToPKServer;

// Messages from PKE Server
typedef struct {
    enum {ackRegisterKey, responsePublicKey} messageType;
    unsigned int userID;
    unsigned int publicKey;
} PKServerToPClientOrLodiServer;

// Messages to Lodi Server
typedef struct {
    enum {login} messageType;
    unsigned int userID;
    unsigned int recipientID;
    unsigned long timestamp;
    unsigned long digitalSig;
} PClientToLodiServer;

// Messages from Lodi Server
typedef struct {
    enum {ackLogin} messageType;
    unsigned int userID;
} LodiServerToLodiClientAcks;

// RSA
// Modular exponentiation: (base^exp) mod n
unsigned long modExp(unsigned long base, unsigned long exp, unsigned long n) {
    unsigned long result = 1;
    base = base % n;
    
    while (exp > 0) {
        if (exp % 2 == 1)
            result = (result * base) % n;
        exp = exp >> 1;
        base = (base * base) % n;
    }
    
    return result;
}

// Create digital signature
unsigned long createDigitalSignature(unsigned long timestamp, unsigned long privateKey, unsigned long n) {
    return modExp(timestamp, privateKey, n);
}

int main(int argc, char *argv[]) {
    int sock;
    struct sockaddr_in pkeServerAddr;
    struct sockaddr_in lodiServerAddr;
    struct sockaddr_in fromAddr;
    unsigned int fromSize;
    char *pkeServerIP;
    unsigned short pkeServerPort;
    char *lodiServerIP;
    unsigned short lodiServerPort;
    char buffer[BUFFER_SIZE];
    int respLen;
    unsigned int userID;
    
    // RSA keys
    unsigned long n = 533;       
    unsigned long e = 13;        
    unsigned long d = 37;        
    unsigned int publicKey = e;
    
    // Check command line arguments
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <ServerIP> <UserID> <register|login>\n", argv[0]);
        exit(1);
    }
    
    pkeServerIP = argv[1];
    userID = atoi(argv[2]);
    pkeServerPort = 2924;
    lodiServerIP = argv[1];
    lodiServerPort = 2926;
    char *action = argv[3];

    printf("(LodiCLient) Lodi Client\n");
    printf("(LodiCLient) User ID: %u\n", userID);
    printf("(LodiCLient) RSA Public Key (e): %lu\n", e);
    printf("(LodiCLient) RSA Private Key (d): %lu\n", d);
    printf("(LodiCLient) RSA Modulus (n): %lu\n\n", n);

    // Create socket
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("(LodiCLient) socket() failed");

    // Register public key w PKE server
    if (strcmp(action, "register") == 0) {
        
    printf("(LodiCLient) Registering public key with PKE Server\n");
    printf("(LodiCLient) Connecting to PKE Server at %s:%u\n", pkeServerIP, pkeServerPort);
    
    // Construct PKE server address
    memset(&pkeServerAddr, 0, sizeof(pkeServerAddr));
    pkeServerAddr.sin_family = AF_INET;
    pkeServerAddr.sin_addr.s_addr = inet_addr(pkeServerIP);
    pkeServerAddr.sin_port = htons(pkeServerPort);
    
    // Create registerKey message
    PClientToPKServer registerMsg;
    registerMsg.messageType = registerKey;
    registerMsg.userID = userID;
    registerMsg.publicKey = publicKey;
    
    printf("(LodiCLient) Sending registerKey message\n");
    printf("(LodiCLient) User ID: %u\n", registerMsg.userID);
    printf("(LodiCLient) Public Key: %u\n", registerMsg.publicKey);
    
    // Send to PKE Server
    if (sendto(sock, &registerMsg, sizeof(registerMsg), 0,
               (struct sockaddr *)&pkeServerAddr, sizeof(pkeServerAddr)) != sizeof(registerMsg))
        DieWithError("(LodiCLient) sendto() failed");
    
    printf("(LodiCLient) Waiting for acknowledgment from PKE Server...\n");
    
    // Receive response
    fromSize = sizeof(fromAddr);
    if ((respLen = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                            (struct sockaddr *)&fromAddr, &fromSize)) < 0)
        DieWithError("(LodiCLient) recvfrom() failed");
    
    PKServerToPClientOrLodiServer *pkeResponse = (PKServerToPClientOrLodiServer *)buffer;
    
    if (pkeResponse->messageType == ackRegisterKey) {
        printf("(LodiCLient) Public key registered successfully\n");
        printf("(LodiCLient) Confirmed User ID: %u\n", pkeResponse->userID);
        printf("(LodiCLient) Confirmed Public Key: %u\n\n", pkeResponse->publicKey);
    } else {
        printf("(LodiCLient) ERROR: Unexpected response from PKE Server\n");
        exit(1);
    }

    // Send Login to Lodi Server
    }
    else if (strcmp(action, "login") == 0) {
        
        printf("(LodiCLient) Logging in to Lodi Server\n");
        printf("(LodiCLient) Connecting to Lodi Server at %s:%u\n", lodiServerIP, lodiServerPort);
        
        // Construct Lodi server address
        memset(&lodiServerAddr, 0, sizeof(lodiServerAddr));
        lodiServerAddr.sin_family = AF_INET;
        lodiServerAddr.sin_addr.s_addr = inet_addr(lodiServerIP);
        lodiServerAddr.sin_port = htons(lodiServerPort);
        
        // Get current timestamp
        unsigned long timestamp = (unsigned long)time(NULL) % 500;
        
        // Create digital signature
        unsigned long digitalSig = createDigitalSignature(timestamp, d, n);
        
        // Create login message
        PClientToLodiServer loginMsg;
        loginMsg.messageType = login;
        loginMsg.userID = userID;
        loginMsg.recipientID = 0; 
        loginMsg.timestamp = timestamp;
        loginMsg.digitalSig = digitalSig;
        
        printf("(LodiCLient) Sending login message\n");
        printf("(LodiCLient) User ID: %u\n", loginMsg.userID);
        printf("(LodiCLient) Timestamp: %lu\n", loginMsg.timestamp);
        printf("(LodiCLient) Digital Signature: %lu\n", loginMsg.digitalSig);
        
        // Send to Lodi Server
        if (sendto(sock, &loginMsg, sizeof(loginMsg), 0,
                (struct sockaddr *)&lodiServerAddr, sizeof(lodiServerAddr)) != sizeof(loginMsg))
            DieWithError("sendto() failed");
        
        printf("(LodiCLient) Waiting for response from Lodi Server...\n");
        
        // Receive response:
        // Check to make sure Client is not waiting forever
        struct timeval tv = {10, 0}; 
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        fromSize = sizeof(fromAddr);
        if ((respLen = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                                (struct sockaddr *)&fromAddr, &fromSize)) < 0)
            DieWithError("(LodiCLient) Login Failed");
        
        LodiServerToLodiClientAcks *lodiResponse = (LodiServerToLodiClientAcks *)buffer;
        
        if (lodiResponse->messageType == ackLogin) {
            printf("(LodiCLient) Login successful\n");
            printf("(LodiCLient) Confirmed User ID: %u\n\n", lodiResponse->userID);
        } else {
            printf("(LodiCLient) ERROR: Unexpected response from Lodi Server\n");
            exit(1);
        }
    }else{
        DieWithError("Use <register|login>");
    }
     
    
    
    
    close(sock);
    return 0;
}