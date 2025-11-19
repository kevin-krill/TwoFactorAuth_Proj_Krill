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

/* NOTE: removed duplicate TCP/extended message typedefs —
   the simple `PClientToLodiServer` and `LodiServerToLodiClientAcks`
   defined above are used for the login exchange. */

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

char *getUserAction() {
    static char action[10];
    printf("Enter action (register/login): ");
    scanf("%s", action);
    return action;
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
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ServerIP> <UserID> \n", argv[0]);
        exit(1);
    }
    
    pkeServerIP = argv[1];
    userID = atoi(argv[2]);
    pkeServerPort = 2924;
    lodiServerIP = argv[1];
    lodiServerPort = 2926;
    char *action = getUserAction(); // Function to get user action: "register" or "login"

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
        
        /* Create a separate TCP socket for the login */
        int tcpSock;
        if ((tcpSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
            DieWithError("(LodiCLient) TCP socket() failed");

        if (connect(tcpSock, (struct sockaddr *)&lodiServerAddr, sizeof(lodiServerAddr)) < 0) {
            close(tcpSock);
            DieWithError("(LodiCLient) connect() failed");
        }

        /* Send the login struct over TCP (ensure all bytes are sent) */
        unsigned int loginMsgLen = sizeof(loginMsg);
        unsigned int sent = 0;
        while (sent < loginMsgLen) {
            int s = send(tcpSock, ((char *)&loginMsg) + sent, loginMsgLen - sent, 0);
            if (s <= 0) {
                close(tcpSock);
                DieWithError("(LodiCLient) send() failed");
            }
            sent += s;
        }

        printf("(LodiCLient) Login message sent to Lodi Server\n");
        printf("(LodiCLient) Waiting for response from Lodi Server...\n");

        /* Set a receive timeout on TCP socket */
        struct timeval tv = {10, 0};
        setsockopt(tcpSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        /* Receive exactly the ACK struct size into buffer (handle partial reads)
           Note: buffer is large enough. */
        unsigned int expected = sizeof(LodiServerToLodiClientAcks);
        unsigned int totalBytesRcvd = 0;
        while (totalBytesRcvd < expected) {
            int r = recv(tcpSock, buffer + totalBytesRcvd, (int)(expected - totalBytesRcvd), 0);
            if (r < 0) {
                close(tcpSock);
                DieWithError("(LodiCLient) recv() failed");
            }
            if (r == 0) break; /* connection closed */
            totalBytesRcvd += r;
        }

        if (totalBytesRcvd < expected) {
            close(tcpSock);
            DieWithError("(LodiCLient) Incomplete response from Lodi Server");
        }

        LodiServerToLodiClientAcks *lodiResponse = (LodiServerToLodiClientAcks *)buffer;
        if (lodiResponse->messageType == ackLogin) {
            printf("(LodiCLient) Login successful\n");
            printf("(LodiCLient) Confirmed User ID: %u\n\n", lodiResponse->userID);
        } else {
            close(tcpSock);
            DieWithError("(LodiCLient) ERROR: Unexpected response from Lodi Server");
        }

        close(tcpSock);
    }else{
        DieWithError("Use <register|login>");
    }
     
    
    
    
    close(sock);
    return 0;
}