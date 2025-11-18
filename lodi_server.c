#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

#define BUFFER_SIZE 1024
#define MAX_TIMESTAMP_DIFF 30  // 30 seconds tolerance for timestamp

void DieWithError(char *errorMessage);


// toLodiServ (received messages) 
typedef struct {
    enum {login, ackRegisterKey, responsePublicKey, responseAuth
    } messageType;
    unsigned int userID;               
    unsigned int recipientID;          
    unsigned long timestamp;           
    unsigned long digitalSig;          
    unsigned int publicKey;            
    
} toLodiServer;

// To Lodi Client
typedef struct {
    enum {ackLogin} messageType;
    unsigned int userID;
} LodiServerToLodiClient;

// To PKE Server 
typedef struct {
    enum {requestKey} messageType;
    unsigned int userID;             
    unsigned int publicKey;            
} LodiServerToPKEServer;

// To TFA Server (request authentication)
typedef struct {
    enum {requestAuth} messageType;
    unsigned int userID;               
} LodiServerToTFAServer;

// RSA 
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

// Request public Key from PKE
unsigned int requestPublicKey(int sock, char *pkeServerIP, unsigned short pkeServerPort, 
                              unsigned int userID, unsigned long n) {
    struct sockaddr_in pkeServerAddr;
    LodiServerToPKEServer request;
    toLodiServer response;  
    int recvMsgSize; 
    
    printf("\n(LodiServer) Requesting public key for user %u from PKE Server...\n", userID);
    
    // Prepare request message
    request.messageType = requestKey;
    request.userID = userID;
    request.publicKey = 0; 
    
    // Configure PKE server address
    memset(&pkeServerAddr, 0, sizeof(pkeServerAddr));
    pkeServerAddr.sin_family = AF_INET;
    pkeServerAddr.sin_addr.s_addr = inet_addr(pkeServerIP);
    pkeServerAddr.sin_port = htons(pkeServerPort);
    
    // Send request to PKE Server
    if (sendto(sock, &request, sizeof(request), 0,
               (struct sockaddr *)&pkeServerAddr, sizeof(pkeServerAddr)) != sizeof(request)) {
        printf("(LodiServer) Error: Failed to send request to PKE Server\n");
        return 0;
    }
    
    printf("(LodiServer) Request sent to PKE Server at %s:%u\n", pkeServerIP, pkeServerPort);
    
    // Receive response from PKE Server
    struct sockaddr_in fromAddr;
    unsigned int fromSize = sizeof(fromAddr);
    
    if ((recvMsgSize = recvfrom(sock, &response, sizeof(response), 0,
                                (struct sockaddr *)&fromAddr, &fromSize)) < 0) {
        printf("(LodiServer) Error: Failed to receive response from PKE Server\n");
        return 0;
    }
    
    printf("(LodiServer) Received response from %s:%u\n", 
           inet_ntoa(fromAddr.sin_addr), ntohs(fromAddr.sin_port));
    

    if (response.messageType == responsePublicKey && response.userID == userID) {
        printf("(LodiServer) Public key received: %u\n", response.publicKey);
        printf("(LodiServer) Verifying digital signature...\n");
        return response.publicKey;
    }
    
    printf("(LodiServer) Error: Invalid response from PKE Server\n");
    return 0;
}

// Function to request TFA Authentication
int requestTFAAuthentication(int sock, char *tfaServerIP, unsigned short tfaServerPort,
                             unsigned int userID) {
    struct sockaddr_in tfaServerAddr;
    LodiServerToTFAServer request;
    toLodiServer response; 
    int recvMsgSize;
    
    printf("\n(LodiServer) Requesting authentication for user %u from TFA Server...\n", userID);
    
    // Prepare request message
    request.messageType = requestAuth;
    request.userID = userID;
    
    // Configure TFA server address
    memset(&tfaServerAddr, 0, sizeof(tfaServerAddr));
    tfaServerAddr.sin_family = AF_INET;
    tfaServerAddr.sin_addr.s_addr = inet_addr(tfaServerIP);
    tfaServerAddr.sin_port = htons(tfaServerPort);
    
    // Send request to TFA Server
    if (sendto(sock, &request, sizeof(request), 0,
               (struct sockaddr *)&tfaServerAddr, sizeof(tfaServerAddr)) != sizeof(request)) {
        printf("(LodiServer) Error: Failed to send request to TFA Server\n");
        return 0;
    }
    
    printf("(LodiServer) Request sent to TFA Server at %s:%u\n", tfaServerIP, tfaServerPort);
    printf("(LodiServer) Waiting for user to approve on TFA client...\n");
    
    // Receive response from TFA Server
    struct sockaddr_in fromAddr;
    unsigned int fromSize = sizeof(fromAddr);
    
    if ((recvMsgSize = recvfrom(sock, &response, sizeof(response), 0,
                                (struct sockaddr *)&fromAddr, &fromSize)) < 0) {
        printf("(LodiServer) Error: Failed to receive response from TFA Server\n");
        return 0;
    }
    
    printf("(LodiServer) Received response from %s:%u\n",
           inet_ntoa(fromAddr.sin_addr), ntohs(fromAddr.sin_port));
    
    if (response.messageType == responseAuth && response.userID == userID) {
        printf("(LodiServer) Authentication successful for user %u\n", userID);
        return 1;
    }
    
    printf("(LodiServer) Error: Authentication failed for user %u\n", userID);
    return 0;
}

// Main
int main(int argc, char *argv[]) {
    int sock;
    struct sockaddr_in lodiServerAddr;
    struct sockaddr_in clientAddr;
    unsigned int clientAddrLen;
    unsigned short lodiServerPort;
    char *pkeServerIP;
    unsigned short pkeServerPort;
    char *tfaServerIP;
    unsigned short tfaServerPort;
    toLodiServer incomingMsg;  
    int recvMsgSize;
    unsigned long n = 533;  

    if (argc != 6) {
        fprintf(stderr, "Usage: %s <Lodi Port> <PKE IP> <PKE Port> <TFA IP> <TFA Port>\n", argv[0]);
        exit(1);
    }
    
    lodiServerPort = atoi(argv[1]);
    pkeServerIP = argv[2];
    pkeServerPort = atoi(argv[3]);
    tfaServerIP = argv[4];
    tfaServerPort = atoi(argv[5]);
    
    printf("(LodiServer) Lodi Server: \n");
    printf("(LodiServer) Listening on port: %u\n", lodiServerPort);
    printf("(LodiServer) PKE Server: %s:%u\n", pkeServerIP, pkeServerPort);
    printf("(LodiServer) TFA Server: %s:%u\n", tfaServerIP, tfaServerPort);
    printf("(LodiServer) RSA Modulus (n): %lu\n", n);
    printf("\n\n");
    
    // Socket creation
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("(LodiServer) socket() failed");

    printf("(LodiServer) Socket created successfully\n");

    // Configure server address
    memset(&lodiServerAddr, 0, sizeof(lodiServerAddr));
    lodiServerAddr.sin_family = AF_INET;
    lodiServerAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    lodiServerAddr.sin_port = htons(lodiServerPort);

    printf("(LodiServer) Address structure configured\n");

    // Bind
    if (bind(sock, (struct sockaddr *)&lodiServerAddr, sizeof(lodiServerAddr)) < 0)
        DieWithError("(LodiServer) bind() failed");

    printf("(LodiServer) Socket bound to port %u\n", lodiServerPort);
    printf("(LodiServer) Lodi Server ready and listening...\n\n");

    // loop
    for (;;) {
        clientAddrLen = sizeof(clientAddr);
        
        printf("(LodiServer) Waiting for login message...\n");
        
        // Receiving message
        if ((recvMsgSize = recvfrom(sock, &incomingMsg, sizeof(incomingMsg), 0,
                                    (struct sockaddr *)&clientAddr,
                                    &clientAddrLen)) < 0)
            DieWithError("(LodiServer) recvfrom() failed");
        
        printf("(LodiServer) Received %d bytes from %s:%d\n",
               recvMsgSize,
               inet_ntoa(clientAddr.sin_addr),
               ntohs(clientAddr.sin_port));
        
        // Verify it's a login message
        if (incomingMsg.messageType != login) {
            printf("(LodiServer) Error: Received non-login message (type=%d)\n", 
                   incomingMsg.messageType);
            continue;
        }
        
        printf("(LodiServer) Login request from User ID: %u\n", incomingMsg.userID);
        printf("(LodiServer) Timestamp: %lu\n", incomingMsg.timestamp);
        printf("(LodiServer) Digital Signature: %lu\n", incomingMsg.digitalSig);
        
        // verify timestamp 
        unsigned long currentTime = time(NULL);
        long timeDiff = (long)(currentTime - incomingMsg.timestamp);
        
        printf("\n(LodiServer) Step 1: Verifying timestamp...\n");
        printf("(LodiServer) Current time: %lu\n", currentTime);
        printf("(LodiServer) Time difference: %ld seconds\n", timeDiff);
        
        if (abs(timeDiff) > MAX_TIMESTAMP_DIFF) {
            printf("(LodiServer) FAILED: Timestamp too old or invalid\n");
            printf("[Auth] Rejecting login from user %u\n\n", incomingMsg.userID);
            continue;
        }
        printf("(LodiServer) SUCCESS: Timestamp is valid\n");
        
        // Verify using PKE Server
        printf("\n(LodiServer) Step 2: Verifying digital signature...\n");
        
        unsigned int publicKey = requestPublicKey(sock, pkeServerIP, pkeServerPort, 
                                                  incomingMsg.userID, n);
        
        if (publicKey == 0) {
            printf("(LodiServer) FAILED: Could not retrieve public key\n");
            printf("(LodiServer) Rejecting login from user %u\n\n", incomingMsg.userID);
            continue;
        }
        
        // Verify the digital signature: Dec(DS) should equal timestamp
        unsigned long decryptedTimestamp = modExp(incomingMsg.digitalSig, publicKey, n);
        
        printf("(LodiServer) Decrypted timestamp: %lu\n", decryptedTimestamp);
        printf("(LodiServer) Original timestamp:  %lu\n", incomingMsg.timestamp);
        
        if (decryptedTimestamp != incomingMsg.timestamp) {
            printf("(LodiServer)FAILED: Digital signature verification failed\n");
            printf("(LodiServer) Signature does not match timestamp\n");
            printf("(LodiServer) Rejecting login from user %u\n\n", incomingMsg.userID);
            continue;
        }
        printf("(LodiServer) SUCCESS: Digital signature verified\n");
        
        // Request TFA Auth
        printf("\n(LodiServer) Step 3: Requesting TFA authentication...\n");
        
        if (!requestTFAAuthentication(sock, tfaServerIP, tfaServerPort, incomingMsg.userID)) {
            printf("(LodiServer) FAILED: TFA authentication failed\n");
            printf("(LodiServer) Rejecting login from user %u\n\n", incomingMsg.userID);
            continue;
        }
        printf("(LodiServer) SUCCESS: TFA authentication completed\n");
        printf("\n(LodiServer) All authentication steps passed!\n");
        printf("(LodiServer) Sending ackLogin to client...\n");
        
        LodiServerToLodiClient ackMsg;
        ackMsg.messageType = ackLogin;
        ackMsg.userID = incomingMsg.userID;
        
        // Ack Client
        if (sendto(sock, &ackMsg, sizeof(ackMsg), 0,
                   (struct sockaddr *)&clientAddr, sizeof(clientAddr)) != sizeof(ackMsg)) {
            printf("(LodiServer) Error: Failed to send ackLogin\n");
        } else {
            printf("(LodiServer) ackLogin sent to %s:%d\n",
                   inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
            printf("(LodiServer) User %u successfully authenticated!\n", incomingMsg.userID);
        }
        
        
    }
    
    close(sock);
    return 0;
}
