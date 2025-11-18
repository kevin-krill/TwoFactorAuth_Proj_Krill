#include <stdio.h>      
#include <sys/socket.h> 
#include <arpa/inet.h>  
#include <stdlib.h>     
#include <string.h>     
#include <unistd.h>     
#include <sys/time.h>

#define MAX_USERS 100   

void DieWithError(char *errorMessage)
{
	perror(errorMessage);
	exit(1);
}

// Message Structs
typedef struct {
    enum {registerTFA, ackRegTFA, ackPushTFA, denyPushTFA, requestAuth} messageType;
    unsigned int userID;
    unsigned long timestamp;
    unsigned long digitalSig;
} TFAClientOrLodiServerToTFAServer;

typedef struct {
    enum {confirmTFA, pushTFA} messageType;
    unsigned int userID;
} TFAServerToTFAClient;

typedef struct {
    enum {responseAuth, responseAuthFail} messageType;
    unsigned int userID;
} TFAServerToLodiServer;

typedef struct {
    enum {registerKey, requestKey} messageType;
    unsigned int userID;
    unsigned int publicKey;
} TFAServerToPKEServer;

typedef struct {
    enum {ackRegisterKey, responsePublicKey} messageType;
    unsigned int userID;
    unsigned int publicKey;
} PKEServerToTFAServer;

// User Registration Table
typedef struct {
    unsigned int userID;
    struct sockaddr_in clientAddr;
    int registered;
} UserEntry;

/* Global user table */
UserEntry userTable[MAX_USERS];
int userCount = 0;

// RSA
unsigned long modExp(unsigned long base, unsigned long exp, unsigned long n)
{
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

// Find user from Table
int findUser(unsigned int userID)
{
    int i;
    for (i = 0; i < userCount; i++) {
        if (userTable[i].userID == userID && userTable[i].registered)
            return i;
    }
    return -1;
}

// Add user to table
int addUser(unsigned int userID, struct sockaddr_in *clientAddr)
{
    if (userCount >= MAX_USERS)
        return -1;
    
    userTable[userCount].userID = userID;
    userTable[userCount].clientAddr = *clientAddr;
    userTable[userCount].registered = 1;
    userCount++;
    
    return userCount - 1;
}

// Request public key from TFA Server
unsigned int requestPublicKey(int sock, char *pkeServerIP, unsigned short pkeServerPort,
                               unsigned int userID, unsigned long n)
{
    struct sockaddr_in pkeServerAddr;
    TFAServerToPKEServer request;
    PKEServerToTFAServer response;
    unsigned int fromSize;
    int recvMsgSize;
    
    printf("(TFAServer) Requesting public key for user %u from PKE Server\n", userID);
    
    request.messageType = requestKey;
    request.userID = userID;
    request.publicKey = 0;
    
    // Configure PKE Server address
    memset(&pkeServerAddr, 0, sizeof(pkeServerAddr));
    pkeServerAddr.sin_family = AF_INET;
    pkeServerAddr.sin_addr.s_addr = inet_addr(pkeServerIP);
    pkeServerAddr.sin_port = htons(pkeServerPort);
    
    // Send 
    if (sendto(sock, &request, sizeof(request), 0,
               (struct sockaddr *)&pkeServerAddr, sizeof(pkeServerAddr)) != sizeof(request))
    {
        printf("(TFAServer) Failed to send request to PKE Server\n");
        return 0;
    }
    
    // Receive
    fromSize = sizeof(pkeServerAddr);
    if ((recvMsgSize = recvfrom(sock, &response, sizeof(response), 0,
                                (struct sockaddr *)&pkeServerAddr, &fromSize)) < 0)
    {
        printf("(TFAServer) Failed to receive response from PKE Server\n");
        return 0;
    }
    
    if (response.messageType == responsePublicKey && response.userID == userID)
    {
        printf("(TFAServer) Public key received: %u\n", response.publicKey);
        return response.publicKey;
    }
    
    printf("(TFAServer) Invalid response from PKE Server\n");
    return 0;
}

// TFA config
void handleRegistration(int sock, TFAClientOrLodiServerToTFAServer *msg,
                        struct sockaddr_in *clientAddr, char *pkeServerIP,
                        unsigned short pkeServerPort, unsigned long n)
{
    TFAServerToTFAClient confirmMsg, ackMsg;
    unsigned int publicKey;
    unsigned long decryptedInt;
    int userIndex;
    
    printf("(TFAServer) Processing registration for user %u\n", msg->userID);
    
    // Check if registered
    userIndex = findUser(msg->userID);
    if (userIndex >= 0)
    {
        printf("(TFAServer) User %u already registered\n", msg->userID);
        
        confirmMsg.messageType = confirmTFA;
        confirmMsg.userID = msg->userID;
        
        if (sendto(sock, &confirmMsg, sizeof(confirmMsg), 0,
                   (struct sockaddr *)clientAddr, sizeof(*clientAddr)) != sizeof(confirmMsg))
            DieWithError("(TFAServer) sendto() failed");
        
        return;
    }
    
    // Request public Key from PKE
    publicKey = requestPublicKey(sock, pkeServerIP, pkeServerPort, msg->userID, n);
    if (publicKey == 0)
    {
        printf("Failed to get public key for user %u\n", msg->userID);
        return;
    }
    
    // Verify DS
    decryptedInt = modExp(msg->digitalSig, publicKey, n);
    
    printf("(TFAServer) Verifying digital signature:\n");
    printf("(TFAServer) Timestamp: %lu\n", msg->timestamp);
    printf("(TFAServer) Decrypted: %lu\n", decryptedInt);
    
    if (decryptedInt != msg->timestamp)
    {
        printf("(TFAServer) Digital signature verification failed\n");
        return;
    }
    
    printf("(TFAServer) Digital signature verified\n");
    
    // Add user to table
    if (addUser(msg->userID, clientAddr) < 0)
    {
        printf("(TFAServer) User table full\n");
        return;
    }
    
    printf("(TFAServer) User %u registered from %s:%d\n",
           msg->userID, inet_ntoa(clientAddr->sin_addr), ntohs(clientAddr->sin_port));
    
    // Confirm TFA
    confirmMsg.messageType = confirmTFA;
    confirmMsg.userID = msg->userID;
    
    if (sendto(sock, &confirmMsg, sizeof(confirmMsg), 0,
               (struct sockaddr *)clientAddr, sizeof(*clientAddr)) != sizeof(confirmMsg))
        DieWithError("(TFAServer) sendto() failed");
    
    printf("(TFAServer) Sent confirmTFA to user %u\n", msg->userID);
}

// Auth from Lodi Server
void handleAuthRequest(int sock, TFAClientOrLodiServerToTFAServer *msg,
                       struct sockaddr_in *lodiServerAddr)
{
    TFAServerToTFAClient pushMsg;
    TFAClientOrLodiServerToTFAServer ackMsg;
    TFAServerToLodiServer responseMsg;
    struct sockaddr_in fromAddr;
    unsigned int fromSize;
    int recvMsgSize;
    int userIndex;
    
    printf("(TFAServer) Processing authentication request for user %u\n", msg->userID);
    
    // Find user
    userIndex = findUser(msg->userID);
    if (userIndex < 0)
    {
        printf("(TFAServer) User %u not registered\n", msg->userID);
        return;
    }
    
    printf("(TFAServer) User %u found, sending push notification\n", msg->userID);
    
    // pushTFA to TFA Client
    pushMsg.messageType = pushTFA;
    pushMsg.userID = msg->userID;
    
    if (sendto(sock, &pushMsg, sizeof(pushMsg), 0,
               (struct sockaddr *)&userTable[userIndex].clientAddr,
               sizeof(userTable[userIndex].clientAddr)) != sizeof(pushMsg))
    {
        printf("(TFAServer) Failed to send push notification\n");
        return;
    }
    
    printf("(TFAServer) Push notification sent to %s:%d\n",
           inet_ntoa(userTable[userIndex].clientAddr.sin_addr),
           ntohs(userTable[userIndex].clientAddr.sin_port));
    
    // Wait for ackPushTFA from TFA Client 

    printf("(TFAServer) Waiting for user approval...\n");
    
    // Set a receive timeout so we don't block forever waiting for client
    struct timeval tv;
    tv.tv_sec = 15; // wait up to 15 seconds for client response
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    fromSize = sizeof(fromAddr);
    if ((recvMsgSize = recvfrom(sock, &ackMsg, sizeof(ackMsg), 0,
                                (struct sockaddr *)&fromAddr, &fromSize)) < 0)
    {
        printf("(TFAServer) Failed to receive ack from TFA Client (timeout or error)\n");
        // Inform Lodi server that authentication failed
        TFAServerToLodiServer failMsg;
        failMsg.messageType = responseAuthFail;
        failMsg.userID = msg->userID;
        if (sendto(sock, &failMsg, sizeof(failMsg), 0,
                   (struct sockaddr *)lodiServerAddr, sizeof(*lodiServerAddr)) != sizeof(failMsg))
            printf("(TFAServer) Failed to send failure response to Lodi Server\n");
        else
            printf("(TFAServer) Sent failure response to Lodi Server due to timeout\n");
        return;
    }
    
    if (ackMsg.userID != msg->userID)
    {
        printf("(TFAServer) Invalid ack from TFA Client (wrong user)\n");
        // Notify Lodi server of failure
        TFAServerToLodiServer failMsg;
        failMsg.messageType = responseAuthFail;
        failMsg.userID = msg->userID;
        if (sendto(sock, &failMsg, sizeof(failMsg), 0,
                   (struct sockaddr *)lodiServerAddr, sizeof(*lodiServerAddr)) != sizeof(failMsg))
            printf("(TFAServer) Failed to send failure response to Lodi Server\n");
        return;
    }

    if (ackMsg.messageType == denyPushTFA)
    {
        printf("(TFAServer) User %u denied authentication\n", msg->userID);
        TFAServerToLodiServer failMsg;
        failMsg.messageType = responseAuthFail;
        failMsg.userID = msg->userID;
        if (sendto(sock, &failMsg, sizeof(failMsg), 0,
                   (struct sockaddr *)lodiServerAddr, sizeof(*lodiServerAddr)) != sizeof(failMsg))
            printf("(TFAServer) Failed to send failure response to Lodi Server\n");
        else
            printf("(TFAServer) Sent failure response to Lodi Server (user denied)\n");
        return;
    }

    if (ackMsg.messageType != ackPushTFA)
    {
        printf("(TFAServer) Invalid ack from TFA Client (unexpected type=%d)\n", ackMsg.messageType);
        TFAServerToLodiServer failMsg;
        failMsg.messageType = responseAuthFail;
        failMsg.userID = msg->userID;
        if (sendto(sock, &failMsg, sizeof(failMsg), 0,
                   (struct sockaddr *)lodiServerAddr, sizeof(*lodiServerAddr)) != sizeof(failMsg))
            printf("(TFAServer) Failed to send failure response to Lodi Server\n");
        return;
    }

    printf("(TFAServer) User %u approved authentication\n", msg->userID);
    
    // Send responseAuth to Lodi Server 
    responseMsg.messageType = responseAuth;
    responseMsg.userID = msg->userID;
    
    if (sendto(sock, &responseMsg, sizeof(responseMsg), 0,
               (struct sockaddr *)lodiServerAddr, sizeof(*lodiServerAddr)) != sizeof(responseMsg))
    {
        printf("(TFAServer) Failed to send response to Lodi Server\n");
        return;
    }
    
    printf("(TFAServer) Sent responseAuth to Lodi Server\n");
}

// Handle ackRegTFA from TFA Client 
void handleAckRegTFA(TFAClientOrLodiServerToTFAServer *msg)
{
    printf("(TFAServer) Received ackRegTFA from user %u\n", msg->userID);
}

int main(int argc, char *argv[])
{
    int sock;                        
    struct sockaddr_in tfaServAddr;  
    struct sockaddr_in clntAddr;     
    unsigned int clntAddrLen;        
    TFAClientOrLodiServerToTFAServer recvMsg;
    unsigned short tfaServPort;      
    char *pkeServerIP;               
    unsigned short pkeServerPort;    
    int recvMsgSize;                 
    unsigned long n = 533;          
    
    // Test for # of Parameters
    if (argc != 2)         
    {
        fprintf(stderr,"(TFAServer) Usage:  %s <Server IP Address>\n", argv[0]);
        exit(1);
    }
    
    tfaServPort = 2925;     
    pkeServerIP = argv[1];           
    pkeServerPort = 2924;   
    
    printf("(TFAServer) TFA Server starting...\n");
    printf("(TFAServer) Listening on port: %u\n", tfaServPort);
    printf("(TFAServer) PKE Server: %s:%u\n", pkeServerIP, pkeServerPort);
    printf("(TFAServer) RSA Modulus (n): %lu\n\n", n);
    
    // Create Socket
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("(TFAServer) socket() failed");
    
    // Construct local address
    memset(&tfaServAddr, 0, sizeof(tfaServAddr));  
    tfaServAddr.sin_family = AF_INET;                
    tfaServAddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    tfaServAddr.sin_port = htons(tfaServPort);       
    
    // Bind
    if (bind(sock, (struct sockaddr *) &tfaServAddr, sizeof(tfaServAddr)) < 0)
        DieWithError("(TFAServer) bind() failed");
    
    printf("(TFAServer) TFA Server ready. Waiting for messages...\n\n");
    
    for (;;) 
    {
        clntAddrLen = sizeof(clntAddr);
        
        // Until receive message from a client
        if ((recvMsgSize = recvfrom(sock, &recvMsg, sizeof(recvMsg), 0,
                                    (struct sockaddr *) &clntAddr, &clntAddrLen)) < 0)
            DieWithError("(TFAServer) recvfrom() failed");
        
        printf("(TFAServer) Handling client %s\n", inet_ntoa(clntAddr.sin_addr));
        printf("(TFAServer) Message type: %d\n", recvMsg.messageType);
        
        // Switch to process message based on type
        switch (recvMsg.messageType)
        {
            case registerTFA:
                handleRegistration(sock, &recvMsg, &clntAddr, pkeServerIP, pkeServerPort, n);
                break;
                
            case ackRegTFA:
                handleAckRegTFA(&recvMsg);
                break;
                
            case requestAuth:
                handleAuthRequest(sock, &recvMsg, &clntAddr);
                break;
                
            default:
                printf("(TFAServer) Unknown message type: %d\n", recvMsg.messageType);
                break;
        }
        
        
    }
    /* NOT REACHED */
}
