#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BUFFER_SIZE 1024  

void DieWithError(char *errorMessage);  /* Error handling function */

// Messages coming to the PKE Server (from clients)
typedef struct {
    enum {registerKey, requestKey} messageType;
    unsigned int userID;
    unsigned int publicKey;
} PClientToPKServer;

// DATABASE
#define MAX_USERS 100

typedef struct {
    unsigned int userID;     
    unsigned int publicKey;  
    int active;              
} UserKeyEntry;

// messages going from the PKE Server (to clients)
typedef struct {
    enum {ackRegisterKey, responsePublicKey} messageType;
    unsigned int userID;
    unsigned int publicKey;
} PKServerToPClientOrLodiServer;

// global database array
UserKeyEntry keyDatabase[MAX_USERS];
int totalUsers = 0;

void initializeDatabase() {
    for (int i = 0; i < MAX_USERS; i++) {
        keyDatabase[i].active = 0;
        keyDatabase[i].userID = 0;
        keyDatabase[i].publicKey = 0;
    }
    printf("(PKEServer) Database initialized (capacity: %d users)\n", MAX_USERS);
}

int storePublicKey(unsigned int userID, unsigned int publicKey) {
    // if user exists 
    for (int i = 0; i < MAX_USERS; i++) {
        if (keyDatabase[i].active && keyDatabase[i].userID == userID) {
            keyDatabase[i].publicKey = publicKey;
            printf("(PKEServer) Updated key for user %u\n", userID);
            return 1;
        }
    }
    
    // find empty slot
    for (int i = 0; i < MAX_USERS; i++) {
        if (!keyDatabase[i].active) {
            keyDatabase[i].userID = userID;
            keyDatabase[i].publicKey = publicKey;
            keyDatabase[i].active = 1;
            totalUsers++;
            printf("(PKEServer) Stored new key for user %u (total users: %d)\n", 
                   userID, totalUsers);
            return 1;
        }
    }
    
    printf("(PKEServer) ERROR: Database full!\n");
    return 0;
}

unsigned int getPublicKey(unsigned int userID) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (keyDatabase[i].active && keyDatabase[i].userID == userID) {
            printf("Found key for user %u\n", userID);
            return keyDatabase[i].publicKey;
        }
    }
    printf("(PKEServer) Key not found for user %u\n", userID);
    return 0;  
}

int main(int argc, char *argv[]) {
    int sock;
    struct sockaddr_in serverAddr;
    unsigned int serverPort;
    
    struct sockaddr_in clientAddr;
    unsigned int clientAddrLen;
    char buffer[BUFFER_SIZE];
    int recvMsgSize;

    // check command line 
    if (argc != 2) {
        fprintf(stderr, "(PKEServer) Usage: %s <Server Port>\n", argv[0]);
        exit(1);
    }
    
    serverPort = atoi(argv[1]);
    printf("(PKEServer) PKE Server starting on port %u...\n", serverPort);
    
    // create socket
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("socket() failed");
    
    printf("(PKEServer) Socket created successfully!\n");
    
    // construct local address structure
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port = htons(serverPort);
    
    printf("(PKEServer) Address structure configured!\n");
    
    // bind to the local address
    if (bind(sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
        DieWithError("(PKEServer) bind() failed");
    
    printf("(PKEServer) Socket bound to port %u!\n", serverPort);
    printf("(PKEServer) PKE Server ready and listening...\n");
    
    // initialize database
    initializeDatabase();
    
    for (;;) {
       clientAddrLen = sizeof(clientAddr);
        
        printf("(PKEServer) Waiting for a message...");
        // if receive message 
        if ((recvMsgSize = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                                    (struct sockaddr *)&clientAddr, 
                                    &clientAddrLen)) < 0)
            DieWithError("(PKEServer) recvfrom() failed");
        
        printf("(PKEServer) Received %d bytes from %s (port %d)\n", 
               recvMsgSize, 
               inet_ntoa(clientAddr.sin_addr),
               ntohs(clientAddr.sin_port));
        
        PClientToPKServer *request = (PClientToPKServer *)buffer;
        
        if (request->messageType == registerKey) {
            printf("(PKEServer) Message Type: registerKey\n");
            printf("(PKEServer) User ID: %u\n", request->userID);
            printf("(PKEServer) Public Key: %u\n", request->publicKey);
            
            storePublicKey(request->userID, request->publicKey);
            
            PKServerToPClientOrLodiServer response;
            response.messageType = ackRegisterKey;
            response.userID = request->userID;
            response.publicKey = request->publicKey;
            
            if (sendto(sock, &response, sizeof(response), 0,
                       (struct sockaddr *)&clientAddr, 
                       sizeof(clientAddr)) != sizeof(response))
                DieWithError("(PKEServer) sendto() sent different number of bytes");
            
            printf("(PKEServer) Sent ackRegisterKey to client\n");
        }
        else if (request->messageType == requestKey) {
            printf("(PKEServer) Message Type: requestKey\n");
            printf("(PKEServer) Requested User ID: %u\n", request->userID);
            
            unsigned int publicKey = getPublicKey(request->userID);
            
            PKServerToPClientOrLodiServer response;
            response.messageType = responsePublicKey;
            response.userID = request->userID;
            response.publicKey = publicKey;
            
            if (sendto(sock, &response, sizeof(response), 0,
                       (struct sockaddr *)&clientAddr, 
                       sizeof(clientAddr)) != sizeof(response))
                DieWithError("(PKEServer) sendto() sent different number of bytes");
            
            printf("(PKEServer) Sent responsePublicKey (key: %u)\n", publicKey);
        }
        else {
            printf("(PKEServer) Message Type: UNKNOWN (%d)\n", request->messageType);
        }
    }
    
    close(sock);
    return 0;
}