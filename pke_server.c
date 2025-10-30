#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BUFFER_SIZE 1024  

/* error handling function */
void DieWithError(char *errorMessage) {
    perror(errorMessage);
    exit(1);
}

// messages coming TO the PKE Server (from clients)
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

// global database array
UserKeyEntry keyDatabase[MAX_USERS];
int totalUsers = 0;

void initializeDatabase() {
    for (int i = 0; i < MAX_USERS; i++) {
        keyDatabase[i].active = 0;
        keyDatabase[i].userID = 0;
        keyDatabase[i].publicKey = 0;
    }
    printf("Database initialized (capacity: %d users)\n", MAX_USERS);
}

int storePublicKey(unsigned int userID, unsigned int publicKey) {
    // if user exists 
    for (int i = 0; i < MAX_USERS; i++) {
        if (keyDatabase[i].active && keyDatabase[i].userID == userID) {
            keyDatabase[i].publicKey = publicKey;
            printf("Updated key for user %u\n", userID);
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
            printf("Stored new key for user %u (total users: %d)\n", 
                   userID, totalUsers);
            return 1;
        }
    }
    
    printf("ERROR: Database full!\n");
    return 0;
}

unsigned int getPublicKey(unsigned int userID) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (keyDatabase[i].active && keyDatabase[i].userID == userID) {
            printf("Found key for user %u\n", userID);
            return keyDatabase[i].publicKey;
        }
    }
    printf("Key not found for user %u\n", userID);
    return 0;  
}

// messages going FROM the PKE Server (to clients)
typedef struct {
    enum {ackRegisterKey, responsePublicKey} messageType;
    unsigned int userID;
    unsigned int publicKey;
} PKServerToPClientOrLodiServer;

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
        fprintf(stderr, "Usage: %s <Server Port>\n", argv[0]);
        exit(1);
    }
    
    serverPort = atoi(argv[1]);
    printf("PKE Server starting on port %u...\n", serverPort);
    
    // create socket
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("socket() failed");
    
    printf("Socket created successfully!\n");
    
    // construct local address structure
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port = htons(serverPort);
    
    printf("Address structure configured!\n");
    
    // bind to the local address
    if (bind(sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
        DieWithError("bind() failed");
    
    printf("Socket bound to port %u!\n", serverPort);
    printf("PKE Server ready and listening...\n");
    
    // initialize database
    initializeDatabase();
    
    for (;;) {
       clientAddrLen = sizeof(clientAddr);
        
        printf("Waiting for a message...");
        // if receive message 
        if ((recvMsgSize = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                                    (struct sockaddr *)&clientAddr, 
                                    &clientAddrLen)) < 0)
            DieWithError("recvfrom() failed");
        
        printf("Received %d bytes from %s (port %d)\n", 
               recvMsgSize, 
               inet_ntoa(clientAddr.sin_addr),
               ntohs(clientAddr.sin_port));
        
        PClientToPKServer *request = (PClientToPKServer *)buffer;
        
        if (request->messageType == registerKey) {
            printf("  Message Type: registerKey\n");
            printf("  User ID: %u\n", request->userID);
            printf("  Public Key: %u\n", request->publicKey);
            
            storePublicKey(request->userID, request->publicKey);
            
            PKServerToPClientOrLodiServer response;
            response.messageType = ackRegisterKey;
            response.userID = request->userID;
            response.publicKey = request->publicKey;
            
            if (sendto(sock, &response, sizeof(response), 0,
                       (struct sockaddr *)&clientAddr, 
                       sizeof(clientAddr)) != sizeof(response))
                DieWithError("sendto() sent different number of bytes");
            
            printf("Sent ackRegisterKey to client\n");
        }
        else if (request->messageType == requestKey) {
            printf("  Message Type: requestKey\n");
            printf("  Requested User ID: %u\n", request->userID);
            
            unsigned int publicKey = getPublicKey(request->userID);
            
            PKServerToPClientOrLodiServer response;
            response.messageType = responsePublicKey;
            response.userID = request->userID;
            response.publicKey = publicKey;
            
            if (sendto(sock, &response, sizeof(response), 0,
                       (struct sockaddr *)&clientAddr, 
                       sizeof(clientAddr)) != sizeof(response))
                DieWithError("sendto() sent different number of bytes");
            
            printf("Sent responsePublicKey (key: %u)\n", publicKey);
        }
        else {
            printf("Message Type: UNKNOWN (%d)\n", request->messageType);
        }
    }
    
    close(sock);
    return 0;
}