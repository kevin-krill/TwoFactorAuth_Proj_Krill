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

// Messages to Lodi Server (TCP Connection)
typedef struct {
    enum{login,post,feed,follow,unfollow,logout} messageType;
    unsigned int userID;
    unsigned int recipientID;
    unsigned long timestamp;
    unsigned long digitalSig;
    char message[100];
} PClientToLodiServer;

// Messages from Lodi Server (TCP Acknowledgments)
typedef struct {
    enum{ackLogin,ackPost,ackFeed,ackFollow,ackUnfollow,ackLogout} messageType;
    unsigned int userID;
    char message[100];
} LodiServerMessage;

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

// Helper function to send request to Lodi Server and receive response
// Returns 0 on failure, 1 on success
int sendRequestToServer(char *lodiServerIP, unsigned short lodiServerPort,
                        PClientToLodiServer *request, LodiServerMessage *response) {
    int tcpSock;
    struct sockaddr_in lodiServerAddr;
    char buffer[BUFFER_SIZE];

    // Create TCP socket
    if ((tcpSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        printf("(LodiClient) Error: Failed to create TCP socket\n");
        return 0;
    }

    // Configure server address
    memset(&lodiServerAddr, 0, sizeof(lodiServerAddr));
    lodiServerAddr.sin_family = AF_INET;
    lodiServerAddr.sin_addr.s_addr = inet_addr(lodiServerIP);
    lodiServerAddr.sin_port = htons(lodiServerPort);

    // Connect to server
    if (connect(tcpSock, (struct sockaddr *)&lodiServerAddr, sizeof(lodiServerAddr)) < 0) {
        printf("(LodiClient) Error: Failed to connect to server\n");
        close(tcpSock);
        return 0;
    }

    // Send request (ensure all bytes sent)
    unsigned int requestLen = sizeof(PClientToLodiServer);
    unsigned int sent = 0;
    while (sent < requestLen) {
        int s = send(tcpSock, ((char *)request) + sent, requestLen - sent, 0);
        if (s <= 0) {
            printf("(LodiClient) Error: Failed to send request\n");
            close(tcpSock);
            return 0;
        }
        sent += s;
    }

    // Set receive timeout
    struct timeval tv = {10, 0};
    setsockopt(tcpSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Receive response (handle partial reads)
    unsigned int expected = sizeof(LodiServerMessage);
    unsigned int totalBytesRcvd = 0;
    while (totalBytesRcvd < expected) {
        int r = recv(tcpSock, buffer + totalBytesRcvd, (int)(expected - totalBytesRcvd), 0);
        if (r < 0) {
            printf("(LodiClient) Error: Failed to receive response\n");
            close(tcpSock);
            return 0;
        }
        if (r == 0) break; // Connection closed
        totalBytesRcvd += r;
    }

    if (totalBytesRcvd < expected) {
        printf("(LodiClient) Error: Incomplete response from server\n");
        close(tcpSock);
        return 0;
    }

    // Copy response
    memcpy(response, buffer, sizeof(LodiServerMessage));

    // Close connection
    close(tcpSock);

    return 1;
}

// Function to display session menu
void displayMenu() {
    printf("\n========== LODI CLIENT MENU ==========\n");
    printf("1. Post a message\n");
    printf("2. View feed (posts from idols)\n");
    printf("3. Follow an idol\n");
    printf("4. Unfollow an idol\n");
    printf("5. Logout\n");
    printf("======================================\n");
    printf("Enter your choice (1-5): ");
}

// Function to get session choice
int getSessionChoice() {
    int choice;
    if (scanf("%d", &choice) != 1) {
        while(getchar() != '\n'); // Clear input buffer
        return -1;
    }
    while(getchar() != '\n'); // Clear remaining input
    return choice;
}

// Skeleton: Post a message
int handlePost(char *lodiServerIP, unsigned short lodiServerPort,
               unsigned int userID, unsigned long d, unsigned long n) {
    printf("\n--- POST MESSAGE ---\n");

    // TODO: Implement posting functionality
    // 1. Get message content from user (fgets into char array)
    // 2. Create timestamp: time(NULL) % 500
    // 3. Create digital signature: createDigitalSignature(timestamp, d, n)
    // 4. Fill PClientToLodiServer struct:
    //    - messageType = post
    //    - userID, recipientID = 0, timestamp, digitalSig
    //    - Copy message content into message field
    // 5. Call sendRequestToServer()
    // 6. Check response.messageType == ackPost
    // 7. Display success message

    printf("(Feature not yet implemented)\n");
    return 0;
}

// Skeleton: View feed (get posts from followed idols)
int handleFeed(char *lodiServerIP, unsigned short lodiServerPort,
               unsigned int userID, unsigned long d, unsigned long n) {
    printf("\n--- VIEW FEED ---\n");

    // TODO: Implement feed retrieval functionality
    // 1. Create timestamp: time(NULL) % 500
    // 2. Create digital signature: createDigitalSignature(timestamp, d, n)
    // 3. Fill PClientToLodiServer struct:
    //    - messageType = feed
    //    - userID, recipientID = 0, timestamp, digitalSig
    //    - message field empty
    // 4. Call sendRequestToServer()
    // 5. Check response.messageType == ackFeed
    // 6. Parse and display posts from response.message field

    printf("(Feature not yet implemented)\n");
    return 0;
}

// Skeleton: Follow an idol
int handleFollow(char *lodiServerIP, unsigned short lodiServerPort,
                 unsigned int userID, unsigned long d, unsigned long n) {
    printf("\n--- FOLLOW IDOL ---\n");

    // TODO: Implement follow functionality
    // 1. Get idol's userID from user input (scanf)
    // 2. Create timestamp: time(NULL) % 500
    // 3. Create digital signature: createDigitalSignature(timestamp, d, n)
    // 4. Fill PClientToLodiServer struct:
    //    - messageType = follow
    //    - userID, recipientID = idol's userID, timestamp, digitalSig
    //    - message field empty
    // 5. Call sendRequestToServer()
    // 6. Check response.messageType == ackFollow
    // 7. Display success message

    printf("(Feature not yet implemented)\n");
    return 0;
}

// Skeleton: Unfollow an idol
int handleUnfollow(char *lodiServerIP, unsigned short lodiServerPort,
                   unsigned int userID, unsigned long d, unsigned long n) {
    printf("\n--- UNFOLLOW IDOL ---\n");

    // TODO: Implement unfollow functionality
    // 1. Get idol's userID from user input (scanf)
    // 2. Create timestamp: time(NULL) % 500
    // 3. Create digital signature: createDigitalSignature(timestamp, d, n)
    // 4. Fill PClientToLodiServer struct:
    //    - messageType = unfollow
    //    - userID, recipientID = idol's userID, timestamp, digitalSig
    //    - message field empty
    // 5. Call sendRequestToServer()
    // 6. Check response.messageType == ackUnfollow
    // 7. Display success message

    printf("(Feature not yet implemented)\n");
    return 0;
}

// Skeleton: Logout
int handleLogout(char *lodiServerIP, unsigned short lodiServerPort,
                 unsigned int userID, unsigned long d, unsigned long n) {
    printf("\n--- LOGOUT ---\n");

    // TODO: Implement logout functionality
    // 1. Create timestamp: time(NULL) % 500
    // 2. Create digital signature: createDigitalSignature(timestamp, d, n)
    // 3. Fill PClientToLodiServer struct:
    //    - messageType = logout
    //    - userID, recipientID = 0, timestamp, digitalSig
    //    - message field empty
    // 4. Call sendRequestToServer()
    // 5. Check response.messageType == ackLogout
    // 6. Display logout confirmation

    printf("Logging out...\n");
    return 1; // Return 1 to signal logout
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
        memset(loginMsg.message, 0, sizeof(loginMsg.message)); // Initialize message field
        
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
        unsigned int expected = sizeof(LodiServerMessage);
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

        LodiServerMessage *lodiResponse = (LodiServerMessage *)buffer;
        if (lodiResponse->messageType == ackLogin) {
            printf("(LodiCLient) Login successful\n");
            printf("(LodiCLient) Confirmed User ID: %u\n", lodiResponse->userID);
            printf("(LodiCLient) Server message: %s\n\n", lodiResponse->message);

            // Close connection after successful login
            close(tcpSock);
            printf("(LodiCLient) Login connection closed\n");

            // ========== CONTINUOUS SESSION LOOP ==========
            printf("(LodiCLient) Starting session...\n");
            int sessionActive = 1;

            while (sessionActive) {
                displayMenu();
                int choice = getSessionChoice();

                switch (choice) {
                    case 1:
                        handlePost(lodiServerIP, lodiServerPort, userID, d, n);
                        break;
                    case 2:
                        handleFeed(lodiServerIP, lodiServerPort, userID, d, n);
                        break;
                    case 3:
                        handleFollow(lodiServerIP, lodiServerPort, userID, d, n);
                        break;
                    case 4:
                        handleUnfollow(lodiServerIP, lodiServerPort, userID, d, n);
                        break;
                    case 5:
                        sessionActive = !handleLogout(lodiServerIP, lodiServerPort, userID, d, n);
                        break;
                    default:
                        printf("Invalid choice. Please enter a number between 1-5.\n");
                        break;
                }
            }

            printf("(LodiCLient) Session ended.\n");
        } else {
            close(tcpSock);
            DieWithError("(LodiCLient) ERROR: Unexpected response from Lodi Server");
        }
    }else{
        DieWithError("Use <register|login>");
    }
     
    
    
    
    close(sock);
    return 0;
}