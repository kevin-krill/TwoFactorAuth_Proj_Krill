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
    printf("5. Logout / Quit\n");
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

// Post a message
int handlePost(char *lodiServerIP, unsigned short lodiServerPort,
               unsigned int userID, unsigned long d, unsigned long n) {
    printf("\n--- POST MESSAGE ---\n");

    // Get message content from user (fgets into char array)
    char messageContent[100];
    printf("Enter your message (max 99 characters): ");
    if (fgets(messageContent, sizeof(messageContent), stdin) == NULL) {
        printf("Error reading message\n");
        return 0;
    }

    // Remove trailing newline if present
    size_t len = strlen(messageContent);
    if (len > 0 && messageContent[len - 1] == '\n') {
        messageContent[len - 1] = '\0';
    }

    // Create timestamp: time(NULL) % 500
    unsigned long timestamp = (unsigned long)time(NULL) % 500;

    // Create digital signature: createDigitalSignature(timestamp, d, n)
    unsigned long digitalSig = createDigitalSignature(timestamp, d, n);

    // Fill PClientToLodiServer struct
    PClientToLodiServer request;
    request.messageType = post;
    request.userID = userID;
    request.recipientID = 0;
    request.timestamp = timestamp;
    request.digitalSig = digitalSig;
    strncpy(request.message, messageContent, sizeof(request.message) - 1);
    request.message[sizeof(request.message) - 1] = '\0'; // Ensure null termination

    // Call sendRequestToServer()
    printf("(LodiClient) Sending POST request to server...\n");
    LodiServerMessage response;
    if (!sendRequestToServer(lodiServerIP, lodiServerPort, &request, &response)) {
        printf("Failed to send post to server\n");
        return 0;
    }

    // Check response.messageType == ackPost
    if (response.messageType == ackPost) {
        // Display success message
        printf("\n*** MESSAGE POSTED SUCCESSFULLY ***\n");
        printf("Your message: \"%s\"\n", messageContent);
        printf("Server response: %s\n", response.message);
        return 1;
    } else {
        printf("Error: Unexpected response from server\n");
        printf("Server message: %s\n", response.message);
        return 0;
    }
}

// View feed (get posts from followed idols) - receives multiple messages
int handleFeed(char *lodiServerIP, unsigned short lodiServerPort,
               unsigned int userID, unsigned long d, unsigned long n) {
    printf("\n--- VIEW FEED ---\n");

    int tcpSock;
    struct sockaddr_in lodiServerAddr;

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

    // Create timestamp: time(NULL) % 500
    unsigned long timestamp = (unsigned long)time(NULL) % 500;

    // Create digital signature: createDigitalSignature(timestamp, d, n)
    unsigned long digitalSig = createDigitalSignature(timestamp, d, n);

    // Fill PClientToLodiServer struct
    PClientToLodiServer request;
    request.messageType = feed;
    request.userID = userID;
    request.recipientID = 0;
    request.timestamp = timestamp;
    request.digitalSig = digitalSig;
    memset(request.message, 0, sizeof(request.message)); // Empty message field

    // Send request (ensure all bytes sent)
    printf("(LodiClient) Sending FEED request to server...\n");
    unsigned int requestLen = sizeof(PClientToLodiServer);
    unsigned int sent = 0;
    while (sent < requestLen) {
        int s = send(tcpSock, ((char *)&request) + sent, requestLen - sent, 0);
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

    printf("\n*** YOUR FEED ***\n");
    int postCount = 0;

    // Loop to receive multiple posts until END_OF_FEED signal
    while (1) {
        LodiServerMessage response;
        char buffer[BUFFER_SIZE];

        // Receive response 
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
        memcpy(&response, buffer, sizeof(LodiServerMessage));

        // Check if this is the end signal
        if (strcmp(response.message, "END_OF_FEED") == 0) {
            break;
        }

        // Check response type
        if (response.messageType != ackFeed) {
            printf("Error: Unexpected response from server\n");
            close(tcpSock);
            return 0;
        }

        // Display this post
        printf("%s\n", response.message);
        postCount++;
    }

    close(tcpSock);

    if (postCount == 0) {
        printf("No posts to display. Follow some users to see their posts!\n");
    } else {
        printf("\n--- End of feed (%d posts) ---\n", postCount);
    }

    return 1;
}

// Follow an idol
int handleFollow(char *lodiServerIP, unsigned short lodiServerPort,
                 unsigned int userID, unsigned long d, unsigned long n) {
    printf("\n--- FOLLOW IDOL ---\n");

    // Get idol's userID from user input (scanf)
    unsigned int idolID;
    printf("Enter the User ID of the idol you want to follow: ");
    if (scanf("%u", &idolID) != 1) {
        while(getchar() != '\n'); // Clear input buffer
        printf("Error: Invalid user ID\n");
        return 0;
    }
    while(getchar() != '\n'); // Clear remaining input

    // Check if trying to follow themselves
    if (idolID == userID) {
        printf("Error: You cannot follow yourself\n");
        return 0;
    }

    // Create timestamp: time(NULL) % 500
    unsigned long timestamp = (unsigned long)time(NULL) % 500;

    // Create digital signature: createDigitalSignature(timestamp, d, n)
    unsigned long digitalSig = createDigitalSignature(timestamp, d, n);

    // Fill PClientToLodiServer struct
    PClientToLodiServer request;
    request.messageType = follow;
    request.userID = userID;
    request.recipientID = idolID;
    request.timestamp = timestamp;
    request.digitalSig = digitalSig;
    memset(request.message, 0, sizeof(request.message)); // Empty message field

    // Call sendRequestToServer()
    printf("(LodiClient) Sending FOLLOW request to server...\n");
    LodiServerMessage response;
    if (!sendRequestToServer(lodiServerIP, lodiServerPort, &request, &response)) {
        printf("Failed to send follow request to server\n");
        return 0;
    }

    // Check response.messageType == ackFollow
    if (response.messageType == ackFollow) {
        // Display success message
        printf("\n*** FOLLOW SUCCESSFUL ***\n");
        printf("You are now following User ID: %u\n", idolID);
        printf("Server response: %s\n", response.message);
        return 1;
    } else {
        printf("Error: Unexpected response from server\n");
        printf("Server message: %s\n", response.message);
        return 0;
    }
}

// Unfollow an idol
int handleUnfollow(char *lodiServerIP, unsigned short lodiServerPort,
                   unsigned int userID, unsigned long d, unsigned long n) {
    printf("\n--- UNFOLLOW IDOL ---\n");

    // Get idol's userID from user input (scanf)
    unsigned int idolID;
    printf("Enter the User ID of the idol you want to unfollow: ");
    if (scanf("%u", &idolID) != 1) {
        while(getchar() != '\n'); // Clear input buffer
        printf("Error: Invalid user ID\n");
        return 0;
    }
    while(getchar() != '\n'); // Clear remaining input

    // Check if trying to unfollow themselves
    if (idolID == userID) {
        printf("Error: You cannot unfollow yourself\n");
        return 0;
    }

    // Create timestamp: time(NULL) % 500
    unsigned long timestamp = (unsigned long)time(NULL) % 500;

    // Create digital signature: createDigitalSignature(timestamp, d, n)
    unsigned long digitalSig = createDigitalSignature(timestamp, d, n);

    // Fill PClientToLodiServer struct
    PClientToLodiServer request;
    request.messageType = unfollow;
    request.userID = userID;
    request.recipientID = idolID;
    request.timestamp = timestamp;
    request.digitalSig = digitalSig;
    memset(request.message, 0, sizeof(request.message)); // Empty message field

    // Call sendRequestToServer()
    printf("(LodiClient) Sending UNFOLLOW request to server...\n");
    LodiServerMessage response;
    if (!sendRequestToServer(lodiServerIP, lodiServerPort, &request, &response)) {
        printf("Failed to send unfollow request to server\n");
        return 0;
    }

    // Check response.messageType == ackUnfollow
    if (response.messageType == ackUnfollow) {
        // Display success message
        printf("\n*** UNFOLLOW SUCCESSFUL ***\n");
        printf("You have unfollowed User ID: %u\n", idolID);
        printf("Server response: %s\n", response.message);
        return 1;
    } else {
        printf("Error: Unexpected response from server\n");
        printf("Server message: %s\n", response.message);
        return 0;
    }
}

// Logout
int handleLogout(char *lodiServerIP, unsigned short lodiServerPort,
                 unsigned int userID, unsigned long d, unsigned long n) {
    printf("\n--- LOGOUT ---\n");

    // Create timestamp: time(NULL) % 500
    unsigned long timestamp = (unsigned long)time(NULL) % 500;

    // Create digital signature: createDigitalSignature(timestamp, d, n)
    unsigned long digitalSig = createDigitalSignature(timestamp, d, n);

    // Fill PClientToLodiServer struct
    PClientToLodiServer request;
    request.messageType = logout;
    request.userID = userID;
    request.recipientID = 0;
    request.timestamp = timestamp;
    request.digitalSig = digitalSig;
    memset(request.message, 0, sizeof(request.message)); // Empty message field

    // Call sendRequestToServer()
    printf("(LodiClient) Sending LOGOUT request to server...\n");
    LodiServerMessage response;
    if (!sendRequestToServer(lodiServerIP, lodiServerPort, &request, &response)) {
        printf("Failed to send logout request to server\n");
        return 1; // Still logout locally even if server communication fails
    }

    // Check response.messageType == ackLogout
    if (response.messageType == ackLogout) {
        // Display logout confirmation
        printf("\n*** LOGOUT SUCCESSFUL ***\n");
        printf("Server response: %s\n", response.message);
        printf("Goodbye!\n");
        return 1;
    } else {
        printf("Warning: Unexpected response from server\n");
        printf("Server message: %s\n", response.message);
        printf("Logging out locally anyway...\n");
        return 1; // Still logout locally
    }
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