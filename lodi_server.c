#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

#define BUFFER_SIZE 1024
#define MAX_TIMESTAMP_DIFF 30  // 30 seconds tolerance for timestamp
#define MAXPENDING 5
#define MAX_POSTS 1000  // Maximum number of posts to store
#define MAX_USERS 100   // Maximum number of users

void DieWithError(char *errorMessage)
{
	perror(errorMessage);
	exit(1);
}


// TCP Connection client to server message
typedef struct {
    enum{login,post,feed,follow,unfollow,logout} messageType;
    unsigned int userID;
    unsigned int recipientID;
    unsigned long timestamp;
    unsigned long digitalSig;
    char message[100];
} PClientToLodiServer;

// TCP connections server to client acks
typedef struct {
    enum{ackLogin,ackPost,ackFeed,ackFollow,ackUnfollow,ackLogout} messageType;
    unsigned int userID;
    char message[100];
} LodiServerMessage;

typedef struct {
    enum { ackRegisterKey, responsePublicKey } messageType;
    unsigned int userID;
    unsigned int publicKey;
} PKServerToPClientOrLodiServer;

typedef struct {
    enum { responseAuth, responseAuthFail } messageType;
    unsigned int userID;
} TFAServerToLodiServer;

// To PKE Server
typedef struct {
    enum {registerKey, requestKey} messageType;
    unsigned int userID;
    unsigned int publicKey;
} LodiServerToPKEServer;

// To TFA Server (request authentication)
typedef struct {
    enum {registerTFA, ackRegTFA, ackPushTFA, denyPushTFA, requestAuth} messageType;
    unsigned int userID;
    unsigned long timestamp;
    unsigned long digitalSig;
} LodiServerToTFAServer;

// Post storage structure
typedef struct {
    unsigned int userID;
    unsigned long timestamp;
    char message[100];
} Post;

// Per-user following list structure
#define MAX_FOLLOWING_PER_USER 100
typedef struct {
    unsigned int userID;                           // The user who owns this list
    unsigned int following[MAX_FOLLOWING_PER_USER]; // IDs of users they follow
    int followingCount;                             // Number of users they follow
} UserFollowingList;

// Global storage for posts
Post posts[MAX_POSTS];
int postCount = 0;

// Global storage for user following lists
UserFollowingList userFollowingLists[MAX_USERS];
int userListCount = 0;

// Helper function to get or create a user's following list, returns pointer to the user's list, or NULL if storage is full
UserFollowingList* getUserFollowingList(unsigned int userID) {
    // Check if user already has a list
    for (int i = 0; i < userListCount; i++) {
        if (userFollowingLists[i].userID == userID) {
            return &userFollowingLists[i];
        }
    }

    // User doesn't have a list yet, create one
    if (userListCount >= MAX_USERS) {
        printf("(LodiServer) ERROR: Cannot create more user following lists (max %d)\n", MAX_USERS);
        return NULL;
    }

    // Initialize new list
    userFollowingLists[userListCount].userID = userID;
    userFollowingLists[userListCount].followingCount = 0;
    printf("(LodiServer) Created new following list for user %u at index %d\n", userID, userListCount);

    userListCount++;
    return &userFollowingLists[userListCount - 1];
}

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
    struct sockaddr_in fromAddr;
    unsigned int fromSize;
    LodiServerToPKEServer request;
    PKServerToPClientOrLodiServer response;
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
    fromSize = sizeof(fromAddr);
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
    TFAServerToLodiServer response; 
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
    else if (response.messageType == responseAuthFail && response.userID == userID) {
        printf("(LodiServer) Authentication denied for user %u\n", userID);
        return 0;
    }

    printf("(LodiServer) Error: Invalid response from TFA Server\n");
    return 0;
}

//  Handle post message
void handlePost(PClientToLodiServer *msg, LodiServerMessage *response) {
    printf("\n(LodiServer) --- HANDLE POST ---\n");
    printf("(LodiServer) User %u wants to post: \"%s\"\n", msg->userID, msg->message);

    // Check if we have space for more posts
    if (postCount >= MAX_POSTS) {
        printf("(LodiServer) ERROR: Post storage is full\n");
        response->messageType = ackPost;
        response->userID = msg->userID;
        strcpy(response->message, "Error: Server post storage is full");
        return;
    }

    // Store the post
    posts[postCount].userID = msg->userID;
    posts[postCount].timestamp = msg->timestamp;
    strncpy(posts[postCount].message, msg->message, sizeof(posts[postCount].message) - 1);
    posts[postCount].message[sizeof(posts[postCount].message) - 1] = '\0';

    printf("(LodiServer) Post stored at index %d\n", postCount);
    printf("(LodiServer) User ID: %u\n", posts[postCount].userID);
    printf("(LodiServer) Timestamp: %lu\n", posts[postCount].timestamp);
    printf("(LodiServer) Message: \"%s\"\n", posts[postCount].message);

    postCount++;
    printf("(LodiServer) Total posts now: %d\n", postCount);

    // Send success response
    response->messageType = ackPost;
    response->userID = msg->userID;
    strcpy(response->message, "Post successful");
    printf("(LodiServer) Post successfully stored\n");
}

// Skeleton: Handle follow request
void handleFollow(PClientToLodiServer *msg, LodiServerMessage *response) {
    printf("\n(LodiServer) --- HANDLE FOLLOW ---\n");
    printf("(LodiServer) User %u wants to follow user %u\n", msg->userID, msg->recipientID);

    // Get or create the user's following list
    UserFollowingList* userList = getUserFollowingList(msg->userID);
    if (userList == NULL) {
        printf("(LodiServer) ERROR: Could not get/create following list for user %u\n", msg->userID);
        response->messageType = ackFollow;
        response->userID = msg->userID;
        strcpy(response->message, "Error: Server user storage is full");
        return;
    }

    // Check if user's following list is full
    if (userList->followingCount >= MAX_FOLLOWING_PER_USER) {
        printf("(LodiServer) ERROR: User %u has reached max following limit (%d)\n",
               msg->userID, MAX_FOLLOWING_PER_USER);
        response->messageType = ackFollow;
        response->userID = msg->userID;
        strcpy(response->message, "Error: You have reached max following limit");
        return;
    }

    // Check if already following this idol
    for (int i = 0; i < userList->followingCount; i++) {
        if (userList->following[i] == msg->recipientID) {
            printf("(LodiServer) User %u is already following user %u\n", msg->userID, msg->recipientID);
            response->messageType = ackFollow;
            response->userID = msg->userID;
            strcpy(response->message, "You are already following this user");
            return;
        }
    }

    // Add the idol to the user's following list
    userList->following[userList->followingCount] = msg->recipientID;
    userList->followingCount++;

    printf("(LodiServer) User %u now following user %u\n", msg->userID, msg->recipientID);
    printf("(LodiServer) User %u is now following %d users\n", msg->userID, userList->followingCount);

    // Send success response
    response->messageType = ackFollow;
    response->userID = msg->userID;
    strcpy(response->message, "Follow successful");
    printf("(LodiServer) Follow relationship successfully stored\n");
}

// Skeleton: Handle unfollow request
void handleUnfollow(PClientToLodiServer *msg, LodiServerMessage *response) {
    printf("\n(LodiServer) --- HANDLE UNFOLLOW ---\n");
    printf("(LodiServer) User %u wants to unfollow user %u\n", msg->userID, msg->recipientID);

    // Get the user's following list
    UserFollowingList* userList = NULL;
    for (int i = 0; i < userListCount; i++) {
        if (userFollowingLists[i].userID == msg->userID) {
            userList = &userFollowingLists[i];
            break;
        }
    }

    // Check if user has a following list
    if (userList == NULL) {
        printf("(LodiServer) User %u has no following list\n", msg->userID);
        response->messageType = ackUnfollow;
        response->userID = msg->userID;
        strcpy(response->message, "You are not following anyone");
        return;
    }

    // Find and remove the idol from the user's following list
    int found = -1;
    for (int i = 0; i < userList->followingCount; i++) {
        if (userList->following[i] == msg->recipientID) {
            found = i;
            break;
        }
    }

    if (found == -1) {
        printf("(LodiServer) User %u is not following user %u\n", msg->userID, msg->recipientID);
        response->messageType = ackUnfollow;
        response->userID = msg->userID;
        strcpy(response->message, "You are not following this user");
        return;
    }

    // Remove the idol by shifting all subsequent elements left
    for (int i = found; i < userList->followingCount - 1; i++) {
        userList->following[i] = userList->following[i + 1];
    }
    userList->followingCount--;

    printf("(LodiServer) User %u unfollowed user %u\n", msg->userID, msg->recipientID);
    printf("(LodiServer) User %u is now following %d users\n", msg->userID, userList->followingCount);

    // Send success response
    response->messageType = ackUnfollow;
    response->userID = msg->userID;
    strcpy(response->message, "Unfollow successful");
    printf("(LodiServer) Unfollow successfully processed\n");
}

// Handle feed request - sends multiple messages
int handleFeedMultiple(PClientToLodiServer *msg, int clientSocket, struct sockaddr_in *clientAddr) {
    printf("\n(LodiServer) --- HANDLE FEED ---\n");
    printf("(LodiServer) User %u requesting feed\n", msg->userID);

    LodiServerMessage response;
    response.messageType = ackFeed;
    response.userID = msg->userID;

    // Find the user's following list
    UserFollowingList* userList = NULL;
    for (int i = 0; i < userListCount; i++) {
        if (userFollowingLists[i].userID == msg->userID) {
            userList = &userFollowingLists[i];
            break;
        }
    }

    // Check if user is following anyone
    if (userList == NULL || userList->followingCount == 0) {
        printf("(LodiServer) User %u is not following anyone\n", msg->userID);
        strcpy(response.message, "END_OF_FEED");

        // Send the end signal
        unsigned int responseLen = sizeof(response);
        unsigned int sent = 0;
        while (sent < responseLen) {
            int s = send(clientSocket, ((char *)&response) + sent, responseLen - sent, 0);
            if (s <= 0) return 0;
            sent += s;
        }
        return 1;
    }

    printf("(LodiServer) User %u follows %d users\n", msg->userID, userList->followingCount);

    int feedPostCount = 0;

    // Iterate through all posts and send each one that matches
    for (int i = 0; i < postCount; i++) {
        // Check if this post is from someone the user follows
        int isFollowing = 0;
        for (int j = 0; j < userList->followingCount; j++) {
            if (posts[i].userID == userList->following[j]) {
                isFollowing = 1;
                break;
            }
        }

        if (isFollowing) {
            feedPostCount++;

            // Format the post message
            snprintf(response.message, sizeof(response.message),
                    "User %u: %s", posts[i].userID, posts[i].message);

            printf("(LodiServer) Sending post %d: %s\n", feedPostCount, response.message);

            // Send this post
            unsigned int responseLen = sizeof(response);
            unsigned int sent = 0;
            while (sent < responseLen) {
                int s = send(clientSocket, ((char *)&response) + sent, responseLen - sent, 0);
                if (s <= 0) {
                    printf("(LodiServer) Error sending post\n");
                    return 0;
                }
                sent += s;
            }
        }
    }

    printf("(LodiServer) Found %d posts from followed users\n", feedPostCount);

    // Send end-of-feed signal
    strcpy(response.message, "END_OF_FEED");
    unsigned int responseLen = sizeof(response);
    unsigned int sent = 0;
    while (sent < responseLen) {
        int s = send(clientSocket, ((char *)&response) + sent, responseLen - sent, 0);
        if (s <= 0) {
            printf("(LodiServer) Error sending end signal\n");
            return 0;
        }
        sent += s;
    }

    printf("(LodiServer) Feed sent successfully (%d posts)\n", feedPostCount);
    return 1;
}

// Handle logout request
void handleLogout(PClientToLodiServer *msg, LodiServerMessage *response) {
    printf("\n(LodiServer) --- HANDLE LOGOUT ---\n");
    printf("(LodiServer) User %u logging out\n", msg->userID);

    // Send success response
    response->messageType = ackLogout;
    response->userID = msg->userID;
    strcpy(response->message, "Logout successful. Goodbye!");

    printf("(LodiServer) User %u has logged out\n", msg->userID);
    printf("(LodiServer) Logout processed successfully\n");
}

int main(int argc, char *argv[]) {
    int sock;
    int tcpServSock;
    int tcpClntSock;
    struct sockaddr_in lodiServerAddr;
    struct sockaddr_in tcpServerAddr;
    struct sockaddr_in clientAddr;
    unsigned int clientAddrLen;
    unsigned short lodiServerPort;
    char *pkeServerIP;
    unsigned short pkeServerPort;
    char *tfaServerIP;
    unsigned short tfaServerPort;
    PClientToLodiServer incomingMsg;
    int recvMsgSize;
    unsigned long n = 533;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <IP Address>\n", argv[0]);
        exit(1);
    }
    
    lodiServerPort = 2926; 
    pkeServerIP = argv[1];
    pkeServerPort = 2924;
    tfaServerIP = argv[1];
    tfaServerPort = 2925;
    
    printf("(LodiServer) Lodi Server: \n");
    printf("(LodiServer) Listening on port: %u\n", lodiServerPort);
    printf("(LodiServer) RSA Modulus (n): %lu\n", n);
    printf("\n\n");
    
    // Socket creation for UDP (used to contact PKE/TFA servers)
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("(LodiServer) socket() failed");

    // TCP socket creation (listen for client connections)
    if ((tcpServSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        DieWithError("(LodiServer) TCP socket() failed");

    printf("(LodiServer) Sockets created successfully\n");

    // Configure UDP server address (for PKE/TFA)
    memset(&lodiServerAddr, 0, sizeof(lodiServerAddr));
    lodiServerAddr.sin_family = AF_INET;
    lodiServerAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    lodiServerAddr.sin_port = htons(lodiServerPort);

    // Bind UDP socket
    if (bind(sock, (struct sockaddr *)&lodiServerAddr, sizeof(lodiServerAddr)) < 0)
        DieWithError("(LodiServer) bind() failed");

    printf("(LodiServer) UDP Socket bound to port %u\n", lodiServerPort);

    // Configure TCP server address
    memset(&tcpServerAddr, 0, sizeof(tcpServerAddr));
    tcpServerAddr.sin_family = AF_INET;
    tcpServerAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    tcpServerAddr.sin_port = htons(lodiServerPort);

    // Bind TCP listening socket
    if (bind(tcpServSock, (struct sockaddr *)&tcpServerAddr, sizeof(tcpServerAddr)) < 0)
        DieWithError("(LodiServer) bind() for TCP failed");

    if (listen(tcpServSock, MAXPENDING) < 0)
        DieWithError("(LodiServer) listen() failed");

    printf("(LodiServer) TCP Socket listening on port %u\n", lodiServerPort);
    printf("(LodiServer) Lodi Server ready and listening...\n\n");

    // loop
    for (;;) {
        clientAddrLen = sizeof(clientAddr);

        printf("(LodiServer) Waiting for client TCP connection...\n");

        if ((tcpClntSock = accept(tcpServSock, (struct sockaddr *)&clientAddr, &clientAddrLen)) < 0)
            DieWithError("(LodiServer) accept() failed");

        printf("(LodiServer) TCP connection from %s:%d\n",
               inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));

        // Receive the login struct over TCP (handle partial reads)
        unsigned int expected = sizeof(incomingMsg);
        unsigned int totalBytesRcvd = 0;
        char *recvPtr = (char *)&incomingMsg;
        while (totalBytesRcvd < expected) {
            int r = recv(tcpClntSock, recvPtr + totalBytesRcvd, (int)(expected - totalBytesRcvd), 0);
            if (r < 0) {
                close(tcpClntSock);
                DieWithError("(LodiServer) recv() failed");
            }
            if (r == 0) break; // connection closed
            totalBytesRcvd += r;
        }

        if (totalBytesRcvd < expected) {
            close(tcpClntSock);
            printf("(LodiServer) Incomplete login message received (got %u of %u)\n", totalBytesRcvd, expected);
            continue;
        }

        recvMsgSize = totalBytesRcvd;
        
        printf("(LodiServer) Received %d bytes from %s:%d\n",
               recvMsgSize,
               inet_ntoa(clientAddr.sin_addr),
               ntohs(clientAddr.sin_port));

        printf("(LodiServer) Message type: %d from User ID: %u\n",
               incomingMsg.messageType, incomingMsg.userID);
        printf("(LodiServer) Timestamp: %lu\n", incomingMsg.timestamp);
        printf("(LodiServer) Digital Signature: %lu\n", incomingMsg.digitalSig);

        // Route message based on type
        if (incomingMsg.messageType == login) {
            printf("(LodiServer) Processing LOGIN request\n");

        // verify timestamp
        unsigned long currentTime = time(NULL) % 500;
        long timeDiff = (long)(currentTime - incomingMsg.timestamp);

        printf("\n(LodiServer) Verifying timestamp...\n");
        printf("(LodiServer) Current time: %lu\n", currentTime);
        printf("(LodiServer) Time difference: %ld seconds\n", timeDiff);

        if (abs(timeDiff) > MAX_TIMESTAMP_DIFF) {
            printf("(LodiServer) FAILED: Timestamp too old or invalid\n");
            printf("[Auth] Rejecting login from user %u\n\n", incomingMsg.userID);
            continue;
        }
        printf("(LodiServer) SUCCESS: Timestamp is valid\n");

        // Verify using PKE Server
        printf("\n(LodiServer) Verifying digital signature...\n");
        
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

        // Require TFA
        printf("(LodiServer) Requesting Two-Factor Authentication\n");
        int tfa_ok = requestTFAAuthentication(
            sock,
            tfaServerIP,
            tfaServerPort,
            incomingMsg.userID
        );
        if (!tfa_ok) {
            printf("(LodiServer) FAILED: TFA authentication for user %u\n", incomingMsg.userID);
            continue;
        }
        printf("(LodiServer) SUCCESS: TFA approved for user %u\n", incomingMsg.userID);
       
        
        printf("\n(LodiServer) All authentication steps passed!\n");
        printf("(LodiServer) Sending ackLogin to client...\n");

        LodiServerMessage ackMsg;
        ackMsg.messageType = ackLogin;
        ackMsg.userID = incomingMsg.userID;
        strcpy(ackMsg.message, "Login successful");
        
        // Ack Client over the accepted TCP connection
        unsigned int ackLen = sizeof(ackMsg);
        unsigned int sent = 0;
        char *sendPtr = (char *)&ackMsg;
        while (sent < ackLen) {
            int s = send(tcpClntSock, sendPtr + sent, ackLen - sent, 0);
            if (s <= 0) {
                printf("(LodiServer) Error: Failed to send ackLogin\n");
                break;
            }
            sent += s;
        }

        if (sent == ackLen) {
            printf("(LodiServer) ackLogin sent to %s:%d\n",
                   inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
            printf("(LodiServer) User %u successfully authenticated!\n", incomingMsg.userID);
        }

        close(tcpClntSock);

        } else {
            // Handle non-login messages (post, feed, follow, unfollow, logout)
            printf("(LodiServer) Processing non-login request\n");

            // Special handling for feed - it sends multiple responses
            if (incomingMsg.messageType == feed) {
                handleFeedMultiple(&incomingMsg, tcpClntSock, &clientAddr);
                close(tcpClntSock);
            } else {
                // Handle other message types normally (single response)
                LodiServerMessage response;

                // Route to appropriate handler based on message type
                switch (incomingMsg.messageType) {
                    case post:
                        handlePost(&incomingMsg, &response);
                        break;
                    case follow:
                        handleFollow(&incomingMsg, &response);
                        break;
                    case unfollow:
                        handleUnfollow(&incomingMsg, &response);
                        break;
                    case logout:
                        handleLogout(&incomingMsg, &response);
                        break;
                    default:
                        printf("(LodiServer) Error: Unknown message type %d\n", incomingMsg.messageType);
                        response.messageType = ackLogin; // Use ackLogin as error response
                        response.userID = incomingMsg.userID;
                        strcpy(response.message, "Error: Unknown message type");
                        break;
                }

                // Send response back to client
                unsigned int responseLen = sizeof(response);
                unsigned int sent = 0;
                char *sendPtr = (char *)&response;
                while (sent < responseLen) {
                    int s = send(tcpClntSock, sendPtr + sent, responseLen - sent, 0);
                    if (s <= 0) {
                        printf("(LodiServer) Error: Failed to send response\n");
                        break;
                    }
                    sent += s;
                }

                if (sent == responseLen) {
                    printf("(LodiServer) Response sent to %s:%d\n",
                           inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
                }

                close(tcpClntSock);
            }
        }

    }
    
    close(sock);
    return 0;
}
