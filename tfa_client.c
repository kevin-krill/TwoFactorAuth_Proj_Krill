#include <stdio.h>      
#include <sys/socket.h> 
#include <arpa/inet.h>  
#include <stdlib.h>     
#include <string.h>    
#include <unistd.h>     
#include <time.h>       

void DieWithError(char *errorMessage)
{
	perror(errorMessage);
	exit(1);
}

// Structs
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

// Function to Register w TFAServ
void registerWithTFAServer(int sock, struct sockaddr_in *tfaServAddr,
                           unsigned int userID, unsigned long privateKey, unsigned long n)
{
    TFAClientOrLodiServerToTFAServer registerMsg, ackMsg;
    TFAServerToTFAClient confirmMsg;
    unsigned long randomInt;
    unsigned int fromSize;
    int recvMsgSize;
    
    printf("(TFAClient) TFA Client Registration\n");
    printf("(TFAClient) User ID: %u\n", userID);
    
    // Timestamp 
    randomInt = time(NULL) % 500;
    printf("(TFAClient) Generated timestamp: %lu\n", randomInt);
    
    // Create DS
    registerMsg.messageType = registerTFA;
    registerMsg.userID = userID;
    registerMsg.timestamp = randomInt;
    registerMsg.digitalSig = modExp(randomInt, privateKey, n);
    
    printf("(TFAClient) Digital signature: %lu\n", registerMsg.digitalSig);
    printf("(TFAClient) Sending registerTFA to TFA Server...\n");
    
    // Register TFAServ message
    if (sendto(sock, &registerMsg, sizeof(registerMsg), 0,
               (struct sockaddr *)tfaServAddr, sizeof(*tfaServAddr)) != sizeof(registerMsg))
        DieWithError("(TFAClient) sendto() sent a different number of bytes than expected");
    
    // TFAServ confimation message
    fromSize = sizeof(*tfaServAddr);
    if ((recvMsgSize = recvfrom(sock, &confirmMsg, sizeof(confirmMsg), 0,
                                (struct sockaddr *)tfaServAddr, &fromSize)) < 0)
        DieWithError("(TFAClient) recvfrom() failed");
    
    if (confirmMsg.messageType != confirmTFA || confirmMsg.userID != userID)
    {
        fprintf(stderr, "(TFAClient) Error: Invalid confirmTFA message received\n");
        exit(1);
    }
    
    printf("(TFAClient) Received confirmTFA from TFA Server\n");
    
    // Send ackTFA 
    ackMsg.messageType = ackRegTFA;
    ackMsg.userID = userID;
    ackMsg.timestamp = 0;
    ackMsg.digitalSig = 0;
    
    printf("(TFAClient) Sending ackRegTFA to TFA Server...\n");
    
    if (sendto(sock, &ackMsg, sizeof(ackMsg), 0,
               (struct sockaddr *)tfaServAddr, sizeof(*tfaServAddr)) != sizeof(ackMsg))
        DieWithError("(TFAClient) sendto() sent a different number of bytes than expected");
    
    printf("(TFAClient) Registration complete!\n");
}

// Listen for push 
void listenForPushNotifications(int sock, struct sockaddr_in *tfaServAddr,
                                unsigned int userID)
{
    TFAServerToTFAClient pushMsg;
    TFAClientOrLodiServerToTFAServer ackMsg;
    struct sockaddr_in fromAddr;
    unsigned int fromSize;
    int recvMsgSize;
    char response[10];
    
    printf("(TFAClient) TFA Client Listening \n");
    printf("(TFAClient) User ID: %u\n", userID);
    printf("(TFAClient) Waiting for push notifications...\n");
    
    
    
    for (;;) 
    {
        // Receive push
        fromSize = sizeof(fromAddr);
        if ((recvMsgSize = recvfrom(sock, &pushMsg, sizeof(pushMsg), 0,
                                    (struct sockaddr *)&fromAddr, &fromSize)) < 0)
            DieWithError("(TFAClient) recvfrom() failed");
        
        printf("(TFAClient) Push Notification Received\n");
        printf("(TFAClient) From: %s:%d\n", inet_ntoa(fromAddr.sin_addr), ntohs(fromAddr.sin_port));
        
        // Verify
        if (pushMsg.messageType != pushTFA)
        {
            printf("(TFAClient) Error: Received non-push message (type=%d)\n", pushMsg.messageType);
            continue;
        }
        
        if (pushMsg.userID != userID)
        {
            printf("(TFAClient) Error: Push notification for different user (ID=%u)\n", pushMsg.userID);
            continue;
        }
        
        printf("(TFAClient) User ID: %u\n", pushMsg.userID);
        
        // Prompt user
        printf("\n(TFAClient) Authentication request received!\n");
        printf("(TFAClient) Approve this login? (yes/no): ");
        fflush(stdout);
        
        if (fgets(response, sizeof(response), stdin) != NULL)
        {
            response[strcspn(response, "\n")] = 0;
            if (strcmp(response, "yes") == 0)
            {
                printf("(TFAClient) Approved! Sending ackPushTFA...\n");
                
                // Send ackPush
                ackMsg.messageType = ackPushTFA;
                ackMsg.userID = userID;
                ackMsg.timestamp = 0;
                ackMsg.digitalSig = 0;
                
                if (sendto(sock, &ackMsg, sizeof(ackMsg), 0,
                           (struct sockaddr *)&fromAddr, sizeof(fromAddr)) != sizeof(ackMsg))
                    DieWithError("sendto() sent a different number of bytes than expected");
                
                printf("(TFAClient) ackPushTFA sent to TFA Server\n");
            }
            else
            {
                printf("(TFAClient) Denied! Sending denyPushTFA to TFA Server...\n");

                // Send deny ack so the TFA server knows user rejected
                ackMsg.messageType = denyPushTFA;
                ackMsg.userID = userID;
                ackMsg.timestamp = 0;
                ackMsg.digitalSig = 0;

                if (sendto(sock, &ackMsg, sizeof(ackMsg), 0,
                           (struct sockaddr *)&fromAddr, sizeof(fromAddr)) != sizeof(ackMsg))
                    DieWithError("(TFAClient) sendto() sent a different number of bytes than expected");

                printf("(TFAClient) denyPushTFA sent to TFA Server\n");
            }
        }
        
        printf("\n(TFAClient) Waiting for push notifications...\n");
    }
}

int main(int argc, char *argv[])
{
    int sock;                        
    struct sockaddr_in tfaServAddr;  
    unsigned short tfaServPort;      
    char *servIP;                    
    unsigned int userID;             
    unsigned long privateKey;        
    unsigned long n = 533;           
    struct sockaddr_in localAddr;    
    
    if (argc != 3)    
    {
        fprintf(stderr, "(TFAClient) Usage: %s <Server IP> <User ID> \n",
                argv[0]);
        exit(1);
    }
    
    servIP = argv[1];                
    tfaServPort = 2925;     
    userID = atoi(argv[2]);         
    privateKey = 37;    
    
    printf("(TFAClient) TFA Client\n");
    printf("(TFAClient) TFA Server: %s:%u\n", servIP, tfaServPort);
    printf("(TFAClient) User ID: %u\n", userID);
    printf("(TFAClient) Private Key: %lu\n", privateKey);
    printf("(TFAClient) RSA Modulus (n): %lu\n\n", n);
    
    // Create sock
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("(TFAClient) socket() failed");
    
    // Construct server address
    memset(&tfaServAddr, 0, sizeof(tfaServAddr));      
    tfaServAddr.sin_family = AF_INET;                  
    tfaServAddr.sin_addr.s_addr = inet_addr(servIP);  
    tfaServAddr.sin_port = htons(tfaServPort);         
    
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    localAddr.sin_port = htons(0);  
    
    // Bind
    if (bind(sock, (struct sockaddr *)&localAddr, sizeof(localAddr)) < 0)
        DieWithError("(TFAClient) bind() failed");
    
    // Get port  
    unsigned int addrLen = sizeof(localAddr);
    if (getsockname(sock, (struct sockaddr *)&localAddr, &addrLen) < 0)
        DieWithError("getsockname() failed");
    
    printf("Local port: %u\n\n", ntohs(localAddr.sin_port));
    
    // Register w TFAServ
    registerWithTFAServer(sock, &tfaServAddr, userID, privateKey, n);
    
    // Listen for push notis 
    listenForPushNotifications(sock, &tfaServAddr, userID);
    
    close(sock);
    exit(0);
}
