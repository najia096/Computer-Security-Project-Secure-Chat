#include "dh.h"
#include "keys.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_MESSAGE_LENGTH 256
#define AES_KEY_LENGTH 128
#define HMAC_KEY_LENGTH 32
#define HMAC_DIGEST_LENGTH 32
#define PORT 8080

int sockfd;

// Function to establish connection with the server
void establishConnection()
{
	struct sockaddr_in servaddr;
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);
	if (inet_pton(AF_INET, "127.0.0.1", &servaddr.sin_addr) <= 0)
	{
		perror("Invalid address/ Address not supported");
		exit(EXIT_FAILURE);
	}
	if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
	{
		perror("Connection Failed");
		exit(EXIT_FAILURE);
	}
}

// Function to perform the handshake for establishing secure communication
void performHandshake()
{
	// Establish connection with the server
	establishConnection();

	// Generate Diffie-Hellman key pair
	dhKey clientKey;
	initKey(&clientKey);
	dhGenk(&clientKey);

	// Serialize and send client's public key to server
	unsigned char serializedKey[MAX_MESSAGE_LENGTH];
	serializeKey(clientKey.PK, serializedKey, MAX_MESSAGE_LENGTH);
	send(sockfd, serializedKey, MAX_MESSAGE_LENGTH, 0);

	// Receive server's public key
	unsigned char serverKey[MAX_MESSAGE_LENGTH];
	recv(sockfd, serverKey, MAX_MESSAGE_LENGTH, 0);
	deserializeKey(serverKey, MAX_MESSAGE_LENGTH, clientKey.PK);

	// Generate shared secret
	mpz_t sharedSecret;
	NEWZ(sharedSecret);
	computeSharedSecret(clientKey.SK, clientKey.PK, clientKey.PK, sharedSecret);

	// Perform mutual authentication
	int authenticated = mutualAuthentication(sharedSecret, sharedSecret);
	if (authenticated)
	{
		printf("Mutual authentication successful.\n");
	}
	else
	{
		printf("Mutual authentication failed.\n");
		exit(EXIT_FAILURE);
	}

	// Clean up resources
	shredKey(&clientKey);
	mpz_clear(sharedSecret);
}

// Function to send an encrypted message to the server
void sendEncryptedMessageToServer(unsigned char *encryptedMessage, size_t length)
{
	send(sockfd, encryptedMessage, length, 0);
}

// Function to receive an encrypted message from the server
void receiveEncryptedMessageFromServer(unsigned char *encryptedMessage, size_t length)
{
	recv(sockfd, encryptedMessage, length, 0);
}

int main()
{
	// Perform handshake to establish secure communication
	performHandshake();

	// Example: sending and receiving encrypted messages
	unsigned char aesKey[AES_KEY_LENGTH / 8];
	unsigned char hmacKey[HMAC_KEY_LENGTH];
	generateKeys(aesKey, hmacKey);

	// Example message to send
	const char *messageToSend = "Hello, server!";

	// Send message to server
	unsigned char encryptedMessage[MAX_MESSAGE_LENGTH];
	encryptMessage(messageToSend, aesKey, encryptedMessage);
	sendEncryptedMessageToServer(encryptedMessage, strlen((char *)encryptedMessage));

	// Receive and decrypt message from server
	unsigned char receivedEncryptedMessage[MAX_MESSAGE_LENGTH];
	receiveEncryptedMessageFromServer(receivedEncryptedMessage, MAX_MESSAGE_LENGTH);
	char decryptedMessage[MAX_MESSAGE_LENGTH];
	decryptMessage(receivedEncryptedMessage, aesKey, decryptedMessage);
	printf("Received message from server: %s\n", decryptedMessage);

	// Clean up resources
	close(sockfd);

	return 0;
}
