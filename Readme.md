# Computer Security Project: Secure(?) Chat

## Team Members

- Myesha Mahazabeen
- Najia Jahan

## Project Description
This project is designed to provide secure communication between users over a network. The program emphasizes authentication of correspondents, message secrecy through encryption, and message integrity using Message Authentication Codes (MACs). 
It aims to foster familiarity with cryptographic libraries, protocol design, network programming, and software security principles.

## Key Features
- Encryption: Messages are encrypted to keep them private.
- Authentication: Mutual authentication ensures the identity of users.
- Integrity: Messages are tagged to detect tampering.
- Forward Secrecy: Ephemeral keys provide extra security.
- Deniable Authentication: Users can authenticate without leaving traces.

## Modifications 
To enhance the security of the chat application, the following modifications have been made in the back-end (chat.c):

- generateEphemeralKey: Added a function to generate ephemeral keys for the session using the Diffie-Hellman key exchange mechanism provided by the dh.h header.

- exchangeKeys: Implemented a function to handle the exchange of keys between the client and server. It serializes the keys using the mpz_serialize function from the util.h header and sends them over the network.

- computeSharedSecret: Introduced a function to compute the shared secret using the Diffie-Hellman key exchange mechanism. It takes the local private key, the local public key, and the remote public key as input and computes the shared secret.

- encryptMessage: Developed a function to encrypt a message using the shared secret computed during the key exchange phase. Utilizes symmetric encryption with AES in CBC mode provided by the OpenSSL library.

- decryptMessage: Implemented a function to decrypt a message using the shared secret. Performs the reverse operation of the encryptMessage function.

- authenticate: Implemented mutual authentication between the client and server using public key cryptography. It signs a message with the private key and verifies the signature using the public key.

## Getting Started

We have used MacOS system for this project

- Clone the github repo and open the terminal
- Ensure you have the necessary dependencies installed, including OpenSSL, GTK, GMP, and GTK3
- Compile the source code using the provided Makefile. Run make to build the executable files
- Start the server by running ./chat -h and then ./chat -l & sleep 1 && ./chat -c localhost &
