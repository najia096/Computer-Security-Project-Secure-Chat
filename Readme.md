###Computer Security Project: Secure(?) Chat

## Team Members

- Myesha Mahazabeen
- Najia Jahan

## Project Description
This project is designed to provide secure communication between users over a network. The program emphasizes authentication of correspondents, message secrecy through encryption, and message integrity using Message Authentication Codes (MACs). 
It aims to foster familiarity with cryptographic libraries, protocol design, network programming, and software security principles.

## Key Features

- End-to-End Encryption: Messages exchanged between clients and the server are encrypted using AES with CBC mode, ensuring confidentiality.
- Message Authentication: Each message is tagged with a Message Authentication Code (MAC) to detect any tampering or unauthorized changes.
- Perfect Forward Secrecy: Ephemeral keys are generated for each session using the Diffie-Hellman key exchange protocol, providing perfect forward secrecy.
- Mutual Authentication: Clients and the server mutually authenticate each other using public-key cryptography, ensuring the identity of the communicating parties.

## Getting Started

We have used MacOS system for this project

- Clone the github repo and open the terminal.
- Ensure you have the necessary dependencies installed, including OpenSSL, GTK, GMP, and GTK3
- Compile the source code using the provided Makefile. Run make to build the executable files
- Start the server by running ./chat -h and then ./chat -l & sleep 1 && ./chat -c localhost &
