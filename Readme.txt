Ephemeral Key Generation
Added code to generate ephemeral keys for each session.
Used functions from dh.h to generate these keys.
Serialized these keys into byte arrays using serializeKey function.

Key Exchange
Utilized functions from util.h to exchange the ephemeral keys securely.
Ensured that both client and server exchanged their ephemeral keys reliably.

For chat.c
Added #include Directives: Included necessary header files such as <openssl/rand.h> to resolve implicit declaration errors for OpenSSL functions like RAND_bytes.
Implementation of encryptAndSendMessage: Implemented the encryptAndSendMessage function as per the requirements specified. This function encrypts the message using AES with CBC mode and computes an HMAC for message authentication.
Modifications to performKeyExchangeAndAuthentication: Updated the function to perform key exchange and authentication based on the provided requirements. This includes generating ephemeral keys, exchanging keys with the other party, and sending/receiving long-term keys.
Modifications to sendMessage: Updated the function to perform key exchange and authentication before encrypting and sending the message. Also, modified the message sending mechanism to match the protocol's requirements.
Other Fixes: Fixed compilation errors related to undeclared functions and variables, such as serializeKey, deserializeKey, and shared_secret. Additionally, fixed some warning messages and provided placeholder implementations for functions like serializeKey and deserializeKey.
