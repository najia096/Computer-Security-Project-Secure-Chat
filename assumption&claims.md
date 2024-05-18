# Security Assumptions and Claims for Secure Chat Program
# Assumptions
- Pre-exchanged Public Keys: Communicating parties have securely exchanged their public keys prior to starting a session.
- Secure Key Storage: Public and private keys are securely stored on each device.
- Authenticated DH Parameters: Diffie-Hellman parameters are agreed upon and securely exchanged beforehand.
- Trusted Execution Environment: The chat application runs in a secure environment free from compromise.
- Adversary's Capabilities: Adversaries can intercept and tamper with messages but cannot break cryptographic primitives or access private keys.
## Claims
### Integrity
- Message Integrity: Messages are tagged with a Message Authentication Code (MAC), ensuring tampering is detected.
### Confidentiality
- Message Confidentiality: Messages are encrypted using AES in CBC mode with a session-specific shared secret, ensuring privacy.
### Mutual Authentication
- Mutual Authentication: Both client and server authenticate each other using their public keys, preventing impersonation.
### Deniable Authentication
- Deniable Authentication: Supports deniable authentication, allowing users to plausibly deny having sent a message.
### Malicious Communicating Party
- Handling Malicious Parties: Malicious parties cannot forge valid MACs, decrypt messages, or impersonate others. They may cause denial of service but cannot compromise message integrity or confidentiality.
## Conclusion
Our secure chat program ensures message integrity, confidentiality, and mutual authentication, protecting against tampering, eavesdropping, and impersonation even in the presence of malicious actors.
