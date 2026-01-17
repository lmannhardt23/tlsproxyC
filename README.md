What I Learned: TLS Proxying, Attacks, and Defenses

This project implements a simple TLS proxy using Mbed TLS. Building the proxy with TLS 
provided hands-on learning to understand how TLS interception works as well as real world
man-in-the-middle attacks.

TLS Proxy Attack:
  - Attacker places themselves between client and server by establishing a TLD connection with the client,
    and forwording responses to the server, so that the client is none the wiser.
  - The proxys man-in-the-middle can view, modify, or block traffic from the client to the server.

Common scenarios:
  - Downgrade or weaken certificate verifcation
  - Install a malicious or untrusted root CA
  - DOS attacks

TLS Proxy Defense:
  - Enforce strict certificate verifcation (VERIFY_REQUIRED)
  - Minimize and control access to trusted root certificates
  - Inspect the certificate verification results
