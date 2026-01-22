What I Learned: TLS Proxying, Attacks, and Defenses

This project implements a simple TLS proxy using Mbed TLS library. Building the proxy with TLS 
provided hands-on learning to understand how TLS interception works as well as real world
man-in-the-middle attacks.

TLS Proxy Attack:
  - Attacker places themselves between client and server by establishing a TLS connection with
    target server and accepting HTTP request                                             traffic from the client.
  - Then the proxy forwords requests and responses between both parties.
  - The proxys man-in-the-middle can view, modify, or block traffic from the client to the server.

Common scenarios:
  - Downgrade or weaken certificate verifcation
  - Install a malicious or untrusted root CA
  - Denile-of-service or traffic manipulation attacks

TLS Proxy Defense:
  - Enforce strict certificate verifcation (VERIFY_REQUIRED)
  - Minimize and control access to trusted root certificates
  - Inspect the certificate verification results

Building and Running the TLS Proxy
  - Clone the repositoty and build the project: git clone https://github.com/lmannhardt23/tlsproxyC.git
  - cd tlsproxyC
  - make (Windowns: use WSL, or choco install make)
  - Then: ./tlsproxy <listen_port> <target_host> <target_port>
  - Example: ./tlsproxy 1024 www.lwn.net 443
  - Open a browser and navigate to http://localhost:1024
  - OPTIONAL: Running the provided service-tlsproxy
    - ./service-tlsproxy -p 2048
    - ./tlsproxy 1024 localhost 2048
    - Open a browser and navigate to http://localhost:1024
    - Should see Sanitized.
