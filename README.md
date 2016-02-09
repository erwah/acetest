# acetest
Just a test. Do not use in production.

Authorization Server supports symmetric and assymetric pop tokens and uses JSON/JWT as formats. The client proves possessions of keys using DTLS PSK or DTLS RPK.

## Configuration
Run the main method in systemsetup/src/main/java/se/wahlstromstekniska/acetest/systemsetup/SystemSetup.java and it will automatically create dummy configurations for AS, RS and C.

## Servers and clients

### Authorization Server
- Run CoAPAuthorizationServer for a non-protected CoAP server.
- Run CoAPSAuthorizationServer for a DTLS PSK protected CoSPS server.

### Client
- Run ClientPSK to prove possesion of an, by AS generated, symmetric key against the RS using DTLS PSK.
- Run ClientRPK to prove possesion of an, by the client generated, assymetric key against the RS using DTLS RPK.

### Resource Server
- Run ResourceServerPSK to deliver a temperature reading to an authorized client using DTLS PSK.
- Run ResourceServerRPK to deliver a temperature reading to an authorized client using DTLS RPK.

