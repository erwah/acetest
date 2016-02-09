# acetest
Just a test. Do not use in production.

Authorization Server supports symmetric and assymetric pop tokens and uses JSON/JWT as formats. The client proves possessions of keys using DTLS PSK or DTLS RPK.

# Configuration

## Authorization Server
Copy authorizationserver/src/main/resources/config.json.example to config.json and make changes.

Run CoAPAuthorizationServer for a non-protected CoAP server.

Run CoAPSAuthorizationServer for a DTLS PSK protected CoSPS server.

## Client
Copy client/src/main/resources/client_config.json.example to client_config.json and make changes.

Run ClientPSK to prove possesion of an, by AS generated, symmetric key against the RS using DTLS PSK.

Run ClientRPK to prove possesion of an, by the client generated, assymetric key against the RS using DTLS RPK.

## Resource Server
Copy resourceserver/src/main/resources/resource_server_config.json.example to resource_server_config.json and make changes.

Run ResourceServerPSK to deliver a temperature reading to an authorized client using DTLS PSK.

Run ResourceServerRPK to deliver a temperature reading to an authorized client using DTLS RPK.

