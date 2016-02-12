# acetest
A proof of concept of authorization based on OAuth2 for Constrained IoT devices defined in https://datatracker.ietf.org/doc/draft-ietf-ace-oauth-authz/

Do NOT use in production.

NOTE: Requires a patch for the DTLS library Scandium. Contact me for patch.

## Configuration
Run the SystemSetup and it will automatically create dummy configurations for AS, RS and C.

## Authorization Server
CoAPS based OAuth2 Authorization Server. Supports client authentication using DTLS PSK and also exposes a plain text CoAP server to be used for request protected with object security.

Authorization Server supports symmetric and assymetric proof of possession tokens and uses JSON/JWT as payload formats. 

Support the following resources:
- /token 
- /introspection

Startup:
- Run CoAPAuthorizationServer for a non-protected CoAP server.
- Run CoAPSAuthorizationServer for a DTLS PSK protected CoSPS server.

## Resource Server

A Resource Server acting as a temperature sensor by returning the current room temperature. 

Support the following resources:
- /authz-info
- /temperature

Startup:
- Run ResourceServerPSK to deliver a temperature reading to an authorized client using DTLS PSK, uses local verification of the access token.
- Run ResourceServerRPK to deliver a temperature reading to an authorized client using DTLS RPK, uses the /introspection resource to validate access token.

## Client

Authenticates against Authorization Server using DTLS PSK. Gets an proof of possession access token. Calls an /authz-info resource on the Resoruce Server then makes an DTLS protected call against the /temperature endpoint.

Startup:
- Run ClientPSK to prove possesion of an, by AS generated, symmetric key against the RS using DTLS PSK.
- Run ClientRPK to prove possesion of an, by the client generated, assymetric key against the RS using DTLS RPK.

