package se.wahlstromstekniska.acetest.authorizationserver.resource;

import java.security.Key;

import org.apache.log4j.Logger;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.RequestProcessor;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKey.OutputControlLevel;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.ByteUtil;

import se.wahlstromstekniska.acetest.authorizationserver.AccessToken;
import se.wahlstromstekniska.acetest.authorizationserver.ClientAuthentication;
import se.wahlstromstekniska.acetest.authorizationserver.Constants;
import se.wahlstromstekniska.acetest.authorizationserver.ErrorResponse;
import se.wahlstromstekniska.acetest.authorizationserver.JWT;
import se.wahlstromstekniska.acetest.authorizationserver.ResourceServer;
import se.wahlstromstekniska.acetest.authorizationserver.ServerConfiguration;
import se.wahlstromstekniska.acetest.authorizationserver.exception.RequestException;


public class TokenResource extends CoapResource {
    
	final static Logger logger = Logger.getLogger(TokenResource.class);
	private static ServerConfiguration config = ServerConfiguration.getInstance();

    public TokenResource() {
        super("token");
        getAttributes().setTitle("OAuth2 Token Endpoint for CoAP");
        
        logger.info("Token endpoints initiated.");
    }

    @Override
    public void handlePOST(CoapExchange exchange) {
        
    	// TODO: refactor this method. Big time.
    	
		logger.info("Request: " + exchange.getRequestText());
		int contentFormat = exchange.getRequestOptions().getContentFormat();
		
    	// take request and turn it into a TokenRequest object
    	byte[] payload = exchange.getRequestPayload();
    	TokenRequest tokenRequest  = null;
    	try {
    		tokenRequest = new TokenRequest(payload, contentFormat);
    	} catch (Exception e) {
    		// request is not valid (missing mandatory attributes)
			logger.info("Could not parse request: " + e.getMessage());
			e.printStackTrace();
    		exchange.respond(ResponseCode.BAD_REQUEST, ErrorResponse.getInvalidRequest());
    		return;
    	}

    	try {
    		
	    	if(!tokenRequest.validateRequest()) {
	    		// request is not valid (the values of the sent attributes is not valid)
				logger.info("Request is not valid.");
	
	    		exchange.respond(ResponseCode.BAD_REQUEST, ErrorResponse.getInvalidRequest());
	    	}
	    	else {
	        	// validate client credentials
	    		ClientAuthentication auth = new ClientAuthentication();
	        	boolean authenticated = auth.authenticate(tokenRequest.getClient_id(), tokenRequest.getClient_secret());
	
	        	if(authenticated) {
	
	        		// does user have access to the resource server
	        		ResourceServer rs = config.getResourceServer(tokenRequest.getAud());
	        		if(rs != null) {
		    			logger.info("Found requested Resource Server in Authorization Servers control.");
	
	        			if(rs.isClientAuthorized(tokenRequest.getClient_id())) {
	        				
	        				// check scopes
	        				// TODO: don't check just as a string, look at each space separated scope.
	        				if(rs.getScopes().equals(tokenRequest.getScopes())) {
	    		    			logger.info("Client is authorized to get token with scopes: " + tokenRequest.getScopes());
		        					
		        				// generate a token for the client against the resource.
				    			logger.info("Client " + tokenRequest.getClient_id() + " is authorized to get token for the resource server " + rs.getAud());
		
				    			logger.info("Minting a new access token.");
		
								try {
	
									AccessToken token = null;
									String serializedJwe = "";
									
									if(rs.getTokenFormat() == ResourceServer.TOKEN_FORMAT_JWT) {
										// get authorization servers signing key
				        				JWT jwt = new JWT();
	
										// TODO: Get a better key generation, this is just copy paste from jose4j examples
				        				// get key from client and if none, generate keys on AS and return encrypted keys to client
										JsonWebKey clientsPublicKey = tokenRequest.getRawKey(); 
										if(clientsPublicKey == null) {
											clientsPublicKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
											clientsPublicKey.setKeyId("asgeneratedKey");
										}
				        				
										Key key = new AesKey(ByteUtil.randomBytes(16));
										JsonWebEncryption jwe = new JsonWebEncryption();
										jwe.setPayload(clientsPublicKey.toJson(OutputControlLevel.INCLUDE_PRIVATE));
										jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW);
										jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
										jwe.setKey(key);
	
										token = jwt.generateJWT(config.getSignAndEncryptKey(), rs.getAud(), rs.getScopes(), clientsPublicKey);
										serializedJwe = jwe.getCompactSerialization();
									}
									else {
										throw new Exception("CWT not implemented yet.");
									}
			        				
									TokenResponse response = null;
									if(tokenRequest.getRawKey() != null) {
										response = new TokenResponse(token, Constants.tokenTypePOP, rs.getCsp(), null);
									}
									else {
										logger.error("Serialized Encrypted JWE: " + serializedJwe);
										response = new TokenResponse(token, Constants.tokenTypePOP, rs.getCsp(), serializedJwe);
									}
			        				
			        				byte[] responsePayload = response.toPayload(contentFormat);
					    			logger.info("Response: " + new String(responsePayload));
		
					    			// store the access token in list of valid access tokens on the resource server(s) that's affected
					    			rs.addAccessToken(token);
					    			
					    			exchange.respond(ResponseCode.CONTENT, responsePayload, contentFormat);
		
								} catch (Exception e1) {
									logger.error("Could not generate token." + e1.getMessage());
									e1.printStackTrace();
					        		exchange.respond(ResponseCode.INTERNAL_SERVER_ERROR, ErrorResponse.getInternalServerError());
								}
	        				}
	        				else {
		        				// wrong type of scopes
								logger.info("Invalid scopes.");
				        		exchange.respond(ResponseCode.BAD_REQUEST, ErrorResponse.getInvalidScope());
	        				}

	        			}
	        			else {
	        				// client is not authorized to get tokens for the resource server
							logger.info("Client " + tokenRequest.getClient_id() + " is not authorized to get token for resource server " + rs.getAud() + ".");
			        		exchange.respond(ResponseCode.BAD_REQUEST, ErrorResponse.getUnauthorizedClient());
	        			}
	        		}
	        		else {
	        			// resource server don't exist.
						logger.info("Resource Server " + tokenRequest.getAud() + " is not managed by the authorization server.");
		        		exchange.respond(ResponseCode.BAD_REQUEST, ErrorResponse.getUnauthorizedClient());
	        		}
	        		
	        		
	        	}
	        	else {
	        		// wrong creds client was not authenticated successfully, return errors
	        		// TODO: if JSON, return JSON otherwise CBOR.
					logger.info("Client was not authenticated successfully.");
	
	        		exchange.respond(ResponseCode.BAD_REQUEST, ErrorResponse.getUnauthorizedClient());
	        	}
	    	}
    	} catch (RequestException e) {
    		if(e.getReason() == RequestException.MISSING_GRANT) {
        		exchange.respond(ResponseCode.BAD_REQUEST, ErrorResponse.getInvalidGrant());
    		}
    		
    		exchange.respond(ResponseCode.BAD_REQUEST, ErrorResponse.getUnauthorizedClient());
    	}
    	

    }
    
}    
    