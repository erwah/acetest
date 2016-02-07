package se.wahlstromstekniska.acetest.authorizationserver.resource;

import java.security.SecureRandom;
import java.math.BigInteger;

import org.apache.log4j.Logger;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKey.OutputControlLevel;
import org.jose4j.jwk.OctJwkGenerator;

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
	private SecureRandom random = new SecureRandom();

	  
    public TokenResource() {
        super("token");
        getAttributes().setTitle("OAuth2 Token Resource for CoAP");
        
        logger.debug("Token resource initiated.");
    }

    public void handlePOST(CoapExchange exchange) {
            	
    	// TODO: refactor this method. Big time.
    	
		int contentFormat = exchange.getRequestOptions().getContentFormat();
    	byte[] payload = Exchange.getPayload(exchange, contentFormat);
    	
    	TokenRequest tokenRequest  = null;
    	try {
    		tokenRequest = new TokenRequest(payload, contentFormat);
    	} catch (Exception e) {
    		// request is not valid (missing mandatory attributes)
    		logger.info("Could not parse request.", e);
			// TODO: Change to cbor.
			try {
				Exchange.respond(exchange, ResponseCode.BAD_REQUEST, ErrorResponse.getInvalidRequest(MediaTypeRegistry.APPLICATION_JSON), MediaTypeRegistry.APPLICATION_JSON);
			} catch (Exception e1) {
				logger.error("Unknown error.", e);
			}
    		return;
    	}

    	try {
    		
	    	if(!tokenRequest.validateRequest()) {
	    		// request is not valid (the values of the sent attributes is not valid)
				logger.info("Request is not valid.");
	
				Exchange.respond(exchange, ResponseCode.BAD_REQUEST, ErrorResponse.getInvalidRequest(contentFormat), contentFormat);
	    	}
	    	else {
	        	// validate client credentials
	    		ClientAuthentication auth = new ClientAuthentication();
	        	boolean authenticated = auth.authenticate(tokenRequest.getClient_id(), tokenRequest.getClient_secret());
	
	        	if(authenticated) {
	
	        		// does user have access to the resource server
	        		ResourceServer rs = config.getResourceServer(tokenRequest.getAud());
	        		if(rs != null) {
	        			logger.debug("Found requested Resource Server in Authorization Servers control.");
	
	        			if(rs.isClientAuthorized(tokenRequest.getClient_id())) {
	        				
	        				// TODO: check scopes
	        				// TODO: don't check just as a string, look at each space separated scope.
	        				if(rs.getScopes().equals(tokenRequest.getScopes())) {
	        					logger.debug("Client is authorized to get token with scopes: " + tokenRequest.getScopes());
		        					
		        				// generate a token for the client against the resource.
	        					logger.debug("Client " + tokenRequest.getClient_id() + " is authorized to get token for the resource server " + rs.getAud());
		
								try {
									AccessToken token = null;
									String serializedJwe = "";
									String pskIdentity = "";
									
									if(rs.getTokenFormat() == ResourceServer.TOKEN_FORMAT_JWT) {
										// get authorization servers signing key
				        				JWT jwt = new JWT();
	
				        				// get key from client and if none, generate keys on AS and return encrypted keys to client
										JsonWebKey popKey = tokenRequest.getRawKey(); 
										if(popKey == null) {
											popKey = OctJwkGenerator.generateJwk(128);
											
											// generate a unique kid for the newly generated key
										    String kid = new BigInteger(130, random).toString(32);
											popKey.setKeyId(kid);

										}
										else {
											
										}
										
										// TODO: ENCRYPT THE SYMMETRIC KEY IN BOTH TOKEN AND IN RESPONSE!!!!!!
										
										// generate a unique PSK identity that's used by by the client when accessing the resource server
										pskIdentity = new BigInteger(130, random).toString(32);
										
										
										token = jwt.generateJWT(config.getSignAndEncryptKey(), rs.getAud(), rs.getScopes(), popKey, pskIdentity);
										serializedJwe = popKey.toJson(OutputControlLevel.INCLUDE_SYMMETRIC);
										
									}
									else {
										throw new Exception("CWT not implemented yet.");
									}
			        				
									TokenResponse response = null;
									if(tokenRequest.getRawKey() != null) {
										response = new TokenResponse(token, Constants.tokenTypePOP, rs.getCsp(), null, null, rs.getRPK());
									}
									else {
										response = new TokenResponse(token, Constants.tokenTypePOP, rs.getCsp(), serializedJwe, pskIdentity, null);
									}
			        				
			        				byte[] responsePayload = response.toPayload(contentFormat);
			        				logger.debug("Response: " + new String(responsePayload));
		
					    			// store the access token in list of valid access tokens on the resource server(s) that's affected
					    			rs.addAccessToken(token);
					    			
					    			Exchange.respond(exchange, ResponseCode.CONTENT, responsePayload, contentFormat);
		
								} catch (Exception e1) {
									logger.error("Could not generate token." + e1.getMessage());
									e1.printStackTrace();
									Exchange.respond(exchange, ResponseCode.INTERNAL_SERVER_ERROR, ErrorResponse.getInternalServerError(contentFormat), contentFormat);
								}
	        				}
	        				else {
		        				// wrong type of scopes
	        					logger.debug("Invalid scopes.");
								Exchange.respond(exchange, ResponseCode.BAD_REQUEST, ErrorResponse.getInvalidScope(contentFormat), contentFormat);
	        				}

	        			}
	        			else {
	        				// client is not authorized to get tokens for the resource server
	        				logger.debug("Client " + tokenRequest.getClient_id() + " is not authorized to get token for resource server " + rs.getAud() + ".");
							Exchange.respond(exchange, ResponseCode.BAD_REQUEST, ErrorResponse.getUnauthorizedClient(contentFormat), contentFormat);
	        			}
	        		}
	        		else {
	        			// resource server don't exist.
	        			logger.debug("Resource Server " + tokenRequest.getAud() + " is not managed by the authorization server.");
						Exchange.respond(exchange, ResponseCode.BAD_REQUEST, ErrorResponse.getUnauthorizedClient(contentFormat), contentFormat);
	        		}
	        		
	        		
	        	}
	        	else {
	        		// wrong creds client was not authenticated successfully, return errors
	        		// TODO: if JSON, return JSON otherwise CBOR.
	        		logger.info("Client was not authenticated successfully.");
	
					Exchange.respond(exchange, ResponseCode.BAD_REQUEST, ErrorResponse.getUnauthorizedClient(contentFormat), contentFormat);
	        	}
	    	}
    	} catch (RequestException e) {
    		if(e.getReason() == RequestException.MISSING_GRANT) {
    			try {
					Exchange.respond(exchange, ResponseCode.BAD_REQUEST, ErrorResponse.getInvalidGrant(contentFormat), contentFormat);
				} catch (Exception e1) {
					logger.debug("Unknown content format.", e);
				}
    		}
    		
    		try {
				Exchange.respond(exchange, ResponseCode.BAD_REQUEST, ErrorResponse.getUnauthorizedClient(contentFormat), contentFormat);
			} catch (Exception e1) {
				logger.debug("Unknown content format.", e);
			}
    	} catch (Exception e) {
    		// TODO: sometimes it can be an content format error...
			logger.info("Unknown error.", e);
		}

    }
    
}    
    