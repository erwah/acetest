package se.wahlstromstekniska.acetest.authorizationserver.resource;

import java.math.BigInteger;
import java.security.Key;
import java.security.SecureRandom;

import org.apache.log4j.Logger;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKey.OutputControlLevel;
import org.jose4j.jwk.OctJwkGenerator;
import org.jose4j.keys.AesKey;
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

		        				boolean isSymmetricKey = false;

		        				String pskIdentity = new BigInteger(130, random).toString(32);
		        				
								try {
									AccessToken token = null;
									String clientsEncryptedKey = "";
									String rsEncryptedKey = "";
									
									if(rs.getTokenFormat() == ResourceServer.TOKEN_FORMAT_JWT) {
										// get authorization servers signing key
				        				JWT jwt = new JWT();
				        				
										JsonWebKey popKey = tokenRequest.getRawKey(); 
 
				        				// get key from client and if none, generate keys on AS and return encrypted keys to client
										if(popKey == null) {
											isSymmetricKey = true;
											popKey = OctJwkGenerator.generateJwk(128);
											
											// Use a random string as kid that will later be used as PSK identity by the client.
											popKey.setKeyId(pskIdentity);
										}
										else {
											
										}

										if(isSymmetricKey) {
											// encrypt the symmetric pop key two times, first for client and then for the RS
											JsonWebEncryption clientJWE = new JsonWebEncryption();
											clientJWE.setPayload(popKey.toJson(OutputControlLevel.INCLUDE_SYMMETRIC));
											clientJWE.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES); 
											clientJWE.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
											clientJWE.setKey(config.getClient(tokenRequest.getClient_id()).getJwk().getKey());
											clientsEncryptedKey = clientJWE.getCompactSerialization();
											
											// now encrypt the pop key for the RS
											JsonWebEncryption rsJWE = new JsonWebEncryption();
											rsJWE.setPayload(popKey.toJson(OutputControlLevel.INCLUDE_SYMMETRIC));
											rsJWE.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES);
											rsJWE.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
											
											// get the RS public key
											rsJWE.setKey(rs.getRPK().getKey());
											rsEncryptedKey = rsJWE.getCompactSerialization();
											// if it's an symmetric key then it needs to be sent encrypted, otherwise it can be sent using public keys
											token = jwt.generateJWT(true, config.getSignAndEncryptKey(), rs.getAud(), rs.getScopes(), popKey, rsEncryptedKey);
										}
										else {
											token = jwt.generateJWT(false, config.getSignAndEncryptKey(), rs.getAud(), rs.getScopes(), popKey, null);
										}

									}
									else {
										throw new Exception("CWT not implemented yet.");
									}
			        				
									TokenResponse response = null;
									if(isSymmetricKey) {
										// using symmetric crypto, PSK identity needs to be sent
										response = new TokenResponse(token, Constants.tokenTypePOP, rs.getCsp(), clientsEncryptedKey, null);
									}
									else {
										// using asymmetric keys and the AS public key must be sent to the client for authentication
										response = new TokenResponse(token, Constants.tokenTypePOP, rs.getCsp(), null, rs.getRPK());
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
    