package se.wahlstromstekniska.acetest.authorizationserver;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.security.Key;

import org.apache.log4j.Logger;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKey.OutputControlLevel;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.ByteUtil;


public class AuthorizationServer extends CoapServer {

	protected static final int COAP_PORT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.COAP_PORT);

	final static Logger logger = Logger.getLogger(AuthorizationServer.class);
	private static ServerConfiguration config = ServerConfiguration.getInstance();
	
    public static void main(String[] args) throws Exception {
        try {

            logger.info("Starting server.");
            AuthorizationServer server = new AuthorizationServer();
            server.addEndpoints();
            server.start();

        } catch (SocketException e) {
            System.err.println("Failed to initialize server: " + e.getMessage());
        }
    }
 
    protected void addEndpoints() {
    	for (InetAddress addr : EndpointManager.getEndpointManager().getNetworkInterfaces()) {
    		// only binds to IPv4 addresses and localhost
			if (addr instanceof Inet4Address || addr.isLoopbackAddress()) {
				InetSocketAddress bindToAddress = new InetSocketAddress(addr, COAP_PORT);
				addEndpoint(new CoapEndpoint(bindToAddress));
	            logger.info("Bound CoAP server to " + addr + " and port " + COAP_PORT);
			}
		}
    }

    /*
     * Constructor.
     */
    public AuthorizationServer() throws SocketException {
        add(new TokenResource());
    }

    
    class TokenResource extends CoapResource {
        
        public TokenResource() {
            super("token");
            getAttributes().setTitle("OAuth2 Token Endpoint for CoAP");
            
            logger.info("Token endpoints initiated.");
        }

        @Override
        public void handlePOST(CoapExchange exchange) {
            
			logger.info("Request: " + exchange.getRequestText());

        	// take request and turn it into a TokenRequest object
        	byte[] payload = exchange.getRequestPayload();
        	TokenRequest tokenRequest  = null;
        	try {
        		tokenRequest = new TokenRequest(payload);
        	} catch (Exception e) {
        		// request is not valid (missing mandatory attributes)
    			logger.info("Could not parse request: " + e.getMessage());
    			e.printStackTrace();
        		exchange.respond(ResponseCode.BAD_REQUEST, ErrorResponse.getInvalidRequest());
        		return;
        	}
        	
        	if(!tokenRequest.validateRequest()) {
        		// request is not valid (the values of the sent attributes is not valid)
    			logger.info("Request is not valid.");

        		exchange.respond(ResponseCode.BAD_REQUEST, ErrorResponse.getInvalidRequest());
        	}
        	else {
	        	// validate client credentials
        		ClientAuthentication auth = new ClientAuthentication();
	        	boolean authenticated = auth.authenticate(tokenRequest.getClientID(), tokenRequest.getClientSecret());
	
	        	if(authenticated) {

	        		// does user have access to the resource server
	        		ResourceServer rs = config.getResourceServer(tokenRequest.getAud());
	        		if(rs != null) {
		    			logger.info("Found requested Resource Server in Authorization Servers control.");

	        			if(rs.isClientAuthorized(tokenRequest.getClientID())) {
	        				// generate a token for the client against the resource.
			    			logger.info("Client " + tokenRequest.getClientID() + " is authorized to get token for the resource server " + rs.getAud());

			    			logger.info("Minting a new access token.");

							try {
								// get authorization servers signing key
		        				JWT jwt = new JWT();
		        				String token = null;

		        				// get key from client and if none, generate keys on AS and return encrypted keys to client
								JsonWebKey clientsPublicKey = tokenRequest.getKey(); 
								if(clientsPublicKey == null) {
									clientsPublicKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
									clientsPublicKey.setKeyId("asgeneratedKey");
								}

								token = jwt.generateJWT(config.getAuthorizationServerKey(), rs.getAud(), clientsPublicKey);
		        				
								TokenResponse response = null;
								if(tokenRequest.getKey() != null) {
									response = new TokenResponse(token, Constants.tokenTypePOP, rs.getCsp(), null);
								}
								else {
									
									// TODO: Get a better key, this is just copy paste from jose4j examples
									
									 Key key = new AesKey(ByteUtil.randomBytes(16));
									 JsonWebEncryption jwe = new JsonWebEncryption();
									 jwe.setPayload(clientsPublicKey.toJson(OutputControlLevel.INCLUDE_PRIVATE));
									 jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW);
									 jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
									 jwe.setKey(key);
									 String serializedJwe = jwe.getCompactSerialization();

									 logger.error("Serialized Encrypted JWE: " + serializedJwe);

									 response = new TokenResponse(token, Constants.tokenTypePOP, rs.getCsp(), serializedJwe);
								}
		        				
		        				// TODO: make it possible to also return CBOR 
		        				String json = response.getJSON();
				    			logger.info("Response: " + json);

		    	                exchange.respond(json);

							} catch (Exception e1) {
								logger.error("Could not generate token." + e1.getMessage());
								e1.printStackTrace();
				        		exchange.respond(ResponseCode.INTERNAL_SERVER_ERROR, ErrorResponse.getInternalServerError());
							}
	        				
	        			}
	        			else {
	        				// client is not authorized to get tokens for the resource server
							logger.info("Client " + tokenRequest.getClientID() + " is not authorized to get token for resource server " + rs.getAud() + ".");
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

	        		exchange.respond(ResponseCode.BAD_REQUEST);
	        	}
        	}

        }
    }    
}