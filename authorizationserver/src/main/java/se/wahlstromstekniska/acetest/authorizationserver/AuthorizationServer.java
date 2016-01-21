package se.wahlstromstekniska.acetest.authorizationserver;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;

import org.apache.log4j.Logger;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.lang.JoseException;
import org.json.JSONException;


public class AuthorizationServer extends CoapServer {

	final static Logger logger = Logger.getLogger(AuthorizationServer.class);
	
	protected static final int COAP_PORT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.COAP_PORT);

	private static ManagedResourceServers managedResourceServers = ManagedResourceServers.getInstance();
	private static ClientAuthentication auth = ClientAuthentication.getInstance();

	
    public static void main(String[] args) throws Exception {
        try {
            AuthorizationServer server = new AuthorizationServer();
            server.addEndpoints();
            server.start();
            
            logger.info("Starting server.");

            // add a new RS to test against
            // TODO: move the pre-registered sensors to a configuration file instead.
            ResourceServer tempSensorInLivingRoom = new ResourceServer("tempSensorInLivingRoom");
            tempSensorInLivingRoom.addAuthorizedClient("myclient");
            tempSensorInLivingRoom.setCsp(Constants.cspDTLS);

        	managedResourceServers.addResourceServer(tempSensorInLivingRoom);

        	logger.info("Added hardcoded resource server tempSensorInLivingRoom.");
            auth.addClient(new ClientCredentials("myclient", "qwerty"));
            
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
        	} catch (JSONException e) {
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
	        	boolean authenticated = auth.authenticate(tokenRequest.getClientID(), tokenRequest.getClientSecret());
	
	        	if(authenticated) {
	    			logger.info("Client is sucessfully authenticated.");

	        		// client authenticated successfully

	        		// does user have access to the resource server
	        		ResourceServer rs = managedResourceServers.getResourceServer(tokenRequest.getAud());
	        		if(rs != null) {
		    			logger.info("Found requested Resource Server in Authorization Servers control.");

	        			if(rs.isClientAuthorized(tokenRequest.getClientID())) {
	        				// generate a token for the client against the resource.
			    			logger.info("Client " + tokenRequest.getClientID() + " is authorized to get token for the resource server " + rs.getAud());

	        				// generate a key
	        				// generate access token
	        					// csp
	        					// validity
	        				
	        			    // Generate an RSA key pair
	        				// TODO: change to EC
			    			logger.info("Minting a new access token.");

	        			    RsaJsonWebKey rsaJsonWebKey;
							try {
								rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);

		        				JWT jwt = new JWT();
		        				
		        				String token = null;
		        				try {
									token = jwt.generateJWT(rsaJsonWebKey, rs.getAud());
								} catch (Exception e) {
					        		// failed to generate token.
					        		exchange.respond(ResponseCode.INTERNAL_SERVER_ERROR, ErrorResponse.getInternalServerError());
									e.printStackTrace();
								}
		        				
		        				// TODO: fix key!!!!
		        				TokenResponse response = new TokenResponse(token, Constants.tokenTypePOP, rs.getCsp(), "todokey");
		        				
		        				// TODO: make it possible to also return CBOR 
		        				String json = response.getJSON();
				    			logger.info("Response: " + json);

		    	                exchange.respond(json);

							} catch (JoseException e1) {
		        				// could not generate keys
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