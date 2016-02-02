package se.wahlstromstekniska.acetest.authorizationserver.resource;

import org.apache.log4j.Logger;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.jose4j.jwk.JsonWebKey.OutputControlLevel;

import se.wahlstromstekniska.acetest.authorizationserver.AccessToken;
import se.wahlstromstekniska.acetest.authorizationserver.ClientAuthentication;
import se.wahlstromstekniska.acetest.authorizationserver.ErrorResponse;
import se.wahlstromstekniska.acetest.authorizationserver.ResourceServer;
import se.wahlstromstekniska.acetest.authorizationserver.ServerConfiguration;


public class IntrospectResource extends CoapResource {
    
	final static Logger logger = Logger.getLogger(IntrospectResource.class);
	private static ServerConfiguration config = ServerConfiguration.getInstance();

    public IntrospectResource() {
        super("introspect");
        getAttributes().setTitle("OAuth2 Introspection endpoint for CoAP");
        
        logger.debug("Introspection endpoints initiated.");
    }

    @Override
    public void handlePOST(CoapExchange exchange) {

    	// refactor this method, big time!!
    	
		int contentFormat = exchange.getRequestOptions().getContentFormat();
    	byte[] payload = Exchange.getPayload(exchange, contentFormat);

    	IntrospectRequest introspectRequest  = null;
    	try {
    		introspectRequest = new IntrospectRequest(payload, contentFormat);
    	} catch (Exception e) {
    		// request is not valid (missing mandatory attributes)
    		logger.debug("Could not parse request: " + e.getMessage());
			try {
				Exchange.respond(exchange, ResponseCode.BAD_REQUEST, ErrorResponse.getInvalidRequest(contentFormat), contentFormat);
			} catch (Exception e1) {
				logger.debug("Unknown content format: " + e.getMessage());
			}
    		return;
    	}
    	
    	if(!introspectRequest.validateRequest()) {
    		// request is not valid (the values of the sent attributes is not valid)
    		logger.debug("Request is not valid.");

			try {
				Exchange.respond(exchange, ResponseCode.BAD_REQUEST, ErrorResponse.getInvalidRequest(contentFormat), contentFormat);
			} catch (Exception e) {
				logger.debug("Unknown content format: " + e.getMessage());
			}
    	}
    	else {
        	// validate client credentials
    		ClientAuthentication auth = new ClientAuthentication();
        	boolean authenticated = auth.authenticate(introspectRequest.getClientID(), introspectRequest.getClientSecret());

        	if(authenticated) {
        		// initialize as false
        		IntrospectResponse response = new IntrospectResponse(false);
        		
        		// loop through all resources, find token.
        		for (ResourceServer rs : config.getResourceServers()) {
        			AccessToken accessToken = rs.getResourceTokensTokenRepresentation(introspectRequest.getToken());
        			if(accessToken != null) {
        				if(rs.isClientAuthorized(introspectRequest.getClientID())) {
        					response.setActive(true);
        					response.setAud(rs.getAud());
        					response.setKey(accessToken.getKey().toJson(OutputControlLevel.INCLUDE_PRIVATE));
        					
        					// TODO: handle AIF
        				}
        			}
				}
        		
				byte[] responsePayload = response.toPayload(contentFormat);
				logger.debug("Response: " + new String(responsePayload));

    			Exchange.respond(exchange, ResponseCode.CONTENT, responsePayload, contentFormat);
        	}
        	else {
        		// wrong creds client was not authenticated successfully, return errors
        		// TODO: if JSON, return JSON otherwise CBOR.
				logger.info("Client was not authenticated successfully.");

				try {
					Exchange.respond(exchange, ResponseCode.BAD_REQUEST, ErrorResponse.getUnauthorizedClient(contentFormat), contentFormat);
				} catch (Exception e) {
					logger.debug("Unknown content format: " + e.getMessage());
				}
        	}
    	}

    }
    
}    
    