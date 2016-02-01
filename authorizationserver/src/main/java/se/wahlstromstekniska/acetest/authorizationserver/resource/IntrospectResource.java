package se.wahlstromstekniska.acetest.authorizationserver.resource;

import org.apache.log4j.Logger;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.scandium.dtls.ContentType;

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
        
        logger.info("Introspection endpoints initiated.");
    }

    @Override
    public void handlePOST(CoapExchange exchange) {

		logger.info("Request: " + exchange.getRequestText());
		int contentFormat = exchange.getRequestOptions().getContentFormat();

    	// take request and turn it into a TokenRequest object
    	byte[] payload = exchange.getRequestPayload();
    	IntrospectRequest introspectRequest  = null;
    	try {
    		introspectRequest = new IntrospectRequest(payload, contentFormat);
    	} catch (Exception e) {
    		// request is not valid (missing mandatory attributes)
			logger.info("Could not parse request: " + e.getMessage());
			e.printStackTrace();
    		exchange.respond(ResponseCode.BAD_REQUEST, ErrorResponse.getInvalidRequest());
    		return;
    	}
    	
    	if(!introspectRequest.validateRequest()) {
    		// request is not valid (the values of the sent attributes is not valid)
			logger.info("Request is not valid.");

    		exchange.respond(ResponseCode.BAD_REQUEST, ErrorResponse.getInvalidRequest());
    	}
    	else {
        	// validate client credentials
    		ClientAuthentication auth = new ClientAuthentication();
        	boolean authenticated = auth.authenticate(introspectRequest.getClientID(), introspectRequest.getClientSecret());

        	if(authenticated) {
        		IntrospectResponse response = new IntrospectResponse(false);
        		
        		// loop through all resources, find token.
        		for (ResourceServer rs : config.getResourceServers()) {
        			if(rs.validateToken(introspectRequest.getToken())) {
        				if(rs.isClientAuthorized(introspectRequest.getClientID())) {
        					response.setActive(true);
        					response.setAud(rs.getAud());
        				}
        			}
				}

        		
				byte[] responsePayload = response.toPayload(contentFormat);
    			logger.info("Response: " + new String(responsePayload));

                exchange.respond(ResponseCode.CONTENT, responsePayload, contentFormat);
        	}
        	else {
        		// wrong creds client was not authenticated successfully, return errors
        		// TODO: if JSON, return JSON otherwise CBOR.
				logger.info("Client was not authenticated successfully.");

        		exchange.respond(ResponseCode.BAD_REQUEST, ErrorResponse.getUnauthorizedClient());
        	}
    	}

    }
    
}    
    