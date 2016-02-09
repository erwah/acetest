package se.wahlstromstekniska.acetest.authorizationserver.resource;

import org.apache.log4j.Logger;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.json.JSONObject;

public class Exchange {
	final static Logger logger = Logger.getLogger(Exchange.class);

	public static byte[] getPayload(CoapExchange exchange, int contentFormat) {
		logger.info("---------------------------    REQUEST    -----------------------------------------");
		logger.info("Header: " + exchange.getRequestCode() + "(T=" + exchange.advanced().getRequest().getType() + ", Code=XXX, MID=" + exchange.advanced().getRequest().getMID() + ")");
		logger.info("Options: " + exchange.advanced().getRequest().getOptions().toString());
		logger.info("Authn: " + exchange.advanced().getRequest().getSenderIdentity());
		logger.info("Token: " + exchange.advanced().getRequest().getTokenString());
		
		logger.info("Uri-Path: " + exchange.advanced().getRequest().getURI());
				
	    if(contentFormat == MediaTypeRegistry.APPLICATION_JSON) {
	    	logger.info("Payload:\n" + new String(exchange.getRequestPayload()) + "\n");
	    }
	    else if(contentFormat == MediaTypeRegistry.APPLICATION_CBOR) {
	    	logger.info("Payload (Diagnostic):\n" + new String(exchange.getRequestPayload()) + "\n\n");
	    }
		
		return exchange.getRequestPayload();
	}
	
	public static void respond(CoapExchange exchange, ResponseCode code, byte[] payload, int contentFormat) {
		exchange.respond(code, payload, contentFormat);

		logger.info("---------------------------    RESPONSE    ----------------------------------------");
		logger.info("Header: " + code + " Content (T=" + exchange.advanced().getRequest().getType() + ", Code=" + code + ", MID=" + exchange.advanced().getRequest().getMID() + ")");
		logger.info("Options: " + exchange.advanced().getResponse().getOptions());
		logger.info("Token: " + exchange.advanced().getRequest().getTokenString());
		
	    if(contentFormat == MediaTypeRegistry.APPLICATION_JSON) {
	    	logger.info("Payload:\n" + new String(payload) + "\n");
	    }
	    else if(contentFormat == MediaTypeRegistry.APPLICATION_CBOR) {
	    	logger.info("Payload (Diagnostic):\n" + new String(payload) + "\n");
	    }
	}

	public static void respond(CoapExchange exchange, ResponseCode code) {
		  
		logger.info("---------------------------    RESPONSE    ----------------------------------------");
		logger.info("Header: " + code + " Content (T=" + exchange.advanced().getRequest().getType() + ", Code=" + code + ", MID=" + exchange.advanced().getRequest().getMID() + ")");
		logger.info("Token: " + exchange.advanced().getRequest().getTokenString());

		exchange.respond(code);
	}


}
