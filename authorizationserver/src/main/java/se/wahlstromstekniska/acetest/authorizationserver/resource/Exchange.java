package se.wahlstromstekniska.acetest.authorizationserver.resource;

import org.apache.log4j.Logger;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.server.resources.CoapExchange;

public class Exchange {
	final static Logger logger = Logger.getLogger(Exchange.class);

	public static byte[] getPayload(CoapExchange exchange, int contentFormat) {
		logger.info("REQUEST\n------------------------------------------------------------");
		logger.info("Header: " + exchange.getRequestCode() + " (Code=X.XX)");
		logger.info("Uri-Path: " + exchange.advanced().getRequest().getURI());
		logger.info("Content-Format: " + contentFormat);
	    if(contentFormat == MediaTypeRegistry.APPLICATION_JSON) {
	    	logger.info("Payload: " + new String(exchange.getRequestPayload()) + "\n");
	    }
	    else if(contentFormat == MediaTypeRegistry.APPLICATION_CBOR) {
	    	logger.info("Payload (Diagnostic): " + new String(exchange.getRequestPayload()) + "\n");
	    }
		
		return exchange.getRequestPayload();
	}
	
	public static void respond(CoapExchange exchange, ResponseCode code, byte[] payload, int contentFormat) {
		  
		logger.info("RESPONSE\n------------------------------------------------------------");
		logger.info("Header: (Code=" + code + ")");
		logger.info("Content-Format: " + contentFormat);
	    if(contentFormat == MediaTypeRegistry.APPLICATION_JSON) {
	    	logger.info("Payload: " + new String(payload) + "\n");
	    }
	    else if(contentFormat == MediaTypeRegistry.APPLICATION_CBOR) {
	    	logger.info("Payload (Diagnostic): " + new String(payload) + "\n");
	    }

		exchange.respond(code, payload, contentFormat);
	}

	public static void respond(CoapExchange exchange, ResponseCode code) {
		  
		logger.info("RESPONSE\n------------------------------------------------------------");
		logger.info("Header: (Code=" + code + ")");

		exchange.respond(code);
	}


}
