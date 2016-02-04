package se.wahlstromstekniska.acetest.resourceserver;

import java.util.Random;

import org.apache.log4j.Logger;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.server.resources.CoapExchange;

import se.wahlstromstekniska.acetest.authorizationserver.resource.Exchange;


public class TemperatureResource extends CoapResource {
    
	final static Logger logger = Logger.getLogger(TemperatureResource.class);
	protected static Random random = new Random();

    public TemperatureResource() {
        super("temperature");
        getAttributes().setTitle("Temperature resource for CoAP");
        
        logger.debug("Temperature resource initiated.");
    }

    @Override
    public void handlePOST(CoapExchange exchange) {
    	TemperatureResponse response = new TemperatureResponse(randomInRange(16.5, 24.5));
    	
		Exchange.respond(exchange, ResponseCode.CONTENT, response.toPayload(MediaTypeRegistry.APPLICATION_JSON), MediaTypeRegistry.APPLICATION_JSON);
    }

	public static double randomInRange(double min, double max) {
  	  double range = max - min;
  	  double scaled = random.nextDouble() * range;
  	  double shifted = scaled + min;
  	  return shifted;
  	}    	

}    
    