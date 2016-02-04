package se.wahlstromstekniska.acetest.resourceserver;

import org.apache.log4j.Logger;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.json.JSONObject;

import se.wahlstromstekniska.acetest.authorizationserver.Constants;
import se.wahlstromstekniska.acetest.authorizationserver.ServerConfiguration;
import se.wahlstromstekniska.acetest.authorizationserver.resource.Exchange;


public class AuthzInfoResource extends CoapResource {
    
	final static Logger logger = Logger.getLogger(AuthzInfoResource.class);
	private static ServerConfiguration asConfig = ServerConfiguration.getInstance();
	private static ResourceServerConfiguration rsConfig = ResourceServerConfiguration.getInstance();
	
    public AuthzInfoResource() {
        super("authz-info");

        getAttributes().setTitle("Authoriation info resource for CoAP");
        
        logger.debug("Authoriation info resource initiated.");
    }

    @Override
    public void handlePOST(CoapExchange exchange) {

    	int contentFormat = exchange.getRequestOptions().getContentFormat();
    	byte[] accessToken = Exchange.getPayload(exchange, contentFormat);
    	
    	String pskIdentity = null;
    	
    	if(contentFormat == Constants.MediaTypeRegistry_APPLICATION_JWT) {
    		try {
    				
        	    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
    		        .setAllowedClockSkewInSeconds(30)
    		        .setExpectedAudience("tempSensorInLivingRoom")
    		        .setVerificationKey(asConfig.getSignAndEncryptKey().getPublicKey())
    		        .build();
    	
				OctetSequenceJsonWebKey ojwk = null;

    		    //  Validate the JWT and process it to the Claims
    		    JwtClaims jwtClaims;
					jwtClaims = jwtConsumer.processToClaims(new String(accessToken));
    		    if(jwtClaims.getAudience().contains("tempSensorInLivingRoom")) {
    		    	
    		    	// jose4j don't read claims with objects in a good way so getting raw json and parsing manually instead
    		    	String rawJson = jwtClaims.getRawJson();
    		    	JSONObject jsonObject = new JSONObject(rawJson).getJSONObject("cnf").getJSONObject("jwk");

    				JsonWebKey jwk = JsonWebKey.Factory.newJwk(jsonObject.toString());
    				if(jwk.getKeyType().equalsIgnoreCase("oct")) {
    					ojwk = new OctetSequenceJsonWebKey(jwk.getKey());
    				}
    				
    				pskIdentity = (String) jwtClaims.getClaimValue("psk_identity");
    				
    				// TODO: add other key types
    		    }
    		    
    		    // add psk key/psk identity to key storage
    		    rsConfig.getPskStorage().setKey(pskIdentity, ojwk.getOctetSequence());

    		    Exchange.respond(exchange, ResponseCode.CREATED);

			} catch (InvalidJwtException e) {
    		    Exchange.respond(exchange, ResponseCode.UNAUTHORIZED);
			} catch (MalformedClaimException e) {
    		    Exchange.respond(exchange, ResponseCode.BAD_REQUEST);
			} catch (JoseException e) {
    		    Exchange.respond(exchange, ResponseCode.BAD_REQUEST);
			}

    	}
    	else if(contentFormat == Constants.MediaTypeRegistry_APPLICATION_CWT) {
		    Exchange.respond(exchange, ResponseCode.NOT_IMPLEMENTED);
    	}
    	
    }

}    
    