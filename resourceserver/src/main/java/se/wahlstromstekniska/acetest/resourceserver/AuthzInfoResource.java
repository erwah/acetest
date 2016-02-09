package se.wahlstromstekniska.acetest.resourceserver;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import org.apache.log4j.Logger;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
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
	private static ResourceServerConfiguration config = ResourceServerConfiguration.getInstance();
	
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
    		        .setVerificationKey(config.getAsSignKey().getPublicKey())
    		        .build();
    	
    		    //  Validate the JWT and process it to the Claims
    		    JwtClaims jwtClaims = jwtConsumer.processToClaims(new String(accessToken));
    		    if(jwtClaims.getAudience().contains("tempSensorInLivingRoom")) {
    		    	
    		    	// jose4j don't read claims with objects in a good way so getting raw json and parsing manually instead
    		    	String rawJson = jwtClaims.getRawJson();
    		    	
    		    	String clientsPopKey = "";
    		    	
    		    	// TODO: Verify against spec.
    		    	if(new JSONObject(rawJson).getJSONObject("cnf").has("jwk")) {
    		    		// it's an unencrypted public key
    		    		clientsPopKey = new JSONObject(rawJson).getJSONObject("cnf").getJSONObject("jwk").toString();
    		    	}
    		    	else {
    		    		// it's an encrypted symmetric pop key
    		    		String encryptedPopKey = new JSONObject(rawJson).getJSONObject("cnf").getString("jwe");

    		    		JsonWebEncryption jwe = new JsonWebEncryption();
    					jwe.setKey(config.getRpk().getEcPrivateKey());
    					jwe.setCompactSerialization(encryptedPopKey);

    					clientsPopKey = jwe.getPayload();
    		    	}
 
    		    	JsonWebKey jwk = JsonWebKey.Factory.newJwk(clientsPopKey);

    				String keyType = jwk.getKeyType();
    				
    				if(keyType.equalsIgnoreCase("oct")) {
    					// this is a symmetric key, either use it as a PSK or with object security
    					OctetSequenceJsonWebKey ojwk = new OctetSequenceJsonWebKey(jwk.getKey());
        				pskIdentity = (String) jwtClaims.getClaimValue("psk_identity");

    	    		    // add psk key/psk identity to key storage
    	    		    config.getPskStorage().setKey(pskIdentity, ojwk.getOctetSequence());
    				}
    				else {
    					PublicKey publicKey = null;
    					
    					if(keyType.equalsIgnoreCase("ec")) {
    						EllipticCurveJsonWebKey ecjwk = new EllipticCurveJsonWebKey((ECPublicKey) jwk.getKey());
    						publicKey = ecjwk.getPublicKey();
    					}
    					else if(keyType.equalsIgnoreCase("rsa")) {
    						RsaJsonWebKey rsajwk = new RsaJsonWebKey((RSAPublicKey) jwk.getKey());
    						publicKey = rsajwk.getPublicKey();
    					}
    					
    					config.getPublicKeyStorage().add(publicKey);
    				}
    				
    		    }
    		    
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
    