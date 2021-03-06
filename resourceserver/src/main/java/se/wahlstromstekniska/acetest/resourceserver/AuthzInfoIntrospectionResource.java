package se.wahlstromstekniska.acetest.resourceserver;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.apache.log4j.Logger;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;
import org.json.JSONObject;

import se.wahlstromstekniska.acetest.authorizationserver.Constants;
import se.wahlstromstekniska.acetest.authorizationserver.DTLSUtils;
import se.wahlstromstekniska.acetest.authorizationserver.resource.Exchange;
import se.wahlstromstekniska.acetest.authorizationserver.resource.IntrospectRequest;
import se.wahlstromstekniska.acetest.authorizationserver.resource.IntrospectResponse;


public class AuthzInfoIntrospectionResource extends CoapResource {
    
	final static Logger logger = Logger.getLogger(AuthzInfoIntrospectionResource.class);
	private static ResourceServerConfiguration config = ResourceServerConfiguration.getInstance();
	
    public AuthzInfoIntrospectionResource() {
        super("authz-info");

        getAttributes().setTitle("Authoriation info resource for CoAP");
        
        logger.debug("Authoriation info resource initiated.");
    }

    @Override
    public void handlePOST(CoapExchange exchange) {

    	int contentFormat = exchange.getRequestOptions().getContentFormat();
    	byte[] accessToken = Exchange.getPayload(exchange, contentFormat);
    	
    	if(contentFormat == Constants.MediaTypeRegistry_APPLICATION_JWT) {
    		try {
    			
    			// see of token is valid and get claims by calling introspection
    			IntrospectRequest introspectionReq = new IntrospectRequest();
    			introspectionReq.setToken(new String(accessToken));
    			introspectionReq.setClientID(config.getClientId());
    			introspectionReq.setClientSecret(config.getClientSecret());
    			
    			Response resp = DTLSUtils.dtlsPSKRequest("coaps://localhost:"+config.getAsCoapsPort()+"/"+Constants.INSTROSPECTION_RESOURCE, "POST", introspectionReq.toPayload(MediaTypeRegistry.APPLICATION_JSON), MediaTypeRegistry.APPLICATION_JSON, config.getAsPskIdentity(), config.getAsPskKey().getBytes());
    			IntrospectResponse ir = new IntrospectResponse(resp.getPayload(), MediaTypeRegistry.APPLICATION_JSON);

    			// is token active and is the token minted for this specific RS (check aud)
    			if(ir.isActive() && ir.getAud().equals(config.getAud())) {

					// TODO: Check scopes
				
					// get key and add to psk store or list of trusted public keys
    				String cnf = ir.getCnf();
    				
    		    	String clientsPopKey = "";
        		    	
    		    	// TODO: Verify against spec.
    		    	if(new JSONObject(cnf).has("jwk")) {
    		    		// it's an unencrypted public key
    		    		clientsPopKey = new JSONObject(cnf).getJSONObject("jwk").toString();
    		    	}
    		    	else {
    		    		// it's an encrypted symmetric pop key
    		    		String encryptedPopKey = new JSONObject(cnf).getString("jwe");

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

    	    		    // add psk to key storage, use KID as PSK identity
    					// TODO: look for duplicates
    	    		    config.getPskStorage().setKey(jwk.getKeyId(), ojwk.getOctetSequence());
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

    					// made changes to scandium to support a list of public keys. Next release of scandium will include the fix.
    					// TODO: look for duplicates
    					config.getPublicKeyStorage().add(publicKey);
    				}
        				
        		    Exchange.respond(exchange, ResponseCode.CREATED);
        		    
    			}
    			else {
        		    Exchange.respond(exchange, ResponseCode.UNAUTHORIZED);
    			}

			} catch (InvalidJwtException e) {
    		    Exchange.respond(exchange, ResponseCode.UNAUTHORIZED);
			} catch (MalformedClaimException e) {
    		    Exchange.respond(exchange, ResponseCode.BAD_REQUEST);
			} catch (JoseException e) {
    		    Exchange.respond(exchange, ResponseCode.BAD_REQUEST);
			} catch (Exception e) {
    		    Exchange.respond(exchange, ResponseCode.INTERNAL_SERVER_ERROR);
			}

    	}
    	else if(contentFormat == Constants.MediaTypeRegistry_APPLICATION_CWT) {
		    Exchange.respond(exchange, ResponseCode.NOT_IMPLEMENTED);
    	}
    	
    }

}    
    