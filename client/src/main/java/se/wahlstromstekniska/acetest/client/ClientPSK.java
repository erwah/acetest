package se.wahlstromstekniska.acetest.client;

import org.apache.log4j.Logger;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetSequenceJsonWebKey;

import se.wahlstromstekniska.acetest.authorizationserver.Constants;
import se.wahlstromstekniska.acetest.authorizationserver.DTLSUtils;
import se.wahlstromstekniska.acetest.authorizationserver.resource.TokenRequest;
import se.wahlstromstekniska.acetest.authorizationserver.resource.TokenResponse;
import se.wahlstromstekniska.acetest.resourceserver.TemperatureResponse;


public class ClientPSK {

	private static ClientConfiguration config = ClientConfiguration.getInstance();
	
	final static Logger logger = Logger.getLogger(ClientPSK.class);

	public static void main(String[] args) {
		try {
			logger.info("Example of an client using symmetric keys.");
			symmetricClient();
		}
		catch (Exception e) {
			logger.error(e);
		}

		System.exit(0);
	}

	private static void symmetricClient() {
		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setAud(config.getRsAud());
		req.setClientID(config.getClientId());
		req.setClientSecret(config.getClientSecret());
		req.setScopes(config.getRsScopes());

		Response response;
		try {
			
			// let AS generate key
			response = DTLSUtils.dtlsPSKRequest("coaps://localhost:"+config.getAsCoapsPort()+"/"+Constants.TOKEN_RESOURCE, "POST", req.toPayload(MediaTypeRegistry.APPLICATION_JSON), MediaTypeRegistry.APPLICATION_JSON, config.getAsPskIdentity(), config.getAsPskKey().getBytes());
			TokenResponse tokenResponse = new TokenResponse(response.getPayload(), response.getOptions().getContentFormat());
			String accessToken = tokenResponse.getAccessToken();
			String encryptedKey = tokenResponse.getKey();
			
			// decrypt the key string 
			JsonWebEncryption jwe = new JsonWebEncryption();
			jwe.setKey(config.getEncryptionKey().getEcPrivateKey());
			jwe.setCompactSerialization(encryptedKey);

			String payload = jwe.getPayload();
			
			// parse out a symmetric key from the key value
			// {"kty":"oct","k":"vPBNfe2AJZc5YAMULD-yEg","kid":"asgeneratedKey"}
			JsonWebKey jwk = JsonWebKey.Factory.newJwk(payload);
			OctetSequenceJsonWebKey ojwk = null;
			
			if(jwk.getKeyType().equalsIgnoreCase("oct")) {
				ojwk = new OctetSequenceJsonWebKey(jwk.getKey());
			}
			
			// use the keys KID value as PSK Identity
			String pskIdentity = jwk.getKeyId();


			// send key to resource servers authz-info resource
			Request authzInfoRequest = Request.newPost();
			authzInfoRequest.setURI("coap://localhost:"+config.getRsCoapPort()+"/"+Constants.AUTHZ_INFO_RESOURCE);
			authzInfoRequest.getOptions().setContentFormat(Constants.MediaTypeRegistry_APPLICATION_JWT);
			authzInfoRequest.setPayload(accessToken.getBytes());
			Response authzInfoResponse = authzInfoRequest.send().waitForResponse();
			
			if(authzInfoResponse.getCode() == ResponseCode.CREATED) {
				// get the temperature
				response = DTLSUtils.dtlsPSKRequest("coaps://localhost:"+config.getRsCoapsPort()+"/temperature", "POST", "".getBytes(), MediaTypeRegistry.APPLICATION_JSON, pskIdentity, ojwk.getOctetSequence());
				TemperatureResponse temperatureResponse = new TemperatureResponse(response.getPayload(), response.getOptions().getContentFormat());
				logger.info("Temp: " + temperatureResponse);
			}
			else {
				logger.info("Access token not valid. Response code: " + response.getCode());
			}

		} catch (Exception e) {
			logger.error(e);
		}		
	}

}
