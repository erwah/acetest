package se.wahlstromstekniska.acetest.client;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.apache.log4j.Logger;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKey.OutputControlLevel;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;

import se.wahlstromstekniska.acetest.authorizationserver.Constants;
import se.wahlstromstekniska.acetest.authorizationserver.DTLSRequest;
import se.wahlstromstekniska.acetest.authorizationserver.ServerConfiguration;
import se.wahlstromstekniska.acetest.authorizationserver.resource.TokenRequest;
import se.wahlstromstekniska.acetest.authorizationserver.resource.TokenResponse;
import se.wahlstromstekniska.acetest.resourceserver.ResourceServerConfiguration;
import se.wahlstromstekniska.acetest.resourceserver.TemperatureResponse;


public class ClientPSK {

	private static ServerConfiguration asConfig = ServerConfiguration.getInstance();
	private static ResourceServerConfiguration rsConfig = ResourceServerConfiguration.getInstance();
	
	final static Logger logger = Logger.getLogger(ClientPSK.class);

	private static SecureRandom random = new SecureRandom();

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
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");
		req.setScopes("read write");

		Response response;
		try {
			
			// let AS generate key
			response = DTLSRequest.dtlsRequest("coaps://localhost:"+asConfig.getCoapsPort()+"/"+Constants.TOKEN_RESOURCE, "POST", req.toPayload(MediaTypeRegistry.APPLICATION_JSON), MediaTypeRegistry.APPLICATION_JSON);
			TokenResponse tokenResponse = new TokenResponse(response.getPayload(), response.getOptions().getContentFormat());
			String accessToken = tokenResponse.getAccessToken();
			String keyString = tokenResponse.getKey();
			String pskIdentity = tokenResponse.getPskIdentity();
			
			// parse out a symmetric key from the key value
			// {"kty":"oct","k":"vPBNfe2AJZc5YAMULD-yEg","kid":"asgeneratedKey"}
			JsonWebKey jwk = JsonWebKey.Factory.newJwk(keyString);
			OctetSequenceJsonWebKey ojwk = null;
			
			if(jwk.getKeyType().equalsIgnoreCase("oct")) {
				ojwk = new OctetSequenceJsonWebKey(jwk.getKey());
			}
			
			logger.info(accessToken);
			logger.info(response);
			logger.info(jwk.toJson(OutputControlLevel.INCLUDE_PRIVATE));
			logger.info("Time elapsed (ms): " + response.getRTT());

			// send key to resource servers authz-info resource
			Request authzInfoRequest = Request.newPost();
			authzInfoRequest.setURI("coap://localhost:"+rsConfig.getCoapPort()+"/"+Constants.AUTHZ_INFO_RESOURCE);
			authzInfoRequest.getOptions().setContentFormat(Constants.MediaTypeRegistry_APPLICATION_JWT);
			authzInfoRequest.setPayload(accessToken.getBytes());
			Response authzInfoResponse = authzInfoRequest.send().waitForResponse();
			
			logger.info("code: " + authzInfoResponse.getCode());
			logger.info("payload: " + authzInfoResponse.getPayloadString());


			if(authzInfoResponse.getCode() == ResponseCode.CREATED) {
				// get the temperature
				response = DTLSRequest.dtlsRequest("coaps://localhost:"+rsConfig.getCoapsPort()+"/temperature", "POST", req.toPayload(MediaTypeRegistry.APPLICATION_JSON), MediaTypeRegistry.APPLICATION_JSON, pskIdentity, ojwk.getOctetSequence());
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
