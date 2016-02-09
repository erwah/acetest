package se.wahlstromstekniska.acetest.client;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;

import org.apache.log4j.Logger;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKey.OutputControlLevel;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;

import se.wahlstromstekniska.acetest.authorizationserver.Constants;
import se.wahlstromstekniska.acetest.authorizationserver.DTLSUtils;
import se.wahlstromstekniska.acetest.authorizationserver.resource.TokenRequest;
import se.wahlstromstekniska.acetest.authorizationserver.resource.TokenResponse;
import se.wahlstromstekniska.acetest.resourceserver.TemperatureResponse;


public class ClientRPK {

	private static ClientConfiguration config = ClientConfiguration.getInstance();
	
	final static Logger logger = Logger.getLogger(ClientRPK.class);

	private static SecureRandom random = new SecureRandom();

	public static void main(String[] args) {
		try {
			logger.info("Example of an client using raw public keys.");
			asymmetricEcClient();
		}
		catch (Exception e) {
			logger.error(e);
		}

		System.exit(0);
	}

	private static void asymmetricEcClient() throws JoseException {
		
		JsonWebKey popKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
		// generate a unique kid for the newly generated key
	    String kid = new BigInteger(130, random).toString(32);
		popKey.setKeyId(kid);
		
		logger.info(popKey.toJson(OutputControlLevel.INCLUDE_PRIVATE));
		logger.info(popKey.toJson(OutputControlLevel.PUBLIC_ONLY));


		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setAud(config.getRsAud());
		req.setClientID(config.getClientId());
		req.setClientSecret(config.getClientSecret());
		req.setScopes(config.getRsScopes());
		// add key to the request so that public part can be sent to AS
		req.setKey(popKey);
		
		Response response;
		try {
			// send token request to AS and include the public key
			response = DTLSUtils.dtlsPSKRequest("coaps://localhost:"+config.getAsCoapsPort()+"/"+Constants.TOKEN_RESOURCE, "POST", req.toPayload(MediaTypeRegistry.APPLICATION_JSON), MediaTypeRegistry.APPLICATION_JSON, config.getAsPskIdentity(), config.getAsPskKey().getBytes());
			TokenResponse tokenResponse = new TokenResponse(response.getPayload(), response.getOptions().getContentFormat());
			String accessToken = tokenResponse.getAccessToken();
			EllipticCurveJsonWebKey rpk = tokenResponse.getRpk();

			if(rpk != null) {
				String keyType = rpk.getKeyType();
				
				PublicKey publicKey = null;
				
				if(keyType.equalsIgnoreCase("ec")) {
					EllipticCurveJsonWebKey ecjwk = new EllipticCurveJsonWebKey((ECPublicKey) rpk.getKey());
					publicKey = ecjwk.getPublicKey();
				}
				else if(keyType.equalsIgnoreCase("rsa")) {
					RsaJsonWebKey rsajwk = new RsaJsonWebKey((RSAPublicKey) rpk.getKey());
					publicKey = rsajwk.getPublicKey();
				}

				ArrayList<PublicKey> trustedPublicKeys = new ArrayList<PublicKey>();
				trustedPublicKeys.add(publicKey);
				
				logger.info(accessToken);
				logger.info("Time elapsed (ms): " + response.getRTT());

				// send key to resource servers authz-info resource over unencrypted DTLS
				Request authzInfoRequest = Request.newPost();
				authzInfoRequest.setURI("coap://localhost:"+config.getRsCoapPort()+"/"+Constants.AUTHZ_INFO_RESOURCE);
				authzInfoRequest.getOptions().setContentFormat(Constants.MediaTypeRegistry_APPLICATION_JWT);
				authzInfoRequest.setPayload(accessToken.getBytes());
				Response authzInfoResponse = authzInfoRequest.send().waitForResponse();
				
				logger.info("code: " + authzInfoResponse.getCode());
				logger.info("payload: " + authzInfoResponse.getPayloadString());

				if(authzInfoResponse.getCode() == ResponseCode.CREATED) {
					// get the temperature
					response = DTLSUtils.dtlsRPKRequest("coaps://localhost:"+config.getRsCoapsPort()+"/temperature", "POST", req.toPayload(MediaTypeRegistry.APPLICATION_JSON), MediaTypeRegistry.APPLICATION_JSON, popKey, trustedPublicKeys);
					TemperatureResponse temperatureResponse = new TemperatureResponse(response.getPayload(), response.getOptions().getContentFormat());
					logger.info("Temp: " + temperatureResponse);
				}
				else {
					logger.info("Access token not valid. Response code: " + response.getCode());
				}
			}

		} catch (Exception e) {
			logger.error(e);
		}
	}

}
