package se.wahlstromstekniska.acetest.authorizationserver;


import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.EllipticCurves;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class JWTTest {

	private static ServerConfiguration config = ServerConfiguration.getInstance();

	JWT jwt = new JWT();
	EllipticCurveJsonWebKey jwk;
	AccessToken token;

	@Before
	public void begin() throws Exception {
		jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
		jwk.setKeyId("testkid");

		token = jwt.generateJWT(true, config.getSignAndEncryptKey(), "myAud", "read", jwk, "erwah");
	}
	
	@Test
	public void validateJWT() throws Exception {
		
		Assert.assertEquals("myAud", token.getAudience());
		
	    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
	        .setAllowedClockSkewInSeconds(30)
	        .setExpectedAudience("myAud")
	        .setVerificationKey(config.getSignAndEncryptKey().getPublicKey())
	        .build();

		try
		{
		    //  Validate the JWT and process it to the Claims
		    JwtClaims jwtClaims = jwtConsumer.processToClaims(token.getAccessToken());
		    
		    Assert.assertTrue(jwtClaims.getAudience().contains("myAud"));
		}
		catch (InvalidJwtException e)
		{
			Assert.fail("Could not validate token.");
		}

	}


	@Test(expected=InvalidJwtException.class)
	public void wrongAud() throws Exception {
		
		Assert.assertEquals("myAud", token.getAudience());
		
	    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
	        .setAllowedClockSkewInSeconds(30)
	        .setExpectedAudience("wrongAud")
	        .setVerificationKey(config.getSignAndEncryptKey().getPublicKey())
	        .build();

	    //  Validate the JWT and process it to the Claims
	    JwtClaims jwtClaims = jwtConsumer.processToClaims(token.getAccessToken());
	    Assert.assertEquals("myAud", jwtClaims.getAudience());
	}


	@Test
	public void ecEncrypt() throws Exception {
		
		 JsonWebEncryption jwe = new JsonWebEncryption();
		 jwe.setPayload("Hello World!");
		 jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES);
		 jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_GCM);
		 
		 // get the resource servers public key
		 jwe.setKey(jwk.getKey());
		 String serializedJwe2 = jwe.getCompactSerialization();
		 
		 
		 System.out.println("Serialized Encrypted JWE: " + serializedJwe2);
		 
		 
		 jwe = new JsonWebEncryption();
		 jwe.setKey(jwk.getEcPrivateKey());
		 jwe.setCompactSerialization(serializedJwe2);
		 System.out.println("Payload: " + jwe.getPayload());
		

	}

	
}
