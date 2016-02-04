package se.wahlstromstekniska.acetest.authorizationserver;


import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
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
	JsonWebKey jwk;
	AccessToken token;

	@Before
	public void begin() throws Exception {
		jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
		jwk.setKeyId("testkid");

		token = jwt.generateJWT(config.getSignAndEncryptKey(), "myAud", "read", jwk, "erwah");
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

	
}
