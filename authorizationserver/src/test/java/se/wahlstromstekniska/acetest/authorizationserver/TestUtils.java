package se.wahlstromstekniska.acetest.authorizationserver;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.json.JSONException;
import org.junit.Assert;

import se.wahlstromstekniska.acetest.authorizationserver.resource.TokenResponse;

public class TestUtils {

	private static ServerConfiguration config = ServerConfiguration.getInstance();


	public static void validateToken(byte[] payload, String aud) throws MalformedClaimException, JSONException, JoseException {
		TokenResponse tokenResponse = new TokenResponse(payload);
		
	    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
	        .setAllowedClockSkewInSeconds(30)
	        .setExpectedAudience(aud)
	        .setVerificationKey(config.getAuthorizationServerKey().getPublicKey())
	        .build();

		try
		{
		    //  Validate the JWT and process it to the Claims
		    JwtClaims jwtClaims = jwtConsumer.processToClaims(tokenResponse.getAccessToken());
		    
		    Assert.assertTrue(jwtClaims.getAudience().contains(aud));
		}
		catch (InvalidJwtException e)
		{
			Assert.fail("Could not validate token.");
		}
	}
}
