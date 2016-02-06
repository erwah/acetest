package se.wahlstromstekniska.acetest.authorizationserver;

import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.json.JSONException;
import org.junit.Assert;

public class TestUtils {

	private static ServerConfiguration config = ServerConfiguration.getInstance();


	public static void validateToken(byte[] accessToken, String aud, int contentFormat) throws MalformedClaimException, JSONException, JoseException {

		if(contentFormat == MediaTypeRegistry.APPLICATION_JSON) {
			try
			{
			    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
			        .setAllowedClockSkewInSeconds(30)
			        .setExpectedAudience(aud)
			        .setVerificationKey(config.getSignAndEncryptKey().getPublicKey())
			        .build();

			    //  Validate the JWT and process it to the Claims
			    JwtClaims jwtClaims = jwtConsumer.processToClaims(new String(accessToken));
			    
			    Assert.assertTrue(jwtClaims.getAudience().contains(aud));
			}
			catch (Exception e)
			{
				Assert.fail("Could not validate token.");
			}
		}
		else if(contentFormat == MediaTypeRegistry.APPLICATION_CBOR) {
			Assert.fail("Not implemented.");
		}
	}
}
