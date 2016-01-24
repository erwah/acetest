package se.wahlstromstekniska.acetest.authorizationserver;

import java.util.Date;

import org.junit.Assert;
import org.junit.Test;

public class ResourceServerTest {

	ResourceServer rs = new ResourceServer("myRS");
	
	String exampleToken = "eyJraWQiOiJBUyBzaWduaW5nIGtleSIsImFsZyI6IkVTMjU2In0.eyJhdWQiOiJ0ZW1wU2Vuc29ySW5MaXZpbmdSb29tIiwianRpIjoidFN4bHlDRlV0N3dzTmNQMFI2UUJFdyIsImlhdCI6MTQ1MzU2NTg2NSwgImNuZiI6IHsiandrIjp7Imt0eSI6IkVDIiwia2lkIjoiYXNnZW5lcmF0ZWRLZXkiLCJ4IjoibW1hQWhEMlpGLVpOV1dNWGRXY2E3VzBrTGlMN2ZrWTVjUVpFRGROUkVnWSIsInkiOiJKa3V1ZDFwZUpEeUhQS1VwZklQQ2xaaUhwQVl5U0dWLUVqU0tSbWZCTFc4IiwiY3J2IjoiUC0yNTYifX19.hvBDRTFg-f6NP6xPON4Lk42TpLeQ0A33ztNxSG90EJywWAQs7POhHoI-5ZNVpKuw-bI6yRNbDepmM2cnSwwMiw";
	
	AccessToken validToken = new AccessToken();
	

	@Test
	public void addingAndValidatingToken() {
		validToken.setAccessToken(exampleToken);
		validToken.setAudience("myRS");
		validToken.setIssuedAt(new Date(1453565865));
		
		// check aud name
		Assert.assertEquals("myRS", rs.getAud());

		// add a token
		rs.addAccessToken(validToken);
		
		// validate token
		Assert.assertTrue(rs.validateToken(exampleToken));

		// remove token
		rs.removeAccessToken(validToken);;

		// token should not be valid any more when removed
		Assert.assertFalse(rs.validateToken(exampleToken));

	}
	
	@Test
	public void addingMiltipleTokens() {
		AccessToken t1 = new AccessToken();
		t1.setAccessToken("t1");
		AccessToken t2 = new AccessToken();
		t2.setAccessToken("t2");
		AccessToken t3 = new AccessToken();
		t3.setAccessToken("t3");

		// add 3 tokens
		rs.addAccessToken(t1);
		rs.addAccessToken(t2);
		rs.addAccessToken(t3);

		// see if we can find second token
		Assert.assertTrue(rs.validateToken("t2"));
	}

}
