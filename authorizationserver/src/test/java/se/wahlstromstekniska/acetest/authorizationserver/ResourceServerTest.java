package se.wahlstromstekniska.acetest.authorizationserver;

import org.junit.Assert;
import org.junit.Test;

import se.wahlstromstekniska.acetest.authorizationserver.ResourceServer;

public class ResourceServerTest {

	ResourceServer rs = new ResourceServer("myRS");
	
	@Test
	public void test() {
		
		// check aud name
		Assert.assertEquals("myRS", rs.getAud());

		// add a token
		rs.addAccessToken("atoken");
		
		// validate token
		Assert.assertTrue(rs.validateToken("atoken"));

		// remove token
		rs.removeAccessToken("atoken");;

		// token should not be valid any more when removed
		Assert.assertFalse(rs.validateToken("atoken"));

		// add 3 tokens
		rs.addAccessToken("atoken1");
		rs.addAccessToken("atoken2");
		rs.addAccessToken("atoken3");

		// see if we can find second token
		Assert.assertTrue(rs.validateToken("atoken2"));
	}

}
