package se.wahlstromstekniska.acetest.authorizationserver;

import org.junit.Assert;
import org.junit.Test;

public class ClientAuthenticationTest {

	ClientAuthentication auth = new ClientAuthentication();

	@Test
	public void emptyCreds() {
		
		Assert.assertFalse(auth.authenticate(null, null));
		Assert.assertFalse(auth.authenticate("", null));
		Assert.assertFalse(auth.authenticate(null, ""));
		Assert.assertFalse(auth.authenticate("", ""));
		Assert.assertFalse(auth.authenticate("", " "));
		Assert.assertFalse(auth.authenticate(" ", " "));
		Assert.assertFalse(auth.authenticate(null, " "));
		Assert.assertFalse(auth.authenticate(" ", null));
	}


	@Test
	public void realTestCreds() {
		Assert.assertTrue(auth.authenticate("myclient", "qwerty"));
	}

	@Test
	public void wrongTestCreds() {
		Assert.assertFalse(auth.authenticate("wrong", "creds"));
	}

}
