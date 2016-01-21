package se.wahlstromstekniska.acetestas;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class ClientAuthenticationTest {

	private static ClientAuthentication auth = ClientAuthentication.getInstance();


	@Before
	public void startupServer() throws Exception {
        auth.addClient(new ClientCredentials("myclient", "qwerty"));
	}

	@After
	public void shutdownServer() {
		auth.deleteClient("myclient");
	}
	
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
