package se.wahlstromstekniska.acetest.authorizationserver;

import org.junit.Assert;
import org.junit.Test;

public class ClientAuthenticationTest {

	private static ServerConfiguration config = ServerConfiguration.getInstance();
	
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
		
		for (Client client : config.getClients()) {
			Assert.assertTrue(auth.authenticate(client.getClient_id(), client.getClient_secret()));
		}
	}

	@Test
	public void wrongTestCreds() {
		Assert.assertFalse(auth.authenticate("wrong", "creds"));
	}

}
