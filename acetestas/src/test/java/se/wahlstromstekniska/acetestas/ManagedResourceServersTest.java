package se.wahlstromstekniska.acetestas;

import org.junit.Assert;
import org.junit.Test;

public class ManagedResourceServersTest {

	private static ManagedResourceServers managedResourceServers = ManagedResourceServers.getInstance();

	@Test
	public void addingResources() {
		
		try {
			managedResourceServers.addResourceServer(new ResourceServer("anRS"));
			ResourceServer rs = managedResourceServers.getResourceServer("anRS");
			Assert.assertTrue(rs.getAud().equals("anRS"));

		} catch (Exception e) {
			// should not happen
			Assert.fail("Code say it's adding multiple RS's when it's actually not.");
		}
	}
	
	@Test
	public void removingResources() {
		
		try {
			managedResourceServers.removeResourceServer("anRS");
			ResourceServer rs = managedResourceServers.getResourceServer("anRS");
			Assert.assertNull(rs);
		} catch (Exception e) {
			// should not happen
			Assert.fail("Code say it's adding multiple RS's when it's actually not.");
		}
	}

	@Test
	public void addMultipleResources() {
		
		try {

			managedResourceServers.addResourceServer(new ResourceServer("aSecondRS"));
			managedResourceServers.addResourceServer(new ResourceServer("aThirdRS"));
			ResourceServer rs = managedResourceServers.getResourceServer("aSecondRS");
			Assert.assertNotNull(rs);

			managedResourceServers.removeResourceServer("aSecondRS");
			rs = managedResourceServers.getResourceServer("aThirdRS");
			Assert.assertNotNull(rs);
		
		} catch (Exception e) {
			// should not happen
			Assert.fail("Code say it's adding multiple RS's when it's actually not.");
		}
	}

	@Test
	public void addingDuplicates() {
		try {
			managedResourceServers.addResourceServer(new ResourceServer("anRS"));
			managedResourceServers.addResourceServer(new ResourceServer("anRS"));
			
			Assert.fail("Should not go down to here. Should have thrown exception instead.");
		} catch (Exception e) {
			// as it should be
		}

	}

}
