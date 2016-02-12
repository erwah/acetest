package se.wahlstromstekniska.acetest.resourceserver;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;

public class AuthInfoIntrospectionServer extends CoapServer {
	
	private static ResourceServerConfiguration config = ResourceServerConfiguration.getInstance();

	AuthInfoIntrospectionServer() {
	    add(new AuthzInfoIntrospectionResource());

		for (InetAddress addr : EndpointManager.getEndpointManager().getNetworkInterfaces()) {
			// only binds to IPv4 addresses and localhost
			if (addr instanceof Inet4Address || addr.isLoopbackAddress()) {
				InetSocketAddress bindToAddress = new InetSocketAddress(addr, config.getCoapPort());
				addEndpoint(new CoapEndpoint(bindToAddress));
			}
		}

	}
	
}
