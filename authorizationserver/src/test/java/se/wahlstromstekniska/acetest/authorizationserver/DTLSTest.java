package se.wahlstromstekniska.acetest.authorizationserver;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import org.junit.Test;

public class DTLSTest {

	@Test
	public void addingAndValidatingToken() throws UnknownHostException {
		InetSocketAddress peerAddress = new InetSocketAddress(InetAddress.getLocalHost(), 0);
		System.out.println(peerAddress.toString());
	}
}
