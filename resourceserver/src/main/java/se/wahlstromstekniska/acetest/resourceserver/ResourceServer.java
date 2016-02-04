package se.wahlstromstekniska.acetest.resourceserver;

import org.apache.log4j.Logger;

public class ResourceServer {
	
	final static Logger logger = Logger.getLogger(ResourceServer.class);

    static DTLSServer dtlsServer = null;
    static AuthInfoServer authzInfoServer = null;

	public static void main(String[] args) {
        try {
        	dtlsServer = new DTLSServer();
        	dtlsServer.start();

        	authzInfoServer = new AuthInfoServer();
        	authzInfoServer.start();
        } catch (Exception e) {
        	logger.error("Failed to initialize server: " + e.getMessage());
        }
	}
	
}
