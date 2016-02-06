package se.wahlstromstekniska.acetest.resourceserver;

import org.apache.log4j.Logger;

public class ResourceServer {
	
	final static Logger logger = Logger.getLogger(ResourceServer.class);

    static DtlsRPKServer dtlsServer = null;
    static AuthInfoServer authzInfoServer = null;

	public static void main(String[] args) {
        try {
        	dtlsServer = new DtlsRPKServer();
        	dtlsServer.start();

        	authzInfoServer = new AuthInfoServer();
        	authzInfoServer.start();
        } catch (Exception e) {
        	logger.error("Failed to initialize server: " + e.getMessage());
        }
	}
	
}
