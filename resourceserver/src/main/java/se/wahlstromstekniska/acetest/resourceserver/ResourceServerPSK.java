package se.wahlstromstekniska.acetest.resourceserver;

import org.apache.log4j.Logger;

public class ResourceServerPSK {
	
	final static Logger logger = Logger.getLogger(ResourceServerPSK.class);

    static DtlsPSKServer dtlsPSKServer = null;
    static AuthInfoLocalValidationServer authzInfoServer = null;

	public static void main(String[] args) {
        try {
        	dtlsPSKServer = new DtlsPSKServer();
        	dtlsPSKServer.start();

        	authzInfoServer = new AuthInfoLocalValidationServer();
        	authzInfoServer.start();
        } catch (Exception e) {
        	logger.error("Failed to initialize server: " + e.getMessage());
        }
	}
	
}
