package se.wahlstromstekniska.acetest.resourceserver;

import org.apache.log4j.Logger;

public class ResourceServerRPK {
	
	final static Logger logger = Logger.getLogger(ResourceServerRPK.class);

    static DtlsRPKServer dtlsRPKServer = null;
    static AuthInfoIntrospectionServer authzInfoServer = null;

	public static void main(String[] args) {
        try {
        	dtlsRPKServer = new DtlsRPKServer();
        	dtlsRPKServer.start();

        	authzInfoServer = new AuthInfoIntrospectionServer();
        	authzInfoServer.start();
        } catch (Exception e) {
        	logger.error("Failed to initialize server: " + e.getMessage());
        }
	}
	
}
