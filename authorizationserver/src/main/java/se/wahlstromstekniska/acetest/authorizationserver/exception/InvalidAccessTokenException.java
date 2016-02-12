package se.wahlstromstekniska.acetest.authorizationserver.exception;

public class InvalidAccessTokenException extends Exception {

	private static final long serialVersionUID = 1L;

	public InvalidAccessTokenException(String msg) {
		super(msg);
	}

}
