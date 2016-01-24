package se.wahlstromstekniska.acetest.authorizationserver.exception;

public class InvalidJsonException extends Exception {

	private static final long serialVersionUID = 1L;

	public InvalidJsonException(String msg) {
		super(msg);
	}

}
