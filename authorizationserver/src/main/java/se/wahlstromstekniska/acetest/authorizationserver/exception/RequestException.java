package se.wahlstromstekniska.acetest.authorizationserver.exception;

public class RequestException extends Exception {

	private static final long serialVersionUID = 1L;

	private int reason = 0;
	
	public static int MISSING_GRANT = 1;
	
	public RequestException(String msg, int reason) {
		super(msg);
		this.setReason(reason);
	}

	public int getReason() {
		return reason;
	}

	public void setReason(int reason) {
		this.reason = reason;
	}

}
