package security;

/**
* This would be used by the Security Administrator.  It is not available
* remotely.
*/
public interface AdminSecurity {
	/**
	* Create the public and private keys for the system.  Note that this is a one-time
	* event.  I don't have a provision for changing the keys if the system is
	* compromised.
	*
	* To keep this somewhat simple, the number of bits has a limit of 128.  A real system
	* would use keys that are at least 2048 bits.
	*/
	public void generateKeys(int numBits);

	/**
	* The password is set in plaintext, however, it is not stored that way.
	* A password must be unique between users because it is used to look
	* up the userid.  There may be other rules as well.  This will return false
	* if the password is not valid.  Just try again with a different password.
	*
	* Password is a 4-6 digit number.
	*/
	public boolean setPassword(int userid, int password);

	//returns 0 if not found
	public int getUserID(String token);
}