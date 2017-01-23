package security;

/**
* This is used by the client of the security.  Login creates a security token
* used by the system.  Make sure to validate it right away.
*/

public interface ClientSecurity {
	/**
	* Generate a security token from the password.  Note that you do not need
	* userid because passwords are unique in the system and it can look up
	* who you are.
	*/
	public String encrypt(PublicKey key,int password);
}