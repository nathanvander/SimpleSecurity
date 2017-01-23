package security;
import java.rmi.*;

/**
* This is the public facing security interface for security.
*
* This is not meant to be secure in a cryptographic sense, but just to be
* better than plaintext.  It uses a simple form of public key encryption.
*
* The rules are: the password is never transmitted across the network in plaintext
* and it is never stored in the password in plaintext.
*
* Password as used here is a 4-6 digit number, like a pin.
*/
public interface PublicSecurity extends Remote {
		public PublicKey getPublicKey() throws RemoteException;

		/**
		* Validate the token.
		* Returns userid if valid, else 0 for failure
		*/
		public int validate(String token) throws RemoteException;

		/**
		* Change to the new password.  Returns true if success
		* or false for failure.  There could be several reasons for failure
		* but I am keeping it simple.
		*/
		public boolean changePassword(String old,String newPassword) throws RemoteException;

}