package security;
import java.math.BigInteger;

/**
* This sits on the client side.  Encrypt a password using the public key
*/
public class ClientSecurityTool implements ClientSecurity {

	/**
	* This is a relatively simple algorithm.
	* Z=(M^E) mod N
	*
	* This could be static, except it is part of the interface
	*/
	public String encrypt(PublicKey key,int password) {
		BigInteger bigM = BigInteger.valueOf(password);
		BigInteger bigN = new BigInteger(key.N);
		BigInteger bigE = BigInteger.valueOf(key.E);

		BigInteger encrypted = bigM.modPow(bigE,bigN);
		//this could also be in another radix to make it more confusing
		//but keep it simple for the demo.
		return encrypted.toString();
	}
}