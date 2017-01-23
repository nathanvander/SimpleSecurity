package security;

/**
* Public key has the information necessary to encrypt the password.
*/
public class PublicKey implements java.io.Serializable {
	/**
	* E is a smaller prime number, which is the exponent during the encryption
	* process.
	*/
	public long E;
	/**
	* N is a composite number which is the product of two prime numbers.
	* It would be very easy to factor, but this is just a demo.
	*/
	public String N;

	public PublicKey(long e1,String n1) {
		E=e1;
		N=n1;
	}
}