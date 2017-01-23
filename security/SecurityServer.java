package security;
import java.rmi.*;
import java.util.Hashtable;
import java.util.Enumeration;
import java.util.Random;
import java.math.BigInteger;


/**
* This is the SecurityServer.  A real version would also update the database
* but this doesn't.  The PublicSecurity interface is available remotely,
* the AdminSecurity interface isn't.
*
* Note that in this implementation, I never decrypt the password, although
* I have the tools to do so.
*/
public class SecurityServer implements PublicSecurity, AdminSecurity {
	//this would go into a users table
	Hashtable userTable=new Hashtable();

	//these are the parts of the encryption.  Would go into the database.
	long E;
	BigInteger P;	//random prime number 1
	BigInteger Q;	//random prime number 2

	//calculated
	BigInteger N;	//product of P * Q
	BigInteger F;	//totient
	BigInteger D;	//decryption key


	public PublicKey getPublicKey() throws RemoteException {
		return new PublicKey(E,N.toString());
	}

	/**
	* Return userid or 0 if failure
	*/
	public int validate(String token) throws RemoteException {
		return getUserID(token);
	}

	/**
	* Change to the new password.  Return an error code.
	* These are encrypted.
	*/
	public boolean changePassword(String old,String newPassword) throws RemoteException {
		//keep this simple.
		//find userid for old password
		int userid=validate(old);

		if (userid<1) {
			System.out.println("user not found");
			return false;
		} else {
			//just set new password
			userTable.put(Integer.valueOf(userid),newPassword);
			return true;
		}
	}

	//==================================
	//we are keeping this VERY simple.  numBits must be from 16..128.  A real system
	//would use 2048.
	public void generateKeys(int numBits) {
		if (numBits<16 || numBits>128) {
			throw new IllegalArgumentException("numBits must be in the range 16..128");
		}

		//first get 3 prime numbers.
		//the first is hard-coded to 65537
		E = 65537L;
		P = randomPrime(numBits);
		//I make Q a little bigger.  We could use the same number of bits since
		//it is random
		Q = randomPrime(numBits+1);

		//calculations
		//1. calculate public key
		N = P.multiply(Q);

		//2. calculate totient
		BigInteger pm=P.subtract(BigInteger.ONE);
		BigInteger qm=Q.subtract(BigInteger.ONE);
		F = pm.multiply(qm);

		//3. calculate decryption key
		D = calculateDecryptionKey(F,BigInteger.valueOf(E));
		System.out.println("decryption key = "+D);
	}


	private BigInteger randomPrime(int numBits) {
		return BigInteger.probablePrime(numBits,new Random());
	}

	/**
	* X in the formula here is any number that will work for integer division by E.
	*	It must be discovered by trial and error.
	* 	Formula: D =(F*X+1)/E
	*
	* This could take a minute or so
	*/
	private BigInteger calculateDecryptionKey(BigInteger f,BigInteger e) {
		System.out.println("calculating decryption key.  this could take a minute");
		System.out.println("e = "+e.toString());
		System.out.println("f = "+f.toString());

		int x=1;
		//put an upper limit on this. hopefully the number won't be too big
		while(x<1000000000) {
			BigInteger bx=BigInteger.valueOf(x);
			//sub = f * x + 1
			BigInteger subtotal=f.multiply(bx).add(BigInteger.ONE);
			//m = sub mod e
			BigInteger m = subtotal.mod(e);
			//System.out.println("for x = "+bx.toString()+", f*x+1 = "+subtotal.toString()+", mod e = "+ m.toString());
			if (m.equals(BigInteger.ZERO)) {
				//we have a winner
				return subtotal.divide(e);
			}
			x++;
		}
		//shouldn't happen
		throw new IllegalStateException("can't find decryption key");
	}

	/**
	* this is the counterpart - not the opposite of - encrypt
	* the formula is: [A=(Z^D) mod N]
	* I don't think we really need this since the password is stored encrypted
	* not in plaintext. This is just a double-check
	*/
	private static long decrypt(String z,BigInteger D,BigInteger N) {
		BigInteger bz = new BigInteger(z);
		BigInteger ba = bz.modPow(D,N);
		return ba.longValue();
	}

	//====================
	//the exact same as ClientSecurityTool.encrypt
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
	//======================

	/**
	* The password is set in plaintext, however, it is not stored that way.
	* A password must be unique between users because it is used to look
	* up the userid.  There may be other rules as well.  This will return false
	* if the password is not valid.  Just try again with a different password.
	*
	* Password is a 4-6 digit number.
	*
	* This will overwrite an existing password
	*/
	public boolean setPassword(int userid, int password) {
		if (userid<1) {
			throw new IllegalArgumentException("userid must be at least 1");
		}
		Integer user=Integer.valueOf(userid);
		//encrypt it
		try {
			PublicKey pk=getPublicKey();
			String token=encrypt(pk,password);

			//now see if it is already in the database
			Enumeration en=userTable.keys();
			while (en.hasMoreElements()) {
				Integer u=(Integer)en.nextElement();
				String v=(String)userTable.get(u);
				if (token.equals(v)) {
					return false;
				}
			}

			//the check passed.  now store it
			//this does not check for a duplicate entry.
			userTable.put(user,token);
			return true;
		} catch (RemoteException x) {
			System.out.println(x.getMessage());
			return false;
		}
	}


	//get userid or 0 if not found
	public int getUserID(String token) {
		Enumeration en=userTable.keys();
		while (en.hasMoreElements()) {
			Integer u=(Integer)en.nextElement();
			String v=(String)userTable.get(u);
			if (token.equals(v)) {
				return u.intValue();
			}
		}
		return 0; //not found
	}
}