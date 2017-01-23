package security;

/**
* This is a simple test of security.
* In actuality, the client would be accessing this through RMI
*/
public class TestSecurity {
	public static void main(String[] args) throws Exception {
		//set up the system
		//in real life, this would involve the system administrator setting up the
		//database and generating the keys.
		SecurityServer server=new SecurityServer();

		AdminSecurity admin=(AdminSecurity)server;
		admin.generateKeys(16);
		//set the password for user 1 to 1001
		admin.setPassword(1, 1001);

		//====================
		//now act as the client
		PublicSecurity pub=(PublicSecurity)server;
		//get the public key
		PublicKey pk=pub.getPublicKey();
		//look at it because we are curious
		System.out.println("pk.E = "+pk.E);
		System.out.println("pk.N = "+pk.N);

		//generate the security token
		//for the password 1001
		String token=new ClientSecurityTool().encrypt(pk,1001);
		System.out.println("token = "+token);

		//now log in with it
		int userid=pub.validate(token);
		System.out.println("userid = "+userid);
		System.out.println("success!");

	}
}