# SimpleSecurity
This is a simple Public Key encryption system.

This is a first-pass at a simple public key encryption system.  It is certainly better than nothing, and this could be made
more robust.  This needs more testing and could contain an error or bug.

To use it, first set up the system by generating the keys to the desired number of bits.  I use 16 bits for this example, 
but RSA uses 2048. Add users, with passwords.  For a password, I use a number greater than 1000.

For client use, the client requests the PublicKey and uses it to encrypt the password into a token.  With the test here,
it generates a 10-digit number.  The client uses this instead of the actual password to login.

The password is never sent over the wire in plaintext and is never stored in the database in plaintext.  Given the public key
and the token, the NSA could easily decrypt it.  Anyone else would have problems.

The decryption key is calculated, but it is never used.  Instead the password is just stored in the database encrypted,
and then this value is checked.

To improve this, you could increase the number of bits.
