package crypto.students;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.Base64;

import org.apache.log4j.Logger;
public class StreamCipher {
	
	private static Logger log = Logger.getLogger(StreamCipher.class);
	
	private BigInteger key;
	private BigInteger prime;
	private BigInteger p1;
	private BigInteger p2;
	private BigInteger r_i;
	/**
	 * build a new stream cipher
	 * @param share-shared key
	 * @param prime- prime number
	 * @param p- p1 given from server
	 * @param q - p2 given from server
	 */
	public StreamCipher(BigInteger share, BigInteger prime, BigInteger p, BigInteger q) {
		this.key = share; // shared key from DH
		this.prime = prime; // DH prime modulus
		//a= shared key modulus p1
		this.p1 = Supplementary.deriveSuppementaryKey(share, p);
	//	System.out.println(p1)
		//b= shared key modulus p2
		this.p2 = Supplementary.deriveSuppementaryKey(share, q);
	// a little bit problem
	//	this.r_i=Supplementary.parityWordChecksum(this.key);
		this.r_i = BigInteger.ZERO; // shift register
		
	}
	
	/***
	 * Updates the shift register for XOR-ing the next byte.
	 * if r_i is zero, we need to set r_i to a checksum
	 * if not, the r_i=(a*r_i+b) mod p
	 */
	public void updateShiftRegister() {
	//	log.error("You must implement this function!");
		if(this.r_i.equals(BigInteger.ZERO))
		{
			this.r_i=Supplementary.parityWordChecksum(key);
		}
		else
		this.r_i=(p1.multiply(this.r_i).add(p2).mod(prime));
	}

	/***
	 * This function returns the shift register to its initial position
	 * return back to BigInteger Zero
	 */
	public void reset() {
		//log.error("You must implement this function!");
       //need to confirm with lecture.
		this.r_i=BigInteger.ZERO;	
	}
	
	/***
	 * Gets N numbers of bits from the MOST SIGNIFICANT BIT (inclusive).
	 * @param value Source from bits will be extracted
	 * @param n The number of bits taken
	 * @return The n most significant bits from value
	 */
	private byte msb(BigInteger value, int n) {
		//log.error("You must implement this function!");
//		if (value.compareTo(new BigInteger("125"))==0)
//		{
////			//System.out.println("msb"+value.byteValueExact());
//			return value.toByteArray()[1]; 
////			return value.byteValueExact();
//		}
//		else{
////		//	System.out.println("msb"+value.toByteArray()[0]);
//			return value.toByteArray()[0]; 
//		}
		BigInteger temp=value;
		while(temp.bitLength()>8)
		{
		  temp=temp.shiftRight(1);	
		}
		if(temp.toByteArray().length>1)
			return temp.toByteArray()[1];
		else
			return temp.toByteArray()[0];
	}
	
	/***
	 * Takes a cipher text/plain text and decrypts/encrypts it.
	 * For every byte in message, update the r_i and xor the most significant byte of r_i and byte from message
	 * @param msg Either Plain Text or Cipher Text.
	 * @return If PT, then output is CT and vice-versa.
	 */
	public byte[] _crypt(byte[] msg) {
		//log.error("You must implement this function!");
		byte[] E=new byte[msg.length];
		//r_i shift right 
		
		for(int i=0;i<msg.length;i++)
		{
			updateShiftRegister();
			byte tem=this.msb(this.r_i, 8);
		//	System.out.println("test for msb"+tem);
			E[i]=(byte) (msg[i]^tem);
		}
		return E;
	}
	
	//-------------------------------------------------------------------//
	// Auxiliary functions to perform encryption and decryption          //
	//-------------------------------------------------------------------//
	public String encrypt(String msg) {
		// input: plaintext as a string
		// output: a base64 encoded ciphertext string
		log.debug("line to encrypt: [" + msg + "]");
		String result = null;
			result = Base64.getEncoder().encodeToString(_crypt(msg.getBytes()));
			log.debug("encrypted text: [" + result + "]");
		return result;
	}
	
	public String decrypt(String msg) {
		// input: a base64 encoded ciphertext string 
		// output: plaintext as a string
		log.debug("line to decrypt (base64): [" + msg + "]");
		String result = null;
		byte[] asArray;
		try {
			asArray = Base64.getDecoder().decode(msg.getBytes("UTF-8"));
			result = new String(_crypt(asArray));
			log.debug("decrypted text; [" + result + "]");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return result;
	}
}
