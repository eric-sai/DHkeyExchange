package crypto.students;

import java.math.BigInteger;
//import java.nio.ByteBuffer;
//import java.nio.LongBuffer;


import org.apache.log4j.Logger;

/***
 * In this class all the candidates must implement the methods
 * related to key derivation. You can create auxiliary functions
 * if you need it, using ONLY Java standard classes.
 * 
 * @author Pablo Serrano
 */
public class Supplementary {
	
	private static Logger log = Logger.getLogger(Supplementary.class);
	
	/***
	 * Receives a 2048 bits key and applies a word by word XOR
	 * to yield a 64 bit integer at the end.
	 * 
	 * @param key 2048 bit integer form part A1 DH Key Exchange Protocol
	 * @return A 64 bit integer
	 */
	public static BigInteger parityWordChecksum(BigInteger key) {
		String k=key.toString(2);
//		System.out.println(k);
		String[]bits= new String[32];
		while(k.length()<2048)
		{
			 k="0"+k;
		}
//		System.out.println(k.length());
		for (int i=0;i<bits.length;i++)
		{
			if(k.length()-(i+1)*64>=0)
			{
			bits[i]=k.substring(k.length()-(i+1)*64,k.length()-i*64);
			}
			else
			{
				bits[i]=k.substring(0,k.length()-i*64);	
			}
		}
//test
//		for(int a=0;a<bits.length; a++)
//		{
//		
//				System.out.println(bits[a]);
//			
//		}
		BigInteger ret= new BigInteger(bits[0],2);
		for(int b=1;b<32;b++)
		{
			ret=ret.xor(new BigInteger(bits[b],2));
		}
		return ret;
//		byte[] bits=key.toByteArray();
//		int length= bits.length;
//		byte[] r=new byte[8];
//		for(int i=0;i<length;i++)
//		{
//		//	System.out.println("every byte in key"+bits[i]);
//			if(i<8)
//			{
//				r[i]=bits[i];
//		//		System.out.println("every 8 bits"+r[i]);
//			}
//			else
//			{
//				r[i%8]=(byte) (r[i%8] ^ bits[i]);
//			}
//			
//		}
////		System.out.println(key.bitLength());
////		System.out.println(length);
////		System.out.println(new BigInteger(r).bitLength());
//		return new BigInteger(r);


//		LongBuffer buffer = ByteBuffer.wrap(key.toByteArray()).asLongBuffer();
//		long xor = 0;
//		while (buffer.hasRemaining()) {
//			xor ^= buffer.get();
//		}
//		System.out.println(BigInteger.valueOf(xor).bitLength());
//		return BigInteger.valueOf(xor);


	}

	/***
	 *  key modulus p
	 * @param key 2048 bit integer form part A1 DH Key Exchange Protocol
	 * @param p A random 64 bit prime integer
	 * @return A 64 bit integer for use as a key for a Stream Cipher
	 */
	public static BigInteger deriveSuppementaryKey(BigInteger key, BigInteger p) {
	//	log.error("You must implement this function!");
	
		return key.mod(p);
	}
}
