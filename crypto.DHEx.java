package crypto.students;

import java.math.BigInteger;
import java.util.Random;

import org.apache.log4j.Logger;

/***
 * In this class, all the candidates must implement their own
 * math and crypto functions required to solve any calculation 
 * and encryption/decryption task involved in this project.
 * 
 * 
 *
 */
public class DHEx {
	
	// debug logger
	private static Logger log = Logger.getLogger(DHEx.class);
	
	private static Random rnd = new Random();
	
	public static BigInteger createPrivateKey(int size) {
	//	log.debug("You must implement this function!");
		return new BigInteger(size,rnd);
		//return BigInteger.ONE;
	}
/**
 * create a pair of key
 * @param generator-generator for key generation
 * @param prime- a prime number from server
 * @param skClient - a secrete key that cleint chosen
 * @return a pair of key the zeroth place is secrete key, the other is the client's public key
 */
	public static BigInteger[] createDHPair(BigInteger generator, BigInteger prime, 
			BigInteger skClient) {
		BigInteger[] pair = new BigInteger[2];
//		log.debug("You must implement this function!");
		pair[0] = skClient;
		pair[1] = modExp(generator,skClient,prime);
		return pair;
	}
	/**
	 * get the shared key between server and client
	 * @param pk-public key from server
	 * @param sk-private key from client
	 * @param prime- prime number
	 * @return a shared key between server and client
	 */
	public static BigInteger getDHSharedKey(BigInteger pk, BigInteger sk, BigInteger prime) {
	//	BigInteger shared = BigInteger.ZERO;
	//	log.debug("You must implement this function!");
		BigInteger shared = modExp(pk,sk,prime);
		return shared;
	}
	/**
	 * a modulus exponential function
	 * @param base- a base number
	 * @param exp- an exponential number
	 * @param modulo- a modulus number
	 * @return the result that base^exp modulus modulo
	 */
	public static BigInteger modExp(BigInteger base, BigInteger exp, BigInteger modulo) {
	//	log.debug("You must implement this function!");
		BigInteger two = BigInteger.ONE.add(BigInteger.ONE);	
		
		if (modulo.compareTo(BigInteger.ZERO)==-1 || modulo.equals(BigInteger.ZERO))
		    throw new ArithmeticException("non-positive modulo");
		if(exp.compareTo(BigInteger.ZERO)==-1)
			return modExp(modulo.modInverse(modulo),exp.negate(),modulo);
		//when exponential is zero, no matter what base is, it will equal to 1 and any module is still 1.
		if (exp.equals(BigInteger.ZERO))
			return BigInteger.ONE;
		//if the exponential is one, the function has become base mod modulo.
		if (exp.equals(BigInteger.ONE))
			return base.mod(modulo);
		
		if (exp.mod(two).equals(BigInteger.ZERO)) {
			BigInteger ans = modExp(base, exp.divide(two), modulo);

			return (ans.multiply(ans)).mod(modulo);
		}	
		return (base.multiply(modExp(base,exp.subtract(BigInteger.ONE),modulo))).mod(modulo);
	//	return BigInteger.ZERO;
	}
}
