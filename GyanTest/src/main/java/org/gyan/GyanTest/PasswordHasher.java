package org.gyan.GyanTest;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class PasswordHasher {
	
	static String password = "webapp123";
	static String salt = "1234";
	static int iterations = 10000;
	static int keyLength = 512;
	static char[] passwordChars = password.toCharArray();
	static byte[] saltBytes = salt.getBytes();
	
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, DecoderException {
		byte[] hashedBytes = hashPassword(passwordChars,saltBytes, iterations, keyLength);
		String hashedString = Hex.encodeHexString(hashedBytes);
		
		System.out.println(hashedString);
		
		boolean matched = validatePassword("webapp123", hashedString);	
		System.out.println(matched);
		
		matched = validatePassword("webapp12", hashedString);	
		System.out.println(matched);
			
	}
	
	
	
	private static byte[] hashPassword(final char[] password, final byte[] salt, final int iterations,final int keyLength)
	{
		try{

			SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
			SecretKey key = skf.generateSecret(spec);
			byte[] res = key.getEncoded();
			return res;

		} catch (NoSuchAlgorithmException | InvalidKeySpecException e)
		{
			throw new RuntimeException();
		}
	}
	
	 private static boolean validatePassword(String originalPassword, String storedPassword) throws NoSuchAlgorithmException, InvalidKeySpecException, DecoderException

	 { PBEKeySpec spec = new PBEKeySpec(originalPassword.toCharArray(), saltBytes, iterations,keyLength);

	 SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

	 byte[] testHash = skf.generateSecret(spec).getEncoded();

	 byte[] stored_pass = Hex.decodeHex(storedPassword);

	 return Arrays.equals(testHash, stored_pass);

	 }
}
