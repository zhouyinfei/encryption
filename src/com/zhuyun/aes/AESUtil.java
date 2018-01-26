package com.zhuyun.aes;

import java.io.IOException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class AESUtil {
	//����AES��Կ��Ȼ��Base64����
	public static String genKeyAES() throws Exception{
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey key = keyGen.generateKey();
		String base64Str = byte2Base64(key.getEncoded());
		return base64Str;
	}
	
	//��Base64������AES��Կת����SecretKey����
	public static SecretKey loadKeyAES(String base64Key) throws Exception{
		byte[] bytes = base642Byte(base64Key);
		SecretKeySpec key = new SecretKeySpec(bytes, "AES");
		return key;
	}
	
	//����
	public static byte[] encryptAES(byte[] source, SecretKey key) throws Exception{
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(source);
	}
	
	//����
	public static byte[] decryptAES(byte[] source, SecretKey key) throws Exception{
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(source);
	}
	
	//�ֽ�����תBase64����
	public static String byte2Base64(byte[] bytes){
		BASE64Encoder encoder = new BASE64Encoder();
		return encoder.encode(bytes);
	}
	
	//Base64����ת�ֽ�����
	public static byte[] base642Byte(String base64Key) throws IOException{
		BASE64Decoder decoder = new BASE64Decoder();
		return decoder.decodeBuffer(base64Key);
	}
}
