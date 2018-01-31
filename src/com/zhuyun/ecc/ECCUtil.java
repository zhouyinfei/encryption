package com.zhuyun.ecc;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import com.zhuyun.aes.AESUtil;

public class ECCUtil {
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	
	//������Կ��
	public static KeyPair getKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
		keyPairGenerator.initialize(256, new SecureRandom());
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}
	
	//��ȡ��Կ(Base64����)
	public static String getPublicKey(KeyPair keyPair){
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		byte[] bytes = publicKey.getEncoded();
		return AESUtil.byte2Base64(bytes);
	}
	
	//��ȡ˽Կ(Base64����)
	public static String getPrivateKey(KeyPair keyPair){
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
		byte[] bytes = privateKey.getEncoded();
		return AESUtil.byte2Base64(bytes);
	}
	
	//��Base64�����Ĺ�Կת����PublicKey����
	public static ECPublicKey string2PublicKey(String pubStr) throws Exception{
		byte[] keyBytes = AESUtil.base642Byte(pubStr);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
		ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(keySpec);
		return publicKey;
	}
	
	//��Base64������˽Կת����PrivateKey����
	public static ECPrivateKey string2PrivateKey(String priStr) throws Exception{
		byte[] keyBytes = AESUtil.base642Byte(priStr);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
		ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(keySpec);
		return privateKey;
	}
	
	//��Կ����
	public static byte[] publicEncrypt(byte[] content, PublicKey publicKey) throws Exception{
		Cipher cipher = Cipher.getInstance("ECIES", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] bytes = cipher.doFinal(content);
		return bytes;
	}
	
	//˽Կ����
	public static byte[] privateDecrypt(byte[] content, PrivateKey privateKey) throws Exception{
		Cipher cipher = Cipher.getInstance("ECIES", "BC");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] bytes = cipher.doFinal(content);
		return bytes;
	}
	
	public static void main(String[] args) throws Exception {
		KeyPair keyPair = ECCUtil.getKeyPair();
		String publicKeyStr = ECCUtil.getPublicKey(keyPair);
		String privateKeyStr = ECCUtil.getPrivateKey(keyPair);
		System.out.println("ECC��ԿBase64����:" + publicKeyStr);
		System.out.println("ECC˽ԿBase64����:" + privateKeyStr);
		
		ECPublicKey publicKey = string2PublicKey(publicKeyStr);
		ECPrivateKey privateKey = string2PrivateKey(privateKeyStr);
		
		byte[] publicEncrypt = publicEncrypt("hello world".getBytes(), publicKey);
		byte[] privateDecrypt = privateDecrypt(publicEncrypt, privateKey);
		System.out.println(new String(privateDecrypt));
	}
}
