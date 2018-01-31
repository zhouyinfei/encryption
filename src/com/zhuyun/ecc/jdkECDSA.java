package com.zhuyun.ecc;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class jdkECDSA{
	
	public static void jdkECDSA(String src) {
	    try {
	      //1.��ʼ����Կ
	      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
	      keyPairGenerator.initialize(112);
	      KeyPair keyPair = keyPairGenerator.generateKeyPair();
	      ECPublicKey ecPublicKey = (ECPublicKey)keyPair.getPublic();
	      ECPrivateKey ecPrivateKey = (ECPrivateKey)keyPair.getPrivate();
	      
	      System.out.println(ecPublicKey);
	      System.out.println(ecPrivateKey);
	      
	      //2.ִ��ǩ��
	      PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(ecPrivateKey.getEncoded());
	      KeyFactory keyFactory = KeyFactory.getInstance("EC");
	      PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
	      Signature signature = Signature.getInstance("SHA1withECDSA");
	      signature.initSign(privateKey);
	      signature.update(src.getBytes());
	      byte[] result = signature.sign();
	      System.out.println("jdk ecdsa sign : " + new String(result));
	      
	      //3.��֤ǩ��
	      X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(ecPublicKey.getEncoded());
	      keyFactory = KeyFactory.getInstance("EC");
	      PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
	      signature = Signature.getInstance("SHA1withECDSA");
	      signature.initVerify(publicKey);
	      signature.update(src.getBytes());
	      boolean bool = signature.verify(result);
	      System.out.println("jdk ecdsa verify : " + bool);
	    } catch (Exception e) {
	      e.printStackTrace();
	    }
	}
	
	public static void main(String[] args) {
		jdkECDSA("hello world");
	}
 }