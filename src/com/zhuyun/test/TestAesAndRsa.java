package com.zhuyun.test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import org.junit.Test;

import com.zhuyun.aes.AESUtil;
import com.zhuyun.rsa.RSAUtil;

public class TestAesAndRsa {

	//����RSA��AES�Ľ�ϡ�
	//					�ͻ����ù�Կ����AES��Կ��AES��Կ����ʵ�����ݣ�
	//					�������˽Կ����AES��Կ��AES��Կ����ʵ������
	@Test
	public void testAesAndRsa() throws Exception {
		//===============���ɹ�Կ��˽Կ����Կ�����ͻ��ˣ�˽Կ����˱���==================
		//����RSA��Կ��˽Կ����Base64���룬����һ���Ժ󣬾�д���������ļ�������У��´β�����������
		KeyPair keyPair = RSAUtil.getKeyPair();
		String publicKeyStr = RSAUtil.getPublicKey(keyPair);
		String privateKeyStr = RSAUtil.getPrivateKey(keyPair);
		System.out.println("RSA��ԿBase64����:" + publicKeyStr);
		System.out.println("RSA˽ԿBase64����:" + privateKeyStr);
		
		//=================�ͻ���=================
		//hello, i am infi, good night!  ��Ҫ���ܵ�ʵ������
		String message = "hello, i am infi, good night!";
		//��Base64�����Ĺ�Կת����PublicKey����
		PublicKey publicKey = RSAUtil.string2PublicKey(publicKeyStr);
		//����AES��Կ����Base64����
		String aesKeyStr = AESUtil.genKeyAES();
		System.out.println("AES��ԿBase64����:" + aesKeyStr);
		//�ù�Կ����AES��Կ
		byte[] publicEncrypt = RSAUtil.publicEncrypt(aesKeyStr.getBytes(), publicKey);
		//��Կ����AES��Կ�������Base64����
		String publicEncryptStr = RSAUtil.byte2Base64(publicEncrypt);
		System.out.println("��Կ����AES��Կ��Base64����Ľ����" + publicEncryptStr);
		
		//��Base64������AES��Կת����SecretKey����
		SecretKey aesKey = AESUtil.loadKeyAES(aesKeyStr);
		//��AES��Կ����ʵ�ʵ�����
		byte[] encryptAES = AESUtil.encryptAES(message.getBytes(), aesKey);
		//AES��Կ���ܺ������Base64����
		String encryptAESStr = AESUtil.byte2Base64(encryptAES);
		System.out.println("AES��Կ����ʵ�ʵ����ݲ�Base64����Ľ����" + encryptAESStr);
		
		
		//##############	�����ϴ����������Base64�����Ĺ�Կ����AES��Կ�Ľ�� �� Base64������AES��Կ����ʵ�����ݵĽ��   #################
		//##############	��publicEncryptStr��encryptAESStr	###################
		
		
		//===================�����================
		//��Base64������˽Կת����PrivateKey����
		PrivateKey privateKey = RSAUtil.string2PrivateKey(privateKeyStr);
		//��Կ����AES��Կ�������(Base64����)������Base64����
		byte[] publicEncrypt2 = RSAUtil.base642Byte(publicEncryptStr);
		//��˽Կ����,�õ�aesKey
		byte[] aesKeyStrBytes = RSAUtil.privateDecrypt(publicEncrypt2, privateKey);
		//���ܺ��aesKey
		String aesKeyStr2 = new String(aesKeyStrBytes);
		System.out.println("���ܺ��aesKey(Base64����): " + aesKeyStr2);
		
		//��Base64������AES��Կת����SecretKey����
		SecretKey aesKey2 = AESUtil.loadKeyAES(aesKeyStr2);
		//AES��Կ���ܺ������(Base64����)������Base64����
		byte[] encryptAES2 = AESUtil.base642Byte(encryptAESStr);
		//��AES��Կ����ʵ�ʵ�����
		byte[] decryptAES = AESUtil.decryptAES(encryptAES2, aesKey2);
		//���ܺ��ʵ������
		System.out.println("���ܺ��ʵ������: " + new String(decryptAES));
	}

}
