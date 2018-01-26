package com.zhuyun.test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.Test;

import com.zhuyun.rsa.RSAUtil;

public class TestRSA {

	@Test
	public void testRSA(){
		try {
			//===============���ɹ�Կ��˽Կ����Կ�����ͻ��ˣ�˽Կ����˱���==================
			//����RSA��Կ��˽Կ����Base64����
			KeyPair keyPair = RSAUtil.getKeyPair();
			String publicKeyStr = RSAUtil.getPublicKey(keyPair);
			String privateKeyStr = RSAUtil.getPrivateKey(keyPair);
			System.out.println("RSA��ԿBase64����:" + publicKeyStr);
			System.out.println("RSA˽ԿBase64����:" + privateKeyStr);
			
			//=================�ͻ���=================
			//hello, i am infi, good night!����
			String message = "hello, i am infi, good night!";
			//��Base64�����Ĺ�Կת����PublicKey����
			PublicKey publicKey = RSAUtil.string2PublicKey(publicKeyStr);
			//�ù�Կ����
			byte[] publicEncrypt = RSAUtil.publicEncrypt(message.getBytes(), publicKey);
			//���ܺ������Base64����
			String byte2Base64 = RSAUtil.byte2Base64(publicEncrypt);
			System.out.println("��Կ���ܲ�Base64����Ľ����" + byte2Base64);
			
			
			//##############	�����ϴ����������Base64�����Ĺ�Կ �� Base64�����Ĺ�Կ���ܵ�����     #################
			
			
			
			//===================�����================
			//��Base64������˽Կת����PrivateKey����
			PrivateKey privateKey = RSAUtil.string2PrivateKey(privateKeyStr);
			//���ܺ������Base64����
			byte[] base642Byte = RSAUtil.base642Byte(byte2Base64);
			//��˽Կ����
			byte[] privateDecrypt = RSAUtil.privateDecrypt(base642Byte, privateKey);
			//���ܺ������
			System.out.println("���ܺ������: " + new String(privateDecrypt));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
