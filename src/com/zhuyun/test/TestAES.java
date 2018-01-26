package com.zhuyun.test;

import javax.crypto.SecretKey;

import org.junit.Test;

import com.zhuyun.aes.AESUtil;

public class TestAES {

	@Test
	public void testAES(){
		try {
			//=================�ͻ���=================
			//hello, i am infi, good night!����
			String message = "hello, i am infi, good night!";
			//����AES��Կ����Base64����
			String base64Str = AESUtil.genKeyAES();
			System.out.println("AES��ԿBase64����:" + base64Str);
			//��Base64������AES��Կת����SecretKey����
			SecretKey aesKey = AESUtil.loadKeyAES(base64Str);
			//����
			byte[] encryptAES = AESUtil.encryptAES(message.getBytes(), aesKey);
			//���ܺ������Base64����
			String byte2Base64 = AESUtil.byte2Base64(encryptAES);
			System.out.println("���ܲ�Base64����Ľ����" + byte2Base64);
			
			
			//##############	�����ϴ����������Base64��������Կ �� Base64������ܺ������		#################
			
			
			//===================�����================
			//��Base64������AES��Կת����SecretKey����
			SecretKey aesKey2 = AESUtil.loadKeyAES(base64Str);
			//���ܺ������Base64����
			byte[] base642Byte = AESUtil.base642Byte(byte2Base64);
			//����
			byte[] decryptAES = AESUtil.decryptAES(base642Byte, aesKey2);
			//���ܺ������
			System.out.println("���ܺ������: " + new String(decryptAES));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
