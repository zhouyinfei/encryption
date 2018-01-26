package com.zhuyun.test;

import javax.crypto.SecretKey;

import org.junit.Test;

import com.zhuyun.aes.AESUtil;

public class TestAES {

	@Test
	public void testAES(){
		try {
			//=================客户端=================
			//hello, i am infi, good night!加密
			String message = "hello, i am infi, good night!";
			//生成AES秘钥，并Base64编码
			String base64Str = AESUtil.genKeyAES();
			System.out.println("AES秘钥Base64编码:" + base64Str);
			//将Base64编码后的AES秘钥转换成SecretKey对象
			SecretKey aesKey = AESUtil.loadKeyAES(base64Str);
			//加密
			byte[] encryptAES = AESUtil.encryptAES(message.getBytes(), aesKey);
			//加密后的内容Base64编码
			String byte2Base64 = AESUtil.byte2Base64(encryptAES);
			System.out.println("加密并Base64编码的结果：" + byte2Base64);
			
			
			//##############	网络上传输的内容有Base64编码后的秘钥 和 Base64编码加密后的内容		#################
			
			
			//===================服务端================
			//将Base64编码后的AES秘钥转换成SecretKey对象
			SecretKey aesKey2 = AESUtil.loadKeyAES(base64Str);
			//加密后的内容Base64解码
			byte[] base642Byte = AESUtil.base642Byte(byte2Base64);
			//解密
			byte[] decryptAES = AESUtil.decryptAES(base642Byte, aesKey2);
			//解密后的明文
			System.out.println("解密后的明文: " + new String(decryptAES));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
