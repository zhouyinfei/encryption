package com.zhuyun.http.encrypt;

import java.io.InputStream;
import java.security.KeyPair;
import java.util.Properties;

import org.junit.Test;

import com.zhuyun.aes.AESUtil;
import com.zhuyun.ecc.ECCUtil;
import com.zhuyun.rsa.RSAUtil;


public class TestHttpEncrypt {

	@Test
	public void testGenerateKeyPair() throws Exception{
		//生成RSA公钥和私钥，并Base64编码
//		KeyPair keyPair = RSAUtil.getKeyPair();
//		String publicKeyStr = RSAUtil.getPublicKey(keyPair);
//		String privateKeyStr = RSAUtil.getPrivateKey(keyPair);
//		System.out.println("RSA公钥Base64编码:" + publicKeyStr);
//		System.out.println("RSA私钥Base64编码:" + privateKeyStr);
		
		//生成ECC公钥和私钥，并Base64编码
		KeyPair keyPair = ECCUtil.getKeyPair();
		String publicKeyStr = ECCUtil.getPublicKey(keyPair);
		String privateKeyStr = ECCUtil.getPrivateKey(keyPair);
		System.out.println("ECC公钥Base64编码:" + publicKeyStr);
		System.out.println("ECC私钥Base64编码:" + privateKeyStr);
	}
	
	
	@Test
	public void testGenerateAesKey() throws Exception{
		//生成AES秘钥，并Base64编码
		String base64Str = AESUtil.genKeyAES();
		System.out.println("AES秘钥Base64编码:" + base64Str);
	}
	
	//测试  APP加密请求内容
	@Test
	public void testAppEncrypt() throws Exception{
		//APP端公钥和私钥从配置文件读取，不能写死在代码里
		Properties prop = new Properties();
		InputStream in = TestHttpEncrypt.class.getClassLoader().getResourceAsStream("client.properties");
		prop.load(in);
		String appPublicKey = prop.getProperty("app.public.key");
		//请求的实际内容
//		String content = "{\"name\":\"infi\", \"weight\":\"60\"}";
		String content = "{\"tenantid\":\"1\", \"account\":\"13015929018\", \"pwd\":\"123456\"}";
		String result = HttpEncryptUtil.appEncrypt(appPublicKey, content);
		System.out.println(result);
	}
	
	//测试  服务器解密APP的请求内容
	@Test
	public void testServerDecrypt() throws Exception{
		String result = "{\"ak\":\"BGNVrPwbMH8FbR09kF1Ud06o4KGuYm+fruznvLjP95T1BmlXNQi1FBol28k1TRDDbrkc7XomAGD88Q1+3uRJeLPVX04bEqB4LEWPKbpJmsUDn8WYzCubWgmKKMYeyF4IKSTp/7dhlUa3oTTveQ==\",\"apk\":\"MHW1AiTkK6+IbludCThMmKB7muNQrjf6W8tVo1jLXj6s6eUGcFDIm70eNGoJl185yTCkbaGmvJEq8F0BtPLkR7in5n/DiwAicQyXm4wFvWyJl6CEoTYiLffRVL6dHqNm8J2/6udkoCGmqnLsrQXeLZsIueJrZf2rNTWOr3dT4bI=\",\"ct\":\"33itCWpSdZbjda8yJ05FyLDsdZocDUeepBNKxgs0MiR3VH436FbxewnRqT35SkZIXq+eNv3RPFHZIYwyzIWr4A==\"}";
		System.out.println(HttpEncryptUtil.serverDecrypt(result));
	}
	
	//测试 服务器加密响应给APP的内容
	@Test
	public void testserverEncrypt() throws Exception{
		String aesKeyStr = "qCrjqeeICRbN6DqxIhBEZA==";
		String appPublicKeyStr = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFXblKT9aq5X86K+d5RzXpspH4GVwqbSkUc80EbkJn7+ZIejEWba/Io9c5DftUy0AiGXlz9/HgFPdhYBuz5p5rg==";
		String content = "{\"retcode\":\"200\"}";
		System.out.println(HttpEncryptUtil.serverEncrypt(appPublicKeyStr, aesKeyStr, content));
	}
	
	//测试 	APP解密服务器的响应内容
	@Test
	public void testAppDecrypt() throws Exception{
		//APP端公钥和私钥从配置文件读取，不能写死在代码里
		Properties prop = new Properties();
		InputStream in = TestHttpEncrypt.class.getClassLoader().getResourceAsStream("client.properties");
		prop.load(in);
		String appPrivateKey = prop.getProperty("app.private.key");
		String content = "{\"ak\":\"BPOujAK4Wzs0lKrygUHggarzmmaSiZejB7OkMZ1emPGTKZjUsb3YgSWRGClg0Z0uBQt5Zby8DKkZgGdDnEeMyjc4JJ1Y1q831/tcP7VkebLGNEHfEpGm15qE2GekJ5b/R6pVjIlUZNKtuaTpIQ==\",\"ct\":\"WcVmcfIr6lUISjx6MmxicI6ODyCs5QcVX6dQgXMkP90=\"}";
		System.out.println(HttpEncryptUtil.appDecrypt(appPrivateKey, content));
	}
}
