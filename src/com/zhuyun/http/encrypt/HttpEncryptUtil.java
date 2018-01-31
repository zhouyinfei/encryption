package com.zhuyun.http.encrypt;

import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import com.zhuyun.aes.AESUtil;
import com.zhuyun.ecc.ECCUtil;
import com.zhuyun.rsa.RSAUtil;

import net.sf.json.JSONObject;


public class HttpEncryptUtil {

//	//################################˫��RSA + AES ##########################
//	//APP������������
//	public static String appEncrypt(String appPublicKeyStr, String content) throws Exception{
//		//��Base64������Server��Կת����PublicKey����
//		PublicKey serverPublicKey = RSAUtil.string2PublicKey(KeyUtil.SERVER_PUBLIC_KEY);
//		//ÿ�ζ��������AES��Կ
//		String aesKeyStr = AESUtil.genKeyAES();
//		SecretKey aesKey = AESUtil.loadKeyAES(aesKeyStr);
//		//��Server��Կ����AES��Կ
//		byte[] encryptAesKey = RSAUtil.publicEncrypt(aesKeyStr.getBytes(), serverPublicKey);
//		//��AES��Կ����APP��Կ
//		byte[] encryptAppPublicKey = AESUtil.encryptAES(appPublicKeyStr.getBytes(), aesKey);
//		//��AES��Կ������������
//		byte[] encryptRequest = AESUtil.encryptAES(content.getBytes(), aesKey);
//		
//		JSONObject result = new JSONObject();
//		result.put("ak", RSAUtil.byte2Base64(encryptAesKey).replaceAll("\r\n", ""));
//		result.put("apk", RSAUtil.byte2Base64(encryptAppPublicKey).replaceAll("\r\n", ""));
//		result.put("ct", RSAUtil.byte2Base64(encryptRequest).replaceAll("\r\n", ""));
//		return result.toString();
//	}
//	
//	//APP���ܷ���������Ӧ����
//	public static String appDecrypt(String appPrivateKeyStr, String content) throws Exception{
//		JSONObject result = JSONObject.fromObject(content);
//		String encryptAesKeyStr = (String) result.get("ak");
//		String encryptContent = (String) result.get("ct");
//		
//		//��Base64������APP˽Կת����PrivateKey����
//		PrivateKey appPrivateKey = RSAUtil.string2PrivateKey(appPrivateKeyStr);
//		//��APP˽Կ����AES��Կ
//		byte[] aesKeyBytes = RSAUtil.privateDecrypt(RSAUtil.base642Byte(encryptAesKeyStr), appPrivateKey);
//		//��AES��Կ������������
//		SecretKey aesKey = AESUtil.loadKeyAES(new String(aesKeyBytes));
//		byte[] response = AESUtil.decryptAES(RSAUtil.base642Byte(encryptContent), aesKey);
//		
//		return new String(response);
//	}
//	
//	//������������Ӧ��APP������
//	public static String serverEncrypt(String appPublicKeyStr, String aesKeyStr, String content) throws Exception{
//		//��Base64������APP��Կת����PublicKey����
//		PublicKey appPublicKey = RSAUtil.string2PublicKey(appPublicKeyStr);
//		//��Base64������AES��Կת����SecretKey����
//		SecretKey aesKey = AESUtil.loadKeyAES(aesKeyStr);
//		//��APP��Կ����AES��Կ
//		byte[] encryptAesKey = RSAUtil.publicEncrypt(aesKeyStr.getBytes(), appPublicKey);
//		//��AES��Կ������Ӧ����
//		byte[] encryptContent = AESUtil.encryptAES(content.getBytes(), aesKey);
//		
//		JSONObject result = new JSONObject();
//		result.put("ak", RSAUtil.byte2Base64(encryptAesKey).replaceAll("\r\n", ""));
//		result.put("ct", RSAUtil.byte2Base64(encryptContent).replaceAll("\r\n", ""));
//		return result.toString();
//	}
//	
//	//����������APP����������
//	public static String serverDecrypt(String content) throws Exception{
//		JSONObject result = JSONObject.fromObject(content);
//		String encryptAesKeyStr = (String) result.get("ak");
//		String encryptAppPublicKeyStr = (String) result.get("apk");
//		String encryptContent = (String) result.get("ct");
//		
//		//��Base64������Server˽Կת����PrivateKey����
//		PrivateKey serverPrivateKey = RSAUtil.string2PrivateKey(KeyUtil.SERVER_PRIVATE_KEY);
//		//��Server˽Կ����AES��Կ
//		byte[] aesKeyBytes = RSAUtil.privateDecrypt(RSAUtil.base642Byte(encryptAesKeyStr), serverPrivateKey);
//		//��Server˽Կ����APP��Կ
//		SecretKey aesKey = AESUtil.loadKeyAES(new String(aesKeyBytes));
//		byte[] appPublicKeyBytes = AESUtil.decryptAES(RSAUtil.base642Byte(encryptAppPublicKeyStr), aesKey);
//		//��AES��Կ������������
//		byte[] request = AESUtil.decryptAES(RSAUtil.base642Byte(encryptContent), aesKey);
//		
//		JSONObject result2 = new JSONObject();
//		result2.put("ak", new String(aesKeyBytes));
//		result2.put("apk", new String(appPublicKeyBytes));
//		result2.put("ct", new String(request));
//		return result2.toString();
//	}
	
	
	//################################˫��ECC + AES ##########################
	//APP������������
	public static String appEncrypt(String appPublicKeyStr, String content) throws Exception{
		//��Base64������Server��Կת����PublicKey����
		ECPublicKey serverPublicKey = ECCUtil.string2PublicKey(KeyUtil.SERVER_PUBLIC_KEY);
		//ÿ�ζ��������AES��Կ
		String aesKeyStr = AESUtil.genKeyAES();
		SecretKey aesKey = AESUtil.loadKeyAES(aesKeyStr);
		//��Server��Կ����AES��Կ
		byte[] encryptAesKey = ECCUtil.publicEncrypt(aesKeyStr.getBytes(), serverPublicKey);
		//��AES��Կ����APP��Կ
		byte[] encryptAppPublicKey = AESUtil.encryptAES(appPublicKeyStr.getBytes(), aesKey);
		//��AES��Կ������������
		byte[] encryptRequest = AESUtil.encryptAES(content.getBytes(), aesKey);
		
		JSONObject result = new JSONObject();
		result.put("ak", AESUtil.byte2Base64(encryptAesKey).replaceAll("\r\n", ""));
		result.put("apk", AESUtil.byte2Base64(encryptAppPublicKey).replaceAll("\r\n", ""));
		result.put("ct", AESUtil.byte2Base64(encryptRequest).replaceAll("\r\n", ""));
		return result.toString();
	}
	
	//APP���ܷ���������Ӧ����
	public static String appDecrypt(String appPrivateKeyStr, String content) throws Exception{
		JSONObject result = JSONObject.fromObject(content);
		String encryptAesKeyStr = (String) result.get("ak");
		String encryptContent = (String) result.get("ct");
		
		//��Base64������APP˽Կת����PrivateKey����
		ECPrivateKey appPrivateKey = ECCUtil.string2PrivateKey(appPrivateKeyStr);
		//��APP˽Կ����AES��Կ
		byte[] aesKeyBytes = ECCUtil.privateDecrypt(AESUtil.base642Byte(encryptAesKeyStr), appPrivateKey);
		//��AES��Կ������������
		SecretKey aesKey = AESUtil.loadKeyAES(new String(aesKeyBytes));
		byte[] response = AESUtil.decryptAES(AESUtil.base642Byte(encryptContent), aesKey);
		
		return new String(response);
	}
	
	//������������Ӧ��APP������
	public static String serverEncrypt(String appPublicKeyStr, String aesKeyStr, String content) throws Exception{
		//��Base64������APP��Կת����PublicKey����
		ECPublicKey appPublicKey = ECCUtil.string2PublicKey(appPublicKeyStr);
		//��Base64������AES��Կת����SecretKey����
		SecretKey aesKey = AESUtil.loadKeyAES(aesKeyStr);
		//��APP��Կ����AES��Կ
		byte[] encryptAesKey = ECCUtil.publicEncrypt(aesKeyStr.getBytes(), appPublicKey);
		//��AES��Կ������Ӧ����
		byte[] encryptContent = AESUtil.encryptAES(content.getBytes(), aesKey);
		
		JSONObject result = new JSONObject();
		result.put("ak", AESUtil.byte2Base64(encryptAesKey).replaceAll("\r\n", ""));
		result.put("ct", AESUtil.byte2Base64(encryptContent).replaceAll("\r\n", ""));
		return result.toString();
	}
	
	//����������APP����������
	public static String serverDecrypt(String content) throws Exception{
		JSONObject result = JSONObject.fromObject(content);
		String encryptAesKeyStr = (String) result.get("ak");
		String encryptAppPublicKeyStr = (String) result.get("apk");
		String encryptContent = (String) result.get("ct");
		
		//��Base64������Server˽Կת����PrivateKey����
		ECPrivateKey serverPrivateKey = ECCUtil.string2PrivateKey(KeyUtil.SERVER_PRIVATE_KEY);
		//��Server˽Կ����AES��Կ
		byte[] aesKeyBytes = ECCUtil.privateDecrypt(AESUtil.base642Byte(encryptAesKeyStr), serverPrivateKey);
		//��AES��Կ����APP��Կ
		SecretKey aesKey = AESUtil.loadKeyAES(new String(aesKeyBytes));
		byte[] appPublicKeyBytes = AESUtil.decryptAES(AESUtil.base642Byte(encryptAppPublicKeyStr), aesKey);
		//��AES��Կ������������
		byte[] request = AESUtil.decryptAES(AESUtil.base642Byte(encryptContent), aesKey);
		
		JSONObject result2 = new JSONObject();
		result2.put("ak", new String(aesKeyBytes));
		result2.put("apk", new String(appPublicKeyBytes));
		result2.put("ct", new String(request));
		return result2.toString();
	}
}
