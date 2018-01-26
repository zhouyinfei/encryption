package com.zhuyun.http.encrypt;

import java.io.InputStream;
import java.security.KeyPair;
import java.util.Properties;

import org.junit.Test;

import com.zhuyun.aes.AESUtil;
import com.zhuyun.rsa.RSAUtil;


public class TestHttpEncrypt {

	@Test
	public void testGenerateKeyPair() throws Exception{
		//生成RSA公钥和私钥，并Base64编码
		KeyPair keyPair = RSAUtil.getKeyPair();
		String publicKeyStr = RSAUtil.getPublicKey(keyPair);
		String privateKeyStr = RSAUtil.getPrivateKey(keyPair);
		System.out.println("RSA公钥Base64编码:" + publicKeyStr);
		System.out.println("RSA私钥Base64编码:" + privateKeyStr);
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
		String result = "{\"ak\":\"iLHfi1XRz4gnirU2OKggNCkz5x0i6aSonm1u3bE+ncI4AuiUG9LX2nbrQV/lWUIqwRp/q/P+SrIPnh5JbgEzSi+K46N4enyDFYbWpC6gONqQpF3tNt6Q1Y+UdX3L5l9hFPAS9tIhI2kT10AbhMox2kKOhr6ZQmmC/A3qeFEbTuUUf8bOCr4nqz4qSNyCZgcJdoAQonJeN8IilWuTD+LpbllNimFNR/sGY5jlyjvVydrdpNs15oFaXtfTLUjSXe2e5Ha1r3K7lP93C2E+KL55001xFJhQZcZXa9ZlYCMQgI+2cJlED4uA3bl2ul1dtnvXK+41Yky9e9QrRDc5luqB6w==\",\"apk\":\"P0SJaTzKWuBMi/fj2G8wwZ9+FWFIrE3BAwdoXwIfiTxptYXumLxnMpZZkCBNqQBvhvSzAEPyA3c9kCjhYCxdTnV61N+T/DZM+B62u4vqCy1MsFZT06BJjrNFW29AfSRNmQdKhJEyDPARcf5FerULbIDWGvrHzHys7jVbicjlYWtQpnyQf5Wl0Bd7taEqSwUSKejoEsN74frwlk8Hu4KP4bLvVy9S7DjOP2juXbVkHYaKgVmhM2V3yElVOEb1TDCLSFMNtug74+7itlzlChDR8wEWdh11vQcp69iGmDXMo2vcJ9tO1YZP+hCYZvujHMRwAzHtkqafEoSJsvSN8PWS+qmQdUX2frf6A0cl6SGnTbGUUEV/w0rBIU/oGhP8cl8+ghqPbp7HzvwXFOJsUciy+7tsLRrdDpLeOcz+fh/c0RSpCKNEZtRmcuUqBQ+3tZKYGPhl+StsFh3s1RCkhI4EsSD95bCbES4r1r1E4dytdELi0ebJug7Quk3rwFVXGX9o4wrnnvcbTaSyyAAg2YTNfA==\",\"ct\":\"mkC7hE/crHbmW+h2OCMBANCA64xtMFLTRmLahOU+UysZrXzK30qRj6RUcvpQz4mJ6EOYYAK34+BQBkN9gapdIw==\"}";
		System.out.println(HttpEncryptUtil.serverDecrypt(result));
	}
	
	//测试 服务器加密响应给APP的内容
	@Test
	public void testserverEncrypt() throws Exception{
		String aesKeyStr = "dSRWXM6IkWkKk7I/ZGouqA==";
		String appPublicKeyStr = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqqKPH/L0AZyn1fJ9xK2ol2nHY5jPu8qw7COwFukkRdr2j0oNJmD8vCTmxgzKWV0CkihiJ7Y0OekrGc78JL5tpL2SqeZTLa2bCJZJaTM3KFOXYb82nc8Xbr2caDnf7mgjyt0AALHG/YfYwd7hifZRB6Ct89uBTn6W5x/7oxGT6D1C8siXKV+99AZPMv2HobglWyquyjIL5TZOhYmCMzFUPMOiXzzGYXMZj2gmfUFXMf/2jitMPGg3zQPJxPSYunjoE1fMInk1obEhEfU8n2YxT5ZbGMWZGjt4hZwF+FJJLV+WOantfUJ4rMBB8qxgQtkT+VzddfLCEoyy4Rl50fvjzwIDAQAB";
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
		String content = "{\"ak\":\"kFUEiOKVNUUEDBS2hFTF1DDiPMFjbjgEzoLPABGntjgRvK/KnF1qi8gimDkmlQRxcvNLvHwk60AUX69lIhiTZp+qIjPnAEmTEY+BI7tgj6dVltrhR7bXHOP2LS0jIdHP/YmAWqf+/C1fTHAuCWv0ifNSYEiKPSCCLDHal1nPSTkWXUgkC+J02dE99o3zeiGwSwbeFsGCcZnzZuKMXJm3yKBsLEqq8kUsn9yElHbQ6Ax52VFz4fq9sNqucEREgT8EJ79IZFhbYjBxBU+oTqlxK6H3PNCu6EZLJANpWuXwSqdrSUefYi4A5RlqJN1OzMVtcanzMSifH243Bw95eHiclA==\",\"ct\":\"4lzwwJfKxVRfNvqLXTwmSB2KSMUZtbeky6fvojbJIV0=\"}";
		System.out.println(HttpEncryptUtil.appDecrypt(appPrivateKey, content));
	}
}
