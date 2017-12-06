package com.ai.ech.mall.common.util;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
 



import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;


public class QEncodeUtil {
    private final static String encoding = "UTF-8"; 
    
    /**
     * AES加密
     * 
     * @param content
     * @param appScerct  密钥
     * @return
     */
    public static String aesEncrypt(String content,String appScerct) {
        byte[] encryptResult = encrypt(content,appScerct);
        String encryptResultStr = parseByte2HexStr(encryptResult);
        // BASE64位加密
        encryptResultStr = ebotongEncrypto(encryptResultStr);
        return encryptResultStr;
    }
    
    /**
     * AES解密
     * 
     * @param encryptResultStr
     * @param appScerct  密钥
     * @return
     */
    public static String aesDecrypt(String encryptResultStr,String appScerct) {
        // BASE64位解密
        String decrpt = ebotongDecrypto(encryptResultStr);
        byte[] decryptFrom = parseHexStr2Byte(decrpt);
        byte[] decryptResult = decrypt(decryptFrom,appScerct);
        return new String(decryptResult);
    }

    /**
     * md5加密
     * 
     * @param originStr
     * @return
     */
    public static String md5Encode(String originStr) {
        String md5String = "";
        StringBuffer buffer = new StringBuffer();
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] bytes = md.digest(originStr.getBytes("UTF-8"));
            for (byte b : bytes) {
                buffer.append(Integer.toHexString((b & 0xf0) >>> 4));
                buffer.append(Integer.toHexString(b & 0x0f));
            }
            md5String = buffer.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return md5String;
    }

    
    public static String ebotongEncrypto(String str) {
        BASE64Encoder base64encoder = new BASE64Encoder();
        String result = str;
        if (str != null && str.length() > 0) {
            try {
                byte[] encodeByte = str.getBytes(encoding);
                result = base64encoder.encode(encodeByte);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        //base64加密超过一定长度会自动换行 需要去除换行符
        return result.replaceAll("\r\n", "").replaceAll("\r", "").replaceAll("\n", "");
    }
    

    public static String ebotongDecrypto(String str) {
        BASE64Decoder base64decoder = new BASE64Decoder();
        try {
            byte[] encodeByte = base64decoder.decodeBuffer(str);
            return new String(encodeByte);
        } catch (IOException e) {
            e.printStackTrace();
            return str;
        }
    }

    
    private static byte[] encrypt(String content,String appScerct) {   
        try {              
            KeyGenerator kgen = KeyGenerator.getInstance("AES"); 
            //防止linux下 随机生成key
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG" );   
            secureRandom.setSeed(appScerct.getBytes());   
            kgen.init(128, secureRandom);
            SecretKey secretKey = kgen.generateKey();   
            byte[] enCodeFormat = secretKey.getEncoded();   
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");   
            Cipher cipher = Cipher.getInstance("AES");// 创建密码器   
            byte[] byteContent = content.getBytes("utf-8");   
            cipher.init(Cipher.ENCRYPT_MODE, key);// 初始化   
            byte[] result = cipher.doFinal(byteContent);   
            return result; // 加密   
        } catch (NoSuchAlgorithmException e) {   
            e.printStackTrace();   
        } catch (NoSuchPaddingException e) {   
            e.printStackTrace();   
        } catch (InvalidKeyException e) {   
            e.printStackTrace();   
        } catch (UnsupportedEncodingException e) {   
            e.printStackTrace();   
        } catch (IllegalBlockSizeException e) {   
            e.printStackTrace();   
        } catch (BadPaddingException e) {   
            e.printStackTrace();   
        }   
        return null;   
    }  

    
    private static byte[] decrypt(byte[] content,String appScerct) {   
        try {   
            KeyGenerator kgen = KeyGenerator.getInstance("AES"); 
            //防止linux下 随机生成key
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG" );   
            secureRandom.setSeed(appScerct.getBytes());   
            kgen.init(128, secureRandom);
            SecretKey secretKey = kgen.generateKey();   
            byte[] enCodeFormat = secretKey.getEncoded();   
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");               
            Cipher cipher = Cipher.getInstance("AES");// 创建密码器   
            cipher.init(Cipher.DECRYPT_MODE, key);// 初始化   
            byte[] result = cipher.doFinal(content);   
            return result; // 加密   
        } catch (NoSuchAlgorithmException e) {   
            e.printStackTrace();   
        } catch (NoSuchPaddingException e) {   
            e.printStackTrace();   
        } catch (InvalidKeyException e) {   
            e.printStackTrace();   
        } catch (IllegalBlockSizeException e) {   
            e.printStackTrace();   
        } catch (BadPaddingException e) {   
            e.printStackTrace();   
        }   
        return null;   
    }  

    
    public static String parseByte2HexStr(byte buf[]) {   
        StringBuffer sb = new StringBuffer();   
        for (int i = 0; i < buf.length; i++) {   
            String hex = Integer.toHexString(buf[i] & 0xFF);   
            if (hex.length() == 1) {   
                hex = '0' + hex;   
            }   
            sb.append(hex.toUpperCase());   
        }   
        return sb.toString();   
    }  

    
    public static byte[] parseHexStr2Byte(String hexStr) {   
        if (hexStr.length() < 1)   
            return null;   
        byte[] result = new byte[hexStr.length()/2];   
        for (int i = 0;i< hexStr.length()/2; i++) {   
            int high = Integer.parseInt(hexStr.substring(i*2, i*2+1), 16);   
            int low = Integer.parseInt(hexStr.substring(i*2+1, i*2+2), 16);   
            result[i] = (byte) (high * 16 + low);   
        }   
        return result;   
    }
    
	/**
	 * des 加密
	 * @param data 
	 * @param key  加密键
	 * @return
	 * @throws Exception
	 */
	public static String desEncrypt(String data, String key) throws Exception {
		byte[] bt = desEncrypt(data.getBytes(), key.getBytes());
		String strs = Base64.encode(bt);
		return strs;
	}

	/**
	 * des 解密
	 * @param data
	 * @param key  加密键
	 * @return
	 * @throws IOException
	 * @throws Exception
	 */
	public static String desDecrypt(String data, String key) throws IOException,
			Exception {
		if (data == null)
			return null;
		byte[] buf = Base64.decode(data);
		byte[] bt = desDecrypt(buf,key.getBytes());
		return new String(bt);
	}

	/**
	 * Description 根据键值进行加密
	 * @param data
	 * @param key  加密键byte数组
	 * @return
	 * @throws Exception
	 */
	private static byte[] desEncrypt(byte[] data, byte[] key) throws Exception {
		// 生成一个可信任的随机数源
		SecureRandom sr = new SecureRandom();

		// 从原始密钥数据创建DESKeySpec对象
		DESKeySpec dks = new DESKeySpec(key);

		// 创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
		SecretKey securekey = keyFactory.generateSecret(dks);
		Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

		// 用密钥初始化Cipher对象
		cipher.init(Cipher.ENCRYPT_MODE, securekey, sr);

		return cipher.doFinal(data);
	}
	
	/**
	 * Description 根据键值进行解密
	 * @param data
	 * @param key  加密键byte数组
	 * @return
	 * @throws Exception
	 */
	private static byte[] desDecrypt(byte[] data, byte[] key) throws Exception {
		// 生成一个可信任的随机数源
		SecureRandom sr = new SecureRandom();

		// 从原始密钥数据创建DESKeySpec对象
		DESKeySpec dks = new DESKeySpec(key);

		// 创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
		SecretKey securekey = keyFactory.generateSecret(dks);

		// Cipher对象实际完成解密操作
		Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

		// 用密钥初始化Cipher对象
		cipher.init(Cipher.DECRYPT_MODE, securekey, sr);

		return cipher.doFinal(data);
	}
}

