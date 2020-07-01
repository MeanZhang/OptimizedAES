import java.io.File;

/**
 * 用于测试AES128优化前后的速度
 */
public class Test {
    public static void main(String[] args) {
        byte[] key = {0x0f, 0x15, 0x71, (byte) 0xc9, 0x47, (byte) 0xd9, (byte) 0xe8, 0x59, 0x0c, (byte) 0xb7, (byte) 0xad, (byte) 0xd6, (byte) 0xaf, 0x7f, 0x67, (byte) 0x98};
        File p = new File("plain.txt");
        File c = new File("cipher.txt");
        AES128 aes1 = new AES128();
        //开始时间
        long start = System.currentTimeMillis();
        aes1.init(key, "encrypt");
        long init1 = System.currentTimeMillis();
        aes1.encrypt(p, c);
        long encrypt1 = System.currentTimeMillis();
        aes1.init(key, "decrypt");
        long init2 = System.currentTimeMillis();
        aes1.decrypt(c,p);
        long decrypt1=System.currentTimeMillis();
        AES aes2=new AES(key);
        long build=System.currentTimeMillis();
        aes2.encrypt(p,c);
        long encrypt2=System.currentTimeMillis();
        aes2.decrypt(c,p);
        long decrypt2= System.currentTimeMillis();
        long pLength = p.length();
        System.out.println("明文大小：" + pLength + "字节");
        long cLength = c.length();
        System.out.println("密文大小：" + cLength + "字节");
        System.out.println("**********优化后*********");
        System.out.println("加密密钥扩展及构造T盒时间：" + (init1 - start) + " ms");
        System.out.println("加密时间：" + (encrypt1 - init1) + " ms");
        System.out.println("加密速度：" + p.length() * 8000 / (encrypt1 - init1) + " bit/s");
        System.out.println("解密密钥扩展及构造T盒时间：" + (init2 - encrypt1) + " ms");
        System.out.println("解密时间：" + (decrypt1 - init2) + " ms");
        System.out.println("解密速度：" + c.length() * 8000 / (decrypt1 - init2) + " bit/s");
        System.out.println("**********优化前*********");
        System.out.println("密钥扩展时间：" + (build-decrypt1) + " ms");
        System.out.println("加密时间：" + (encrypt2 - build) + " ms");
        System.out.println("加密速度：" + p.length() * 8000 / (encrypt2 - build) + " bit/s");
        System.out.println("解密时间：" + (decrypt2 - encrypt2) + " ms");
        System.out.println("解密速度：" + c.length() * 8000 / (decrypt2 - encrypt2) + " bit/s");
    }
}
