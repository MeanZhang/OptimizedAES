import java.io.*;

/**
 * AES-128加解密(未优化)
 *
 * @author Mean
 * @version 2.0
 */
public class AES {
    /**
     * S盒
     * <p>
     * 256字节
     */
    private static final byte[] S = {(byte) 0x63, (byte) 0x7C, (byte) 0x77, (byte) 0x7B, (byte) 0xF2, (byte) 0x6B,
            (byte) 0x6F, (byte) 0xC5, (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2B, (byte) 0xFE, (byte) 0xD7,
            (byte) 0xAB, (byte) 0x76, (byte) 0xCA, (byte) 0x82, (byte) 0xC9, (byte) 0x7D, (byte) 0xFA, (byte) 0x59,
            (byte) 0x47, (byte) 0xF0, (byte) 0xAD, (byte) 0xD4, (byte) 0xA2, (byte) 0xAF, (byte) 0x9C, (byte) 0xA4,
            (byte) 0x72, (byte) 0xC0, (byte) 0xB7, (byte) 0xFD, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3F,
            (byte) 0xF7, (byte) 0xCC, (byte) 0x34, (byte) 0xA5, (byte) 0xE5, (byte) 0xF1, (byte) 0x71, (byte) 0xD8,
            (byte) 0x31, (byte) 0x15, (byte) 0x04, (byte) 0xC7, (byte) 0x23, (byte) 0xC3, (byte) 0x18, (byte) 0x96,
            (byte) 0x05, (byte) 0x9A, (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xE2, (byte) 0xEB, (byte) 0x27,
            (byte) 0xB2, (byte) 0x75, (byte) 0x09, (byte) 0x83, (byte) 0x2C, (byte) 0x1A, (byte) 0x1B, (byte) 0x6E,
            (byte) 0x5A, (byte) 0xA0, (byte) 0x52, (byte) 0x3B, (byte) 0xD6, (byte) 0xB3, (byte) 0x29, (byte) 0xE3,
            (byte) 0x2F, (byte) 0x84, (byte) 0x53, (byte) 0xD1, (byte) 0x00, (byte) 0xED, (byte) 0x20, (byte) 0xFC,
            (byte) 0xB1, (byte) 0x5B, (byte) 0x6A, (byte) 0xCB, (byte) 0xBE, (byte) 0x39, (byte) 0x4A, (byte) 0x4C,
            (byte) 0x58, (byte) 0xCF, (byte) 0xD0, (byte) 0xEF, (byte) 0xAA, (byte) 0xFB, (byte) 0x43, (byte) 0x4D,
            (byte) 0x33, (byte) 0x85, (byte) 0x45, (byte) 0xF9, (byte) 0x02, (byte) 0x7F, (byte) 0x50, (byte) 0x3C,
            (byte) 0x9F, (byte) 0xA8, (byte) 0x51, (byte) 0xA3, (byte) 0x40, (byte) 0x8F, (byte) 0x92, (byte) 0x9D,
            (byte) 0x38, (byte) 0xF5, (byte) 0xBC, (byte) 0xB6, (byte) 0xDA, (byte) 0x21, (byte) 0x10, (byte) 0xFF,
            (byte) 0xF3, (byte) 0xD2, (byte) 0xCD, (byte) 0x0C, (byte) 0x13, (byte) 0xEC, (byte) 0x5F, (byte) 0x97,
            (byte) 0x44, (byte) 0x17, (byte) 0xC4, (byte) 0xA7, (byte) 0x7E, (byte) 0x3D, (byte) 0x64, (byte) 0x5D,
            (byte) 0x19, (byte) 0x73, (byte) 0x60, (byte) 0x81, (byte) 0x4F, (byte) 0xDC, (byte) 0x22, (byte) 0x2A,
            (byte) 0x90, (byte) 0x88, (byte) 0x46, (byte) 0xEE, (byte) 0xB8, (byte) 0x14, (byte) 0xDE, (byte) 0x5E,
            (byte) 0x0B, (byte) 0xDB, (byte) 0xE0, (byte) 0x32, (byte) 0x3A, (byte) 0x0A, (byte) 0x49, (byte) 0x06,
            (byte) 0x24, (byte) 0x5C, (byte) 0xC2, (byte) 0xD3, (byte) 0xAC, (byte) 0x62, (byte) 0x91, (byte) 0x95,
            (byte) 0xE4, (byte) 0x79, (byte) 0xE7, (byte) 0xC8, (byte) 0x37, (byte) 0x6D, (byte) 0x8D, (byte) 0xD5,
            (byte) 0x4E, (byte) 0xA9, (byte) 0x6C, (byte) 0x56, (byte) 0xF4, (byte) 0xEA, (byte) 0x65, (byte) 0x7A,
            (byte) 0xAE, (byte) 0x08, (byte) 0xBA, (byte) 0x78, (byte) 0x25, (byte) 0x2E, (byte) 0x1C, (byte) 0xA6,
            (byte) 0xB4, (byte) 0xC6, (byte) 0xE8, (byte) 0xDD, (byte) 0x74, (byte) 0x1F, (byte) 0x4B, (byte) 0xBD,
            (byte) 0x8B, (byte) 0x8A, (byte) 0x70, (byte) 0x3E, (byte) 0xB5, (byte) 0x66, (byte) 0x48, (byte) 0x03,
            (byte) 0xF6, (byte) 0x0E, (byte) 0x61, (byte) 0x35, (byte) 0x57, (byte) 0xB9, (byte) 0x86, (byte) 0xC1,
            (byte) 0x1D, (byte) 0x9E, (byte) 0xE1, (byte) 0xF8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xD9,
            (byte) 0x8E, (byte) 0x94, (byte) 0x9B, (byte) 0x1E, (byte) 0x87, (byte) 0xE9, (byte) 0xCE, (byte) 0x55,
            (byte) 0x28, (byte) 0xDF, (byte) 0x8C, (byte) 0xA1, (byte) 0x89, (byte) 0x0D, (byte) 0xBF, (byte) 0xE6,
            (byte) 0x42, (byte) 0x68, (byte) 0x41, (byte) 0x99, (byte) 0x2D, (byte) 0x0F, (byte) 0xB0, (byte) 0x54,
            (byte) 0xBB, (byte) 0x16};
    /**
     * 逆S盒
     * <p>
     * 256字节
     */
    private static final byte[] INV_S = {(byte) 0x52, (byte) 0x09, (byte) 0x6A, (byte) 0xD5, (byte) 0x30, (byte) 0x36,
            (byte) 0xA5, (byte) 0x38, (byte) 0xBF, (byte) 0x40, (byte) 0xA3, (byte) 0x9E, (byte) 0x81, (byte) 0xF3,
            (byte) 0xD7, (byte) 0xFB, (byte) 0x7C, (byte) 0xE3, (byte) 0x39, (byte) 0x82, (byte) 0x9B, (byte) 0x2F,
            (byte) 0xFF, (byte) 0x87, (byte) 0x34, (byte) 0x8E, (byte) 0x43, (byte) 0x44, (byte) 0xC4, (byte) 0xDE,
            (byte) 0xE9, (byte) 0xCB, (byte) 0x54, (byte) 0x7B, (byte) 0x94, (byte) 0x32, (byte) 0xA6, (byte) 0xC2,
            (byte) 0x23, (byte) 0x3D, (byte) 0xEE, (byte) 0x4C, (byte) 0x95, (byte) 0x0B, (byte) 0x42, (byte) 0xFA,
            (byte) 0xC3, (byte) 0x4E, (byte) 0x08, (byte) 0x2E, (byte) 0xA1, (byte) 0x66, (byte) 0x28, (byte) 0xD9,
            (byte) 0x24, (byte) 0xB2, (byte) 0x76, (byte) 0x5B, (byte) 0xA2, (byte) 0x49, (byte) 0x6D, (byte) 0x8B,
            (byte) 0xD1, (byte) 0x25, (byte) 0x72, (byte) 0xF8, (byte) 0xF6, (byte) 0x64, (byte) 0x86, (byte) 0x68,
            (byte) 0x98, (byte) 0x16, (byte) 0xD4, (byte) 0xA4, (byte) 0x5C, (byte) 0xCC, (byte) 0x5D, (byte) 0x65,
            (byte) 0xB6, (byte) 0x92, (byte) 0x6C, (byte) 0x70, (byte) 0x48, (byte) 0x50, (byte) 0xFD, (byte) 0xED,
            (byte) 0xB9, (byte) 0xDA, (byte) 0x5E, (byte) 0x15, (byte) 0x46, (byte) 0x57, (byte) 0xA7, (byte) 0x8D,
            (byte) 0x9D, (byte) 0x84, (byte) 0x90, (byte) 0xD8, (byte) 0xAB, (byte) 0x00, (byte) 0x8C, (byte) 0xBC,
            (byte) 0xD3, (byte) 0x0A, (byte) 0xF7, (byte) 0xE4, (byte) 0x58, (byte) 0x05, (byte) 0xB8, (byte) 0xB3,
            (byte) 0x45, (byte) 0x06, (byte) 0xD0, (byte) 0x2C, (byte) 0x1E, (byte) 0x8F, (byte) 0xCA, (byte) 0x3F,
            (byte) 0x0F, (byte) 0x02, (byte) 0xC1, (byte) 0xAF, (byte) 0xBD, (byte) 0x03, (byte) 0x01, (byte) 0x13,
            (byte) 0x8A, (byte) 0x6B, (byte) 0x3A, (byte) 0x91, (byte) 0x11, (byte) 0x41, (byte) 0x4F, (byte) 0x67,
            (byte) 0xDC, (byte) 0xEA, (byte) 0x97, (byte) 0xF2, (byte) 0xCF, (byte) 0xCE, (byte) 0xF0, (byte) 0xB4,
            (byte) 0xE6, (byte) 0x73, (byte) 0x96, (byte) 0xAC, (byte) 0x74, (byte) 0x22, (byte) 0xE7, (byte) 0xAD,
            (byte) 0x35, (byte) 0x85, (byte) 0xE2, (byte) 0xF9, (byte) 0x37, (byte) 0xE8, (byte) 0x1C, (byte) 0x75,
            (byte) 0xDF, (byte) 0x6E, (byte) 0x47, (byte) 0xF1, (byte) 0x1A, (byte) 0x71, (byte) 0x1D, (byte) 0x29,
            (byte) 0xC5, (byte) 0x89, (byte) 0x6F, (byte) 0xB7, (byte) 0x62, (byte) 0x0E, (byte) 0xAA, (byte) 0x18,
            (byte) 0xBE, (byte) 0x1B, (byte) 0xFC, (byte) 0x56, (byte) 0x3E, (byte) 0x4B, (byte) 0xC6, (byte) 0xD2,
            (byte) 0x79, (byte) 0x20, (byte) 0x9A, (byte) 0xDB, (byte) 0xC0, (byte) 0xFE, (byte) 0x78, (byte) 0xCD,
            (byte) 0x5A, (byte) 0xF4, (byte) 0x1F, (byte) 0xDD, (byte) 0xA8, (byte) 0x33, (byte) 0x88, (byte) 0x07,
            (byte) 0xC7, (byte) 0x31, (byte) 0xB1, (byte) 0x12, (byte) 0x10, (byte) 0x59, (byte) 0x27, (byte) 0x80,
            (byte) 0xEC, (byte) 0x5F, (byte) 0x60, (byte) 0x51, (byte) 0x7F, (byte) 0xA9, (byte) 0x19, (byte) 0xB5,
            (byte) 0x4A, (byte) 0x0D, (byte) 0x2D, (byte) 0xE5, (byte) 0x7A, (byte) 0x9F, (byte) 0x93, (byte) 0xC9,
            (byte) 0x9C, (byte) 0xEF, (byte) 0xA0, (byte) 0xE0, (byte) 0x3B, (byte) 0x4D, (byte) 0xAE, (byte) 0x2A,
            (byte) 0xF5, (byte) 0xB0, (byte) 0xC8, (byte) 0xEB, (byte) 0xBB, (byte) 0x3C, (byte) 0x83, (byte) 0x53,
            (byte) 0x99, (byte) 0x61, (byte) 0x17, (byte) 0x2B, (byte) 0x04, (byte) 0x7E, (byte) 0xBA, (byte) 0x77,
            (byte) 0xD6, (byte) 0x26, (byte) 0xE1, (byte) 0x69, (byte) 0x14, (byte) 0x63, (byte) 0x55, (byte) 0x21,
            (byte) 0x0C, (byte) 0x7D};
    /**
     * 11个子密钥
     * <p>
     * 形式为byte[11][4][4]，每一个子密钥由4个字(4字节)组成，一行为一个字
     */
    private byte[][][] k = new byte[11][4][4];
public AES(byte[] key){
    keyExpansion(key);
}
    /**
     * AES加密
     *
     * @param plain 16字节明文
     * @return 16字节密文
     */
    public byte[] encrypt(byte[] plain) {
        // 16字节密文
        byte[] cipher = new byte[16];
        // 状态矩阵
        byte[][] state = new byte[4][4];
        for (int i = 0; i < 4; i++)
            System.arraycopy(plain, 4 * i, state[i], 0, 4);
        // 轮密钥加
        addRoundKey(state, k[0]);
        for (int i = 1; i <= 9; i++) {
            // 字节代替
            subBytes(state);
            // 行移位
            state = shiftRows(state);
            // 列混淆
            state = mixColumns(state);
            // 轮密钥加
            addRoundKey(state, k[i]);
        }
        // 字节代替
        subBytes(state);
        // 行移位
        state = shiftRows(state);
        // 轮密钥加
        addRoundKey(state, k[10]);
        for (int i = 0; i < 4; i++)
            System.arraycopy(state[i], 0, cipher, 4 * i, 4);
        return cipher;
    }

    /**
     * AES解密
     *
     * @param cipher 16字节密文
     * @return 16字节明文
     */
    public byte[] decrypt(byte[] cipher) {
        // 16字节密文
        byte[] plain = new byte[16];
        // 状态矩阵
        byte[][] state = new byte[4][4];
        for (int i = 0; i < 4; i++)
            System.arraycopy(cipher, i * 4, state[i], 0, 4);
        // 轮密钥加
        addRoundKey(state, k[10]);
        // 逆向行移位
        state = invShiftRows(state);
        // 逆向字节代替
        invSubBytes(state);
        for (int i = 9; i >= 1; i--) {
            // 轮密钥加
            addRoundKey(state, k[i]);
            // 逆向列混淆
            state = invMixColumns(state);
            // 逆向行移位
            state = invShiftRows(state);
            // 逆向字节代替
            invSubBytes(state);
        }
        // 轮密钥加
        addRoundKey(state, k[0]);
        for (int i = 0; i < 4; i++)
            System.arraycopy(state[i], 0, plain, 4 * i, 4);
        return plain;
    }

    /**
     * ECB模式文件加密
     *
     * @param p 明文文件
     * @param c 密文文件
     */
    public void encrypt(File p, File c) {
        try {
            InputStream in = new FileInputStream(p);
            // 如果密文文件不存在就创建
            if (!c.exists())
                c.createNewFile();
            OutputStream out = new FileOutputStream(c);
            // 记录每组读取的字节数
            int length;
            // 每一组的明文和密文
            byte[] plain = new byte[16];
            byte[] cipher;
            // 读取16字节，加密
            while ((length = in.read(plain)) == 16) {
                cipher = encrypt(plain);
                out.write(cipher);
            }
            if (length == -1)
                length = 0;
            // 不足16字节进行填充
            for (int i = length; i < 16; i++)
                plain[i] = (byte) (16 - length);
            cipher = encrypt(plain);
            out.write(cipher);
            in.close();
            out.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            System.out.println("File Not Found");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * ECB模式文件解密
     *
     * @param c 密文文件
     * @param p 明文文件
     */
    public void decrypt(File c, File p) {
        try {
            InputStream in = new FileInputStream(c);
            // 如果明文文件不存在就创建
            if (!p.exists())
                p.createNewFile();
            OutputStream out = new FileOutputStream(p);
            // 每一组的明文和密文
            byte[] plain;
            byte[] cipher = new byte[16];
            in.read(cipher);
            //先解密一组
            plain = decrypt(cipher);
            //然后每读取一组，输出上一组解密的明文
            while (in.read(cipher) != -1) {
                out.write(plain);
                plain = decrypt(cipher);
            }
            //最后有填充的组
            plain = decrypt(cipher);
            out.write(plain, 0, 16 - plain[15]);
            in.close();
            out.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            System.out.println("File Not Found");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成轮密钥
     *
     * @param key 初始密钥
     */
    public void keyExpansion(byte[] key) {
        byte[][] w = new byte[44][4];
        byte[] RC = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, (byte) 0x80, 0x1B, 0x36};
        // 将前nk个字填入w
        for (int i = 0; i < 4; i++)
            System.arraycopy(key, 4 * i, w[i], 0, 4);
        for (int i = 4; i < w.length; i++) {
            // 如果i是nk的倍数，wi = wi-nk ⊕ g(wi-1)，g为循环左移1字节⊕字节代替⊕Rcon
            if (i % 4 == 0) {
                // 异或Rcon即第一个字节异或RC
                w[i][0] = (byte) (w[i - 4][0] ^ S[w[i - 1][1] & 0xff] ^ RC[i / 4 - 1]);
                w[i][1] = (byte) (w[i - 4][1] ^ S[w[i - 1][2] & 0xff]);
                w[i][2] = (byte) (w[i - 4][2] ^ S[w[i - 1][3] & 0xff]);
                w[i][3] = (byte) (w[i - 4][3] ^ S[w[i - 1][0] & 0xff]);
            }
                // 其他wi = wi-nk ⊕ wi-1
            else
                for (int j = 0; j < 4; j++)
                    w[i][j] = (byte) (w[i - 4][j] ^ w[i - 1][j]);
        }
        // w填入密钥
        for (int i = 0; i < 11; i++)
            for (int j = 0; j < 4; j++)
                System.arraycopy(w[i * 4 + j], 0, k[i][j], 0, 4);
    }

    /**
     * 轮密钥加
     *
     * @param state 4*4状态矩阵
     * @param key   4*4轮密钥
     */
    public static void addRoundKey(byte[][] state, byte[][] key) {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                state[i][j] ^= key[i][j];
    }

    /**
     * 字节代替
     *
     * @param state 4*4状态矩阵
     */
    public static void subBytes(byte[][] state) {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                state[i][j] = S[state[i][j] & 0xff];
    }

    /**
     * 逆字节代替
     *
     * @param state 4*4状态矩阵
     */
    public static void invSubBytes(byte[][] state) {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                state[i][j] = INV_S[state[i][j] & 0xff];
    }

    /**
     * 行移位
     * <p>
     * 由于状态矩阵是按行填充的，所以这里实际上是“列移位”，只是保留了原方法名
     *
     * @param state 4*4状态矩阵
     * @return 经过行移位后的状态矩阵
     */
    public static byte[][] shiftRows(byte[][] state) {
        byte[][] result = new byte[4][4];
        // 4行分别循环右移0，1，2，3位
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                result[j][i] = state[(j + i) % 4][i];
        return result;
    }

    /**
     * 逆行移位
     * <p>
     * 由于状态矩阵是按行填充的，所以这里实际上是“逆列移位”，只是保留了原方法名
     *
     * @param state 4*4状态矩阵
     * @return 经过逆行移位后的状态矩阵
     */
    private static byte[][] invShiftRows(byte[][] state) {
        byte[][] result = new byte[4][4];
        // 4行分别循环左移0，1，2，3位
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                result[j][i] = state[(j - i + 4) % 4][i];
        return result;
    }

    /**
     * 列混淆
     * <p>
     * 由于状态矩阵是按行填充的，所以这里实际上是“行混淆”，只是保留了原方法名
     *
     * @param state 4*4状态矩阵
     * @return 经过列混淆后的状态矩阵
     */
    private static byte[][] mixColumns(byte[][] state) {
        // 列混淆可以表示为与以下矩阵相乘
        byte[][] matrix = {{2, 1, 1, 3}, {3, 2, 1, 1}, {1, 3, 2, 1}, {1, 1, 3, 2}};
        // 4*4矩阵相乘
        byte[][] result = new byte[4][4];
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                for (int k = 0; k < 4; k++)
                    result[i][j] ^= multiply(state[i][k], matrix[k][j]);
        return result;
    }

    /**
     * 逆列混淆
     * <p>
     * 由于状态矩阵是按行填充的，所以这里实际上是“逆行混淆”，只是保留了原方法名
     *
     * @param state 4*4状态矩阵
     * @return 经过逆列混淆后的状态矩阵
     */
    private static byte[][] invMixColumns(byte[][] state) {
        // 逆列混淆可以表示为与以下矩阵相乘
        byte[][] matrix = {{0xE, 0x9, 0xD, 0xB}, {0xB, 0xE, 0x9, 0xD}, {0xD, 0xB, 0xE, 0x9},
                {0x9, 0xD, 0xB, 0xE}};
        byte[][] result = new byte[4][4];
        // 4*4矩阵相乘
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                for (int k = 0; k < 4; k++)
                    result[i][j] ^= multiply(state[i][k], matrix[k][j]);
        return result;
    }

    /**
     * GF(2^8)上的乘法
     *
     * @param a 第一个因数
     * @param b 第一个因数
     * @return 积
     */
    public static byte multiply(byte a, byte b) {
        byte tmp = a;
        byte result = 0;
        // b0为1时，结果要异或的第一个数为a*0x01，否则为0（异或0为本身）
        if ((b & 1) == 1)
            result = a;
        // 算出a乘0b10，0b100……
        for (int i = 1; i < 8; i++) {
            // 最高位为1时左移1位再异或11011
            if (tmp < 0)
                tmp = (byte) ((tmp << 1) ^ 27);
                // 最高位为0时左移1位
            else
                tmp = (byte) (tmp << 1);
            b = (byte) ((b & 0xff) >> 1);
            // bi为1，结果异或bi*a^i
            if ((b & 1) == 1)
                result ^= tmp;
        }
        return result;
    }
}
