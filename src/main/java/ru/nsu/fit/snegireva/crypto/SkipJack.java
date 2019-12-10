package ru.nsu.fit.snegireva.crypto;

import ru.fit.nsu.snegireva.longbytes.LongBytes;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;

@SuppressWarnings("Duplicates")
public class SkipJack {
    public static final int[] F = new int[]{
            0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
            0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
            0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
            0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
            0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
            0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
            0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
            0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d,
            0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
            0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
            0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
            0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
            0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
            0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
            0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
            0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46
    };

    private static final int key[] = {241, 164, 117, 194, 244, 3, 131, 51, 122, 77};

    public static void encrypt(File in, File out) throws IOException {
        byte[] bytes = Files.readAllBytes(in.toPath());
        long[] longs = LongBytes.bytesToLong(bytes);

        long[] code = new long[longs.length];

        for (int i = 0; i < longs.length; i++)
            code[i] = skipJack(longs[i], key);

        byte[] bytesCode = LongBytes.longToBytes(code);

        new FileOutputStream(out).write(bytesCode);
    }

    public static void decrypt(File in, File out) throws IOException {
        byte[] bytes = Files.readAllBytes(in.toPath());
        long[] longs = LongBytes.bytesToLong(bytes);

        long[] decode = new long[longs.length];

        for (int i = 0; i < longs.length; i++)
            decode[i] = deSkipJack(longs[i], key);

        byte[] bytesDecode = LongBytes.longToBytes(decode);

        new FileOutputStream(out).write(bytesDecode);
    }

    private static long skipJack(long message, int key[]) {
        int counter = 0;
        while (counter < 8) {
            message = ruleA(counter, message, key);
            counter++;
        }
        while (counter < 16) {
            message = ruleB(counter, message, key);
            counter++;
        }
        while (counter < 24) {
            message = ruleA(counter, message, key);
            counter++;
        }
        while (counter < 32) {
            message = ruleB(counter, message, key);
            counter++;
        }
        return message;
    }

    private static long deSkipJack(long message, int key[]) {
        int counter = 31;
        while (counter > 23) {
            message = deRuleB(counter, message, key);
            counter--;
        }
        while (counter > 15) {
            message = deRuleA(counter, message, key);
            counter--;
        }
        while (counter > 7) {
            message = deRuleB(counter, message, key);
            counter--;
        }
        while (counter > -1) {
            message = deRuleA(counter, message, key);
            counter--;
        }
        return message;
    }

    private static long ruleA(int step, long block, int key[]) {
        long w_1i = (block >>> 48);
        long w_2i = (block >> 32) & 0xFFFFL;
        long w_3i = (block >> 16) & 0xFFFFL;
        long w_4i = (block & 0xFFFFL);

        long w_1o = G(step, w_1i, key) ^ w_4i ^ (step + 1);
        long w_2o = G(step, w_1i, key);

        return w_1o << 48 | w_2o << 32 | w_2i << 16 | w_3i;
    }

    private static long ruleB(int step, long block, int key[]) {
        long w_1i = (block >>> 48);
        long w_2i = ((block >> 32) & 0xFFFFL);
        long w_3i = ((block >> 16) & 0xFFFFL);
        long w_4i = (block & 0xFFFFL);

        long w_2o = G(step, w_1i, key);
        long w_3o = w_1i ^ w_2i ^ (step + 1);

        return w_4i << 48 | w_2o << 32 | w_3o << 16 | w_3i;
    }

    private static long deRuleA(int step, long block, int[] key) {
        long w_1i = (block >>> 48);
        long w_2i = (block >> 32) & 0xFFFFL;
        long w_3i = (block >> 16) & 0xFFFFL;
        long w_4i = (block & 0xFFFFL);

        long w_1o = deG(step, w_2i, key);
        long w_4o = w_1i ^ w_2i ^ (step + 1);

        return w_1o << 48 | w_3i << 32 | w_4i << 16 | w_4o;
    }

    private static long deRuleB(int step, long block, int key[]) {
        long w_1i = (block >>> 48);
        long w_2i = ((block >> 32) & 0xFFFFL);
        long w_3i = ((block >> 16) & 0xFFFFL);
        long w_4i = (block & 0xFFFFL);

        long w_1o = deG(step, w_2i, key);
        long w_2o = deG(step, w_2i, key) ^ w_3i ^ (step + 1);

        return w_1o << 48 | w_2o << 32 | w_4i << 16 | w_1i;
    }

    private static long G(int step, long w, int key[]) {
        int g1 = (int) (w >>> 8);
        int g2 = (int) (w & 0xFF);

        int cv0 = key[(step * 4) % 10];
        int cv1 = key[(step * 4 + 1) % 10];
        int cv2 = key[(step * 4 + 2) % 10];
        int cv3 = key[(step * 4 + 3) % 10];

        int g3 = (F[g2 ^ cv0] ^ g1);
        int g4 = (F[g3 ^ cv1] ^ g2);
        int g5 = (F[g4 ^ cv2] ^ g3);
        int g6 = (F[g5 ^ cv3] ^ g4);

        return ((long) g5 << 8) | g6;
    }

    private static long deG(int step, long w, int key[]) {
        int g1 = (int) (w & 0xFF);
        int g2 = (int) (w >>> 8);

        int cv0 = key[(step * 4 + 3) % 10];
        int cv1 = key[(step * 4 + 2) % 10];
        int cv2 = key[(step * 4 + 1) % 10];
        int cv3 = key[(step * 4) % 10];

        int g3 = (F[g2 ^ cv0] ^ g1);
        int g4 = (F[g3 ^ cv1] ^ g2);
        int g5 = (F[g4 ^ cv2] ^ g3);
        int g6 = (F[g5 ^ cv3] ^ g4);

        return ((long) g6 << 8) | g5;
    }

    private static int hashKey[];

    private static void setHashKey(byte[] bytes, int offset){
        hashKey = new int[10];
        for (int i = offset; i < offset + 10; i++){
            if (i >= bytes.length)
                break;
            hashKey[i - offset] = (int)bytes[i];
        }

    }

    public static void hash(File file) throws IOException {
        byte[] bytes = Files.readAllBytes(file.toPath());
        byte[] H_in = {105, 110, 105, 116, 105, 110, 105, 116};  //"initinit"

        long[] H_prev = LongBytes.bytesToLong(H_in);

        for (int i = 0; i < bytes.length; i += 10){
            setHashKey(bytes, i);
            long H = skipJack(H_prev[0], hashKey);
            long tmp = H_prev[0] ^ H;
            H_prev[0] = tmp;
        }

        byte[] out = LongBytes.longToBytes(H_prev);

        new FileOutputStream(new File("hash.txt")).write(out);
    }

}
