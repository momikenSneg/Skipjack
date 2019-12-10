package ru.nsu.fit.snegireva.crypto;

import java.io.File;
import java.io.IOException;

public class Main {
    public static void main(String[] args) {
        try {
            //SkipJack.decrypt(new File("code.txt"), new File("out.txt"));
            //SkipJack.encrypt(new File("in.txt"), new File("code.txt"));

            SkipJack.hash(new File("in.txt"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}