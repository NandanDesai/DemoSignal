package signal.demo.one_on_one;/*
 * DemoSignal — Demonstrate the signal protocol.
 * Copyright (C) 2017 Vijay Lakshminarayanan <lvijay@gmail.com>.
 * Modified by Nandan Desai
 */

import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import signal.demo.Entity;
import sun.misc.BASE64Encoder;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Demo {
    public static void main(String[] args) throws Exception {

        /*
         * Text messages Alice and Bob send to each other
         * */
        String messageFromAlice = "Hello from Alice";
        String messageFromBob = "Hello from Bob";

        /*
         * Create instances of the two parties.
         */
        Entity alice = new Entity(1, 314159, "Alice");
        Entity bob = new Entity(2, 271828, "Bob");

        /*
         * Establish a session between the two parties.
         */
        Session aliceToBobSession = new Session(alice.getStore(), bob.getPreKey(), bob.getAddress());

        /*
         * Alice can now send messages to Bob.
         */
        System.out.println("Plaintext Message being sent to Bob: "+messageFromAlice);

        PreKeySignalMessage toBobMessage = aliceToBobSession.encrypt(messageFromAlice);

        System.out.println("Ciphertext message sent to Bob : "+new String(toBobMessage.getWhisperMessage().getBody(), StandardCharsets.UTF_8));

        /*
         * For Bob to read them, Bob must know Alice.
         */
        Session bobToAliceSession = new Session(bob.getStore(), alice.getPreKey(), alice.getAddress());

        /*
         * Now Bob can decrypt them.
         */

        String decryptedAliceMessage = bobToAliceSession.decrypt(toBobMessage);

        if (!decryptedAliceMessage.equals(messageFromAlice)) {
            throw new IllegalStateException("Message sent from Alice to Bob doesn't match");
        } else {
            System.out.println("Message sent from Alice to Bob matches!!");
        }

        /*
         * Bob, too, can send messages to Alice.
         */
        System.out.println("Plaintext Message being sent to Alice: "+messageFromBob);

        PreKeySignalMessage toAliceMessage = bobToAliceSession.encrypt(messageFromBob);

        System.out.println("Ciphertext message sent to Alice : "+new String(toAliceMessage.getWhisperMessage().getBody(), StandardCharsets.UTF_8));


        /*
         * Alice can decrypt the Bob's message.
         * */
        String decryptedBobMessage = aliceToBobSession.decrypt(toAliceMessage);

        if (!decryptedBobMessage.equals(messageFromBob)) {
            throw new IllegalStateException("Message sent from Bob to Alice doesn't match");
        } else {
            System.out.println("Message sent from Bob to Alice matches!!");
        }


        System.out.println();
        System.out.println();


        /*
         * Bob can send a file (here, an image from "resources" directory of this project) to Alice
         * */
        URL imageSampleUrl = ClassLoader.getSystemClassLoader().getResource("Beach.jpg");
        File inputFile = new File(imageSampleUrl.toURI());
        PreKeySignalMessage toAliceFileMessage = bobToAliceSession.encryptFile(inputFile);


        /*
         * Alice can now decrypt the encrypted file received from Bob
         * */
        File outputFile = aliceToBobSession.decryptFile(toAliceFileMessage);

        /*
        * Getting the MD5 hash of both the files sent by Bob and received by Alice and comparing them.
        * */
        String inputFileHash= getHash(inputFile);
        String outputFileHash= getHash(outputFile);

        System.out.println("Hash of input file: "+inputFileHash);
        System.out.println("Hash of output file: "+outputFileHash);

        if(inputFileHash.equals(outputFileHash)){
            System.out.println("Files successfully sent and received by Alice and Bob!");
        }else{
            System.out.println("File sent by Bob doesn't match to that received by Alice :(");
        }


    }

    private static String getHash(File file) throws IOException, NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance("MD5");
        try (InputStream is = Files.newInputStream(Paths.get(file.getAbsolutePath()));
             DigestInputStream dis = new DigestInputStream(is, md)) {

        }
        return new BASE64Encoder().encode(md.digest());

    }
}
