package signal.demo.one_on_one;/*
 * DemoSignal — Demonstrate the signal protocol.
 * Copyright (C) 2017 Vijay Lakshminarayanan <lvijay@gmail.com>.
 * Modified by Nandan Desai
 */

import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.SignalProtocolStore;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

public class Session {

    private /* static */ enum Operation {ENCRYPT, DECRYPT;}

    private final SignalProtocolStore self;
    private PreKeyBundle otherKeyBundle;
    private SignalProtocolAddress otherAddress;
    private Operation lastOp;
    private SessionCipher cipher;

    public Session(SignalProtocolStore self,
                   PreKeyBundle otherKeyBundle,
                   SignalProtocolAddress otherAddress) {
        this.self = self;
        this.otherKeyBundle = otherKeyBundle;
        this.otherAddress = otherAddress;
    }

    private synchronized SessionCipher getCipher(Operation operation) {
        if (operation == lastOp) {
            return cipher;
        }

        SignalProtocolAddress toAddress = otherAddress;
        SessionBuilder builder = new SessionBuilder(self, toAddress);

        try {
            builder.process(otherKeyBundle);
        } catch (InvalidKeyException | UntrustedIdentityException e) {
            throw new RuntimeException(e);
        }

        this.cipher = new SessionCipher(self, toAddress);
        this.lastOp = operation;

        return cipher;
    }

    public PreKeySignalMessage encrypt(String message) throws UntrustedIdentityException {
        SessionCipher cipher = getCipher(Operation.ENCRYPT);

        CiphertextMessage ciphertext = cipher.encrypt(message.getBytes(StandardCharsets.UTF_8));
        byte[] rawCiphertext = ciphertext.serialize();

        try {
            PreKeySignalMessage encrypted = new PreKeySignalMessage(rawCiphertext);

            return encrypted;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String decrypt(PreKeySignalMessage ciphertext) {
        SessionCipher cipher = getCipher(Operation.DECRYPT);

        try {
            byte[] decrypted = cipher.decrypt(ciphertext);

            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public PreKeySignalMessage encryptFile(File inputFile) {
        SessionCipher cipher = getCipher(Operation.ENCRYPT);

        try {

            byte[] bytesArray = new byte[(int) inputFile.length()];

            FileInputStream fileInputStream = new FileInputStream(inputFile);
            fileInputStream.read(bytesArray);
            fileInputStream.close();

            CiphertextMessage ciphertextMessage = cipher.encrypt(bytesArray);

            byte[] rawCiphertext = ciphertextMessage.serialize();
            return new PreKeySignalMessage(rawCiphertext);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public File decryptFile(PreKeySignalMessage ciphertext) {
        SessionCipher cipher = getCipher(Operation.DECRYPT);

        String outputFileName = "decryptedImage.jpg";

        try {
            byte[] decrypted = cipher.decrypt(ciphertext);
            OutputStream outputStream = new FileOutputStream(outputFileName);

            outputStream.write(decrypted);
            outputStream.close();
            return new File(outputFileName);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }
}
