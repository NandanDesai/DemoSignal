package signal.demo;/*
 * DemoSignal — Demonstrate the signal protocol.
 * Copyright (C) 2017 Vijay Lakshminarayanan <lvijay@gmail.com>.
 * Modified by Nandan Desai
 */

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.groups.state.SenderKeyStore;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore;
import org.whispersystems.libsignal.util.KeyHelper;
import signal.demo.group.InMemorySenderKeyStore;

public class Entity {
    private final SignalProtocolStore store;
    private final PreKeyBundle preKey;
    private final SignalProtocolAddress address;
    private final SenderKeyStore senderKeyStore; /*used for group messages*/

    public Entity(int preKeyId, int signedPreKeyId, String address)
            throws InvalidKeyException
    {
        this.address = new SignalProtocolAddress(address, 1);

        /*
        * Here we are using InMemorySignalProtocolStore for demonstration. In real application, you will have to write your
        * own class to implement SignalProtocolStore interface to store and fetch keys from database.
        * Check out "MySignalKeyStore" class in sample_templates package
        * */
        this.store = new InMemorySignalProtocolStore(
                KeyHelper.generateIdentityKeyPair(),
                KeyHelper.generateRegistrationId(false));

        /*
        * Here we are using InMemorySenderKeyStore for demonstration. In real application,
        * you need to implement your own.
        * */
        this.senderKeyStore=new InMemorySenderKeyStore(); /* for Group messages */

        IdentityKeyPair identityKeyPair = store.getIdentityKeyPair();
        int registrationId = store.getLocalRegistrationId();

        ECKeyPair preKeyPair = Curve.generateKeyPair();
        ECKeyPair signedPreKeyPair = Curve.generateKeyPair();
        int deviceId = 1;
        long timestamp = System.currentTimeMillis();

        byte[] signedPreKeySignature = Curve.calculateSignature(
                identityKeyPair.getPrivateKey(),
                signedPreKeyPair.getPublicKey().serialize());

        IdentityKey identityKey = identityKeyPair.getPublicKey();
        ECPublicKey preKeyPublic = preKeyPair.getPublicKey();
        ECPublicKey signedPreKeyPublic = signedPreKeyPair.getPublicKey();

        this.preKey = new PreKeyBundle(
                registrationId,
                deviceId,
                preKeyId,
                preKeyPublic,
                signedPreKeyId,
                signedPreKeyPublic,
                signedPreKeySignature,
                identityKey);

        PreKeyRecord preKeyRecord = new PreKeyRecord(preKey.getPreKeyId(), preKeyPair);
        SignedPreKeyRecord signedPreKeyRecord = new SignedPreKeyRecord(
                signedPreKeyId, timestamp, signedPreKeyPair, signedPreKeySignature);

        store.storePreKey(preKeyId, preKeyRecord);
        store.storeSignedPreKey(signedPreKeyId, signedPreKeyRecord);
    }

    public SignalProtocolStore getStore() {
        return store;
    }

    public PreKeyBundle getPreKey() {
        return preKey;
    }

    public SignalProtocolAddress getAddress() {
        return address;
    }

    public SenderKeyStore getSenderKeyStore() {
        return senderKeyStore;
    }
}
