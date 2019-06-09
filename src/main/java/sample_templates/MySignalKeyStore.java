package sample_templates;

import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;

import java.io.IOException;
import java.util.List;
/*
* This class is just a template for those who want to write their own SignalProtocolStore with storing and retrieving data
* from actual database.
* */
public class MySignalKeyStore implements SignalProtocolStore {


    @Override
    public IdentityKeyPair getIdentityKeyPair() {

        /*
            When you generate your own IdentityKeyPair, store them in a shared preference something like this:

            save(context, IDENTITY_PUBLIC_KEY_PREF, sample_templates.Base64.encodeBytes(djbIdentityKey.serialize()));
            save(context, IDENTITY_PRIVATE_KEY_PREF, sample_templates.Base64.encodeBytes(djbPrivateKey.serialize()));

            Then over here,return them like this:

            IdentityKey publicKey=new IdentityKey(sample_templates.Base64.decode(retrieve(context, IDENTITY_PUBLIC_KEY_PREF)), 0);
            ECPrivateKey privateKey = Curve.decodePrivatePoint(sample_templates.Base64.decode(retrieve(context, IDENTITY_PRIVATE_KEY_PREF)));
            return new IdentityKeyPair(publicKey, privateKey);

            All this stuff is present in IdentityKeyUtil.java file in original repo
        */

        return null;
    }

    @Override
    public int getLocalRegistrationId() {

        //store the registration Id generated through KeyHelper.generateRegistrationId(); in a SharedPreference and return that here.

        return 0;
    }

    @Override
    public boolean saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
        String addressName=address.getName();
        String identityKeyString = Base64.encodeBytes(identityKey.serialize());

        //save these both in the database

        return false;
    }

    @Override
    public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction) {

        /*
            Not sure what this method is for but you can refer this file in the original repo
            TextSecureIdentityKeyStore.java
        */

        return false;
    }

    @Override
    public IdentityKey getIdentity(SignalProtocolAddress address) {
        String addressName=address.getName();
        //use addressName to get the serialized Identity from the database

        String serializedIdentity=""; //get this from the database
        IdentityKey identityKey=null;
        try {
            identityKey=new IdentityKey(Base64.decode(serializedIdentity), 0);
        } catch (InvalidKeyException | IOException e) {
            e.printStackTrace();
        }
        return identityKey;
    }

    @Override
    public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {

        /*
            ECPublicKey  publicKey  = Curve.decodePoint(sample_templates.Base64.decode(<public key from db>, 0);
            ECPrivateKey privateKey = Curve.decodePrivatePoint(sample_templates.Base64.decode(<private key from db>));

            return new PreKeyRecord(keyId, new ECKeyPair(publicKey, privateKey));
        */

        return null;
    }

    @Override
    public void storePreKey(int preKeyId, PreKeyRecord record) {
        String publicKey=Base64.encodeBytes(record.getKeyPair().getPublicKey().serialize());
        String privateKey= Base64.encodeBytes(record.getKeyPair().getPrivateKey().serialize());

        //insert preKeyId, publicKey, privateKey into the database
    }

    @Override
    public boolean containsPreKey(int preKeyId) {
        //check if the database contains the preKey for the following Id

        return false;
    }

    @Override
    public void removePreKey(int preKeyId) {
        //delete the prekey from the database for the following Id
    }

    @Override
    public SessionRecord loadSession(SignalProtocolAddress address) {
        String addressName=address.getName();
        int deviceId=address.getDeviceId();
        //use both of the above variables to get SessionRecord

        //return SessionRecord( byte[] )

        return null;
    }

    @Override
    public List<Integer> getSubDeviceSessions(String name) {

        //use String name to get the corresponding deviceId

        return null;
    }

    @Override
    public void storeSession(SignalProtocolAddress address, SessionRecord record) {
        String addressName=address.getName();
        int deviceId=address.getDeviceId();
        byte[] serializedRecord=record.serialize();

        //store record as a blob in the database
    }

    @Override
    public boolean containsSession(SignalProtocolAddress address) {
        //take address.getName() and address.getDeviceId() and check if a row exists in the database or not
        String addressName=address.getName();
        int deviceId=address.getDeviceId();


        return false;
    }

    @Override
    public void deleteSession(SignalProtocolAddress address) {
        //take address.getName() and address.getDeviceId() and and delete the row
        String addressName=address.getName();
        int deviceId=address.getDeviceId();

    }

    @Override
    public void deleteAllSessions(String name) {
        //take name and delete the row


    }

    @Override
    public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
        /*
            ECPublicKey  publicKey  = Curve.decodePoint(sample_templates.Base64.decode(<serialized public key from database>)), 0);
            ECPrivateKey privateKey = Curve.decodePrivatePoint(sample_templates.Base64.decode(<serialized private key from database>));
            byte[]       signature  = sample_templates.Base64.decode(<serialized signature from database>);
            long         timestamp  = <timestamp from database>;

            return new SignedPreKeyRecord(keyId, timestamp, new ECKeyPair(publicKey, privateKey), signature);
        */

        return null;
    }

    @Override
    public List<SignedPreKeyRecord> loadSignedPreKeys() {

        //get all from database and return it, select * from SignedPreKeyDatabase
        return null;
    }

    @Override
    public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
        int keyId=signedPreKeyId;
        String publicKey=Base64.encodeBytes(record.getKeyPair().getPublicKey().serialize());
        String privateKey=Base64.encodeBytes(record.getKeyPair().getPrivateKey().serialize());
        String signature=Base64.encodeBytes(record.getSignature());
        long timestamp=record.getTimestamp();

        //store all these in the database
    }

    @Override
    public boolean containsSignedPreKey(int signedPreKeyId) {
        //check if the row of the corresponding signedPreKeyId is present or not and return

        return false;
    }

    @Override
    public void removeSignedPreKey(int signedPreKeyId) {
        //delete row from the database
    }
}