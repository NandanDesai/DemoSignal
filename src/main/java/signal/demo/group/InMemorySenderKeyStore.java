package signal.demo.group;

import org.whispersystems.libsignal.groups.SenderKeyName;
import org.whispersystems.libsignal.groups.state.SenderKeyRecord;
import org.whispersystems.libsignal.groups.state.SenderKeyStore;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;


/*
* A simple SenderKeyStore for demo purposes
* */
public class InMemorySenderKeyStore implements SenderKeyStore {

    private final Map<SenderKeyName, SenderKeyRecord> store = new HashMap<>();

    @Override
    public void storeSenderKey(SenderKeyName senderKeyName, SenderKeyRecord record) {
        store.put(senderKeyName, record);
    }

    @Override
    public SenderKeyRecord loadSenderKey(SenderKeyName senderKeyName) {
        try {
            SenderKeyRecord record = store.get(senderKeyName);

            if (record == null) {
                return new SenderKeyRecord();
            } else {
                return new SenderKeyRecord(record.serialize());
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}