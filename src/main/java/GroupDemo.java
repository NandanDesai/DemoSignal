import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.groups.GroupCipher;
import org.whispersystems.libsignal.groups.SenderKeyName;
import org.whispersystems.libsignal.protocol.SenderKeyDistributionMessage;

import java.nio.charset.StandardCharsets;

public class GroupDemo {
    public static void main(String[] args) throws InvalidKeyException, NoSessionException, LegacyMessageException, DuplicateMessageException, InvalidMessageException {

        /*
        * There is a class called as SenderKeyName which is just a (groupId {or groupName} + senderId {or address} + deviceId) tuple
        * This SenderKeyName is used to store the corresponding Keys of the message sender of a group. The store is called
        * SenderKeyStore. This SenderKeyStore is used by GroupSessionBuilder to build a group session to encrypt and decrypt messages
        * sent and received from/to a group.
        *
        * In my class Entity, both SenderKeyStore and GroupSessionBuilder are included.
        * For demonstration purposes, SenderKeyStore will just store and fetch keys to/from the memory using the InMemorySenderKeyStore
        * class present in this package.
        * */
        Entity alpha = new Entity(1, 314159, "Alpha");
        Entity bravo = new Entity(2, 271828, "Bravo");
        Entity charlie = new Entity(3, 123456, "Charlie");

        String groupName="Political Discussions";

        /*
        * Charlie wants to send a message to the group. So create a SenderKeyName with Charlie's info and group's name.
        *
        * */
        SenderKeyName charlieGroupSender = new SenderKeyName(groupName, charlie.getAddress());

        /*
        * Build the group ciphers for all three participants of the group w.r.t. the sender (Charlie).
        * The sender will use this GroupCipher to encrypt and the receivers will use it to decrypt.
        * */
        GroupCipher alphaGroupCipher = new GroupCipher(alpha.getSenderKeyStore(), charlieGroupSender);
        GroupCipher bravoGroupCipher = new GroupCipher(bravo.getSenderKeyStore(), charlieGroupSender);
        GroupCipher charlieGroupCipher = new GroupCipher(charlie.getSenderKeyStore(), charlieGroupSender);


        /*
        * Charlie first sends a key distribution message to the other members of the group
        * */
        SenderKeyDistributionMessage charlieKeyDistributionMessage = charlie.getGroupSessionBuilder().create(charlieGroupSender);


        /*
        * Alpha and Bravo will process (store in SenderKeyStore) Charlie's SenderKeyName and KeyDistributionMessage and they'll get ready to decrypt Charlie's messages
        * */
        alpha.getGroupSessionBuilder().process(charlieGroupSender, charlieKeyDistributionMessage);
        bravo.getGroupSessionBuilder().process(charlieGroupSender, charlieKeyDistributionMessage);

        String charlieGroupMessage="Hi guys! This is Charlie!!";

        /*
        * Charlie will encrypt his message
        * */
        byte[] charlieCipherText=charlieGroupCipher.encrypt(charlieGroupMessage.getBytes());

        System.out.println("Ciphertext sent by Charlie : "+new String(charlieCipherText, StandardCharsets.UTF_8));

        /*
        * Alpha and Bravo will decrypt the message after receiving it.
        * */
        String messageReceivedByAlpha=new String(alphaGroupCipher.decrypt(charlieCipherText), StandardCharsets.UTF_8);
        String messageReceivedByBravo=new String(bravoGroupCipher.decrypt(charlieCipherText), StandardCharsets.UTF_8);

        if(charlieGroupMessage.equals(messageReceivedByAlpha)){
            System.out.println("Alpha decrypted Charlie's message successfully");
        }else{
            System.out.println("Alpha didn't decrypt Charlie's message :(");
        }

        if(charlieGroupMessage.equals(messageReceivedByBravo)){
            System.out.println("Bravo decrypted Charlie's message successfully");
        }else{
            System.out.println("Bravo didn't decrypt Charlie's message :(");
        }



    }
}
