package signal.demo.group;

import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.groups.GroupCipher;
import org.whispersystems.libsignal.groups.GroupSessionBuilder;
import org.whispersystems.libsignal.groups.SenderKeyName;
import org.whispersystems.libsignal.protocol.SenderKeyDistributionMessage;
import signal.demo.Entity;

import java.nio.charset.StandardCharsets;

public class GroupDemo {
    public static void main(String[] args) throws InvalidKeyException, NoSessionException, LegacyMessageException, DuplicateMessageException, InvalidMessageException {


        /*
        * Create three entities
        * */
        Entity alpha = new Entity(1, 314159, "Alpha");
        Entity bravo = new Entity(2, 271828, "Bravo");
        Entity charlie = new Entity(3, 123456, "Charlie");


        /*
        * Build group session builder for each of them
        * */
        GroupSessionBuilder alphaSessionBuilder = new GroupSessionBuilder(alpha.getSenderKeyStore());
        GroupSessionBuilder bravoSessionBuilder = new GroupSessionBuilder(bravo.getSenderKeyStore());
        GroupSessionBuilder charlieSessionBuilder = new GroupSessionBuilder(charlie.getSenderKeyStore());

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
        SenderKeyDistributionMessage charlieKeyDistributionMessage = charlieSessionBuilder.create(charlieGroupSender);


        /*
        * Alpha and Bravo will process (store in SenderKeyStore) Charlie's SenderKeyName and KeyDistributionMessage and they'll get ready to decrypt Charlie's messages
        * */
        alphaSessionBuilder.process(charlieGroupSender, charlieKeyDistributionMessage);
        bravoSessionBuilder.process(charlieGroupSender, charlieKeyDistributionMessage);

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
