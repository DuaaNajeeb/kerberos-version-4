package networkSecurity;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;



import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Client {

    private final String IDtgs = "tgs_service";

    public Client() {

        try (Socket socketAs = new Socket("localhost", 7000)) { // connect to authentication server
            InputStream in = socketAs.getInputStream();
            OutputStream out = socketAs.getOutputStream();

            // send request to AS: IDC || IDtgs || TS1
            String requestFromClient = "Duaa||" + IDtgs + "||" + System.currentTimeMillis();

            // معالجة اول بايتين المحجوزين للبروتوكول
            byte[] messageBytes = requestFromClient.getBytes(StandardCharsets.UTF_8);
            byte[] finalRequest = new byte[messageBytes.length + 2];
            System.arraycopy(messageBytes, 0, finalRequest, 2, messageBytes.length);

            out.write(finalRequest); // ارسال الطلب
            out.flush(); // تأكيد كل البايتات وصلت

            try {
                // استقبال الرد من AS
                byte[] buffer = new byte[2048];
                int byteRead = in.read(buffer);

                if (byteRead == -1) {
                    throw new IllegalStateException("Server closed connection");
                }

                String responseInBase64 = new String(buffer, 0, byteRead, StandardCharsets.UTF_8);
                byte[] encryptedResponse = Base64.getDecoder().decode(responseInBase64);

                // استخراج Kc من الباسوورد المخزن عند العميل
                SecretKey clientKeyServer = DES.getKeyFromPassword("1230915"); // Duaa password must match server

                // فك التشفير للرسالة
                byte[] decryptedData = DES.D(encryptedResponse, clientKeyServer.getEncoded());
                String answer = new String(decryptedData, StandardCharsets.UTF_8);
                System.out.println(" successful process :) " + answer);

                // تقسيم الرد لاستخراج المعلومات
                String[] part = answer.split("\\|\\|");
                String sessionKey = part[0]; // Kc,tgs (Base64)
                String ticketTgs = part[4];  // Ticket_tgs (Base64)

                byte[] sessionKeys = Base64.getDecoder().decode(sessionKey);
                SecretKey kcTGS = new SecretKeySpec(sessionKeys, "DES");
                String authenticator = getAuthenticater(kcTGS);

                // ارسال الطلب الى TGS
                try (Socket socketTGS = new Socket("localhost", 8000)) {
                    InputStream inTGS = socketTGS.getInputStream();
                    OutputStream outputTGS = socketTGS.getOutputStream();

                    // IDv || Ticket_tgs || Authenticator
                    String requestToTGS = "MailServer||" + ticketTgs + "||" + authenticator;

                    // معالجة اول بايتين للبروتوكول
                    byte[] messageBytesTGS = requestToTGS.getBytes(StandardCharsets.UTF_8);
                    byte[] finalRequestTGS = new byte[messageBytesTGS.length + 2];
                    System.arraycopy(messageBytesTGS, 0, finalRequestTGS, 2, messageBytesTGS.length);

                    outputTGS.write(finalRequestTGS);
                    outputTGS.flush();
                    System.out.println(" step 3 --> request sent to TGS :)");

                    // -------- read response from TGS --------
                    byte[] bufferTGS = new byte[4096];
                    int bytesReadTGS = inTGS.read(bufferTGS);

                    if (bytesReadTGS == -1) {
                        throw new IllegalStateException("TGS closed connection");
                    }

                    // response is Base64-encoded
                    String responseBase64 = new String(bufferTGS, 0, bytesReadTGS, StandardCharsets.UTF_8);
                    byte[] encryptedResponseV = Base64.getDecoder().decode(responseBase64);

                    // decrypt with Kc,tgs (session key from previous step)
                    byte[] decryptedTGSResponse = DES.D(encryptedResponseV, kcTGS.getEncoded());
                    String responseString = new String(decryptedTGSResponse, StandardCharsets.UTF_8);
                    System.out.println("Decrypted TGS Response: " + responseString);

                    // split the fields: Kc,v || IDv || TS4 || Ticket_v
                    String[] parts = responseString.split("\\|\\|");
                    String KcV_Base64 = parts[0];      // session key for client-server communication
                    String TicketV_Base64 = parts[3];  // service ticket to send to server V

                    // decode Kc,v for use in Authenticator
                    byte[] KcV_Bytes = Base64.getDecoder().decode(KcV_Base64);
                    SecretKey kcV = new SecretKeySpec(KcV_Bytes, "DES");

                    // after extracting kcV and TicketV_Base64
                    System.out.println("Extracted Kc,v length: " + KcV_Bytes.length);
                    System.out.println("Ticket_v Base64: " + TicketV_Base64);

// Step 5: request service from V
                    try (Socket socketV = new Socket("localhost", 9000)) { // connect to service V
                        OutputStream outputV = socketV.getOutputStream();

                        // generate Authenticator_c with Kc,v
                        String authenticatorV = "Duaa||" + System.currentTimeMillis();
                        byte[] authEncrypted = DES.E(authenticatorV.getBytes(StandardCharsets.UTF_8), kcV.getEncoded());
                        String authenticatorVBase64 = Base64.getEncoder().encodeToString(authEncrypted);

                        // send Ticket_v || Authenticator_c
                        String requestToV = TicketV_Base64 + "||" + authenticatorVBase64;

                        byte[] requestBytes = requestToV.getBytes(StandardCharsets.UTF_8);
                        byte[] finalRequestV = new byte[requestBytes.length + 2]; // reserve 2 bytes for protocol
                        System.arraycopy(requestBytes, 0, finalRequestV, 2, requestBytes.length);

                        outputV.write(finalRequestV);
                        outputV.flush();

                        System.out.println(" step 5 --> request sent to server V :)");

                    } catch (Exception e) {
                        e.printStackTrace();
                        System.out.println(" fail processing request to service V ");
                    }





                } catch (IOException e) {
                    e.printStackTrace();
                    System.out.println(" fail processing TGS request ");
                }






            } catch (javax.crypto.BadPaddingException | javax.crypto.IllegalBlockSizeException e) {
                System.out.println(" unauthorized user !!! try again :(");
            } catch (Exception e) {
                e.printStackTrace();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    // we need to build the authencater  from the answer that we get
    public String getAuthenticater(SecretKey kcTGS) {
        String Athuentcator = "Duaa||" + System.currentTimeMillis();
        byte[] authen = DES.E(Athuentcator.getBytes(StandardCharsets.UTF_8), kcTGS.getEncoded());
        String authentcaterAsString = Base64.getEncoder().encodeToString(authen);
        return authentcaterAsString;
    }

    // to excute the client class
    public static void main(String[] args) {
        new Client();
    }
}
