package networkSecurity;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;

public class AuthenticationServer {
 private static ArrayList<User> users ;
    private static String KTGS= "tgssecret";

    private static final SecretKey Ktgs = new SecretKeySpec(DES.processKey(KTGS), "DES");


    public static void main(String[] args) throws Exception {
        users = new ArrayList<>();
        users.add(new User("Duaa", "1230915"));
        users.add(new User("Batoul", "1232541"));
        users.add(new User("Mamoun", "789456"));
        users.add(new User("Ahmed", "123789"));

        ServerSocket serverSocket = new ServerSocket(7000);
        System.out.println("AS started");

        Socket client = serverSocket.accept();
        System.out.println("Client connected");

        InputStream in = client.getInputStream();
        OutputStream out = client.getOutputStream();

        String ADc = client.getInetAddress().getHostAddress();

        try {
            // Take bytes from client and turn them into a String
            byte[] buffer = new byte[1024];
            int bytesRead = in.read(buffer);
            if (bytesRead <= 2) {
                throw new IllegalArgumentException("Invalid request from client");
            }

            String message = new String(buffer, 2, bytesRead - 2, "UTF-8"); // skip first two protocol bytes

            // Process request and get encrypted response
            byte[] responseBytes = processRequest(message, ADc);

            // Encode response as Base64 for safe transmission
            String response = Base64.getEncoder().encodeToString(responseBytes);

            // Send response to client
            out.write(response.getBytes("UTF-8"));
            out.flush();

            System.out.println("Response sent to client");

        } catch (Exception ex) {
            System.out.println("Authentication failed: " + ex.getMessage());
        } finally {
            client.close();
            serverSocket.close();
        }
    }



    //Addition helper Methods:


    // In this method im going to do msg(2):  AS → C : E(Kc, [Kc,tgs ‖ IDtgs ‖ TS2 ‖ Lifetime2 ‖ Tickettgs]).
    public static byte[] processRequest(String request, String ADc) {
        // Split request to get IDC || IDtgs || TS1
        String[] parts = request.split("\\|\\|");
        if (parts.length < 3) {
            throw new IllegalArgumentException("Malformed request: " + request);
        }
        String IDC = parts[0];
        String IDtgs = parts[1];
        String TS1 = parts[2];

        // -AS verifies the client (using stored password info):
        System.out.println("Verifying client: " + IDC);
        String clientPassword = getClientPassword(IDC);
        if (clientPassword == null) {
            throw new IllegalArgumentException("Unknown client: " + IDC);
        }

        // -Kc (derived from user’s password)
        SecretKey Kc = DES.getKeyFromPassword(clientPassword);

        // -Kc,tgs: session key shared between C and TGS
        SecretKey Kc_tgs = generateKcTgs();
        String Kc_TgsString = Base64.getEncoder().encodeToString(Kc_tgs.getEncoded());

        // -Create Ticket_tgs (Ticket-Granting Ticket): E(Ktgs, [Kc_tgs || IDc || ADc || IDtgs || TS2 || Lifetime2])
        long TS2 = System.currentTimeMillis();
        final long TICKET_LIFETIME = 300000; // 5min

        String ticket_tgsNotEnc = Kc_TgsString + "||" + IDC + "||" + ADc + "||" + IDtgs + "||" + TS2 + "||" + TICKET_LIFETIME;
        byte[] ticket_tgsNotEncBytes = ticket_tgsNotEnc.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedTicketTgs;
        try {
            encryptedTicketTgs = DES.E(ticket_tgsNotEncBytes, Ktgs.getEncoded());
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to encrypt TicketTGS: " + e.getMessage());
        }

        // -AS → C: encrypt with Kc
        String responseString = Kc_TgsString + "||" + IDC + "||" + TS2 + "||" + TICKET_LIFETIME + "||" +
                Base64.getEncoder().encodeToString(encryptedTicketTgs);
        byte[] responseBytes;
        try {
            responseBytes = DES.E(responseString.getBytes(StandardCharsets.UTF_8), Kc.getEncoded());
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to encrypt AS response: " + e.getMessage());
        }

        return responseBytes;
    }




    public static String getClientPassword(String IDC) {
        for (int i = 0; i < users.size(); i++) {
            if (users.get(i).getUsername().equalsIgnoreCase(IDC)) {
                return users.get(i).getPassword();
            }
        }
        return null;
    }



    private static SecretKey generateKcTgs(){
        return DES.generateRandomKey();
    }





}
