package networkSecurity;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;

public class TicketGrantingServer {

    //Ktgs: shared between the tgs server and the AS server
    private static String KTGS = "tgssecret";
    private static final SecretKey KtgsKey = new SecretKeySpec(DES.processKey(KTGS), "DES");

    // Kv: shared between TGS and the service Server
    private static final String KV = "mailserv";
    private static final SecretKey KvKey = new SecretKeySpec(DES.processKey(KV), "DES");


    //TGS → C : E(Kc,tgs, [Kc,v ‖ IDv ‖ TS4 ‖ Ticket_v])
    public static void main(String[] args) throws Exception {

        ServerSocket tgsSocket = new ServerSocket(8000);
        System.out.println("TGS Server started on port 8000");

        while (true) {

            try (Socket client = tgsSocket.accept()) {

                InputStream in = client.getInputStream();
                OutputStream out = client.getOutputStream();

                String ADc = client.getInetAddress().getHostAddress();

                // هون بستقبل الطلب من الكلاينت كبايتات
                byte[] buffer = new byte[4096];
                int bytesRead = in.read(buffer);

                if (bytesRead <= 2) {
                    throw new IllegalArgumentException("Empty request");
                }

                // بحذف اول بايتين تبعون البروتوكول
                String request =
                        new String(buffer, 2, bytesRead - 2, StandardCharsets.UTF_8);

                System.out.println("Request received from client");

                // بمرر الطلب كامل عشان يتحقق من Ticket_tgs و Authenticator
                // ويرجع response مشفر بـ Kc,tgs
                byte[] response = processRequest(request, ADc);

                // ببعت الريسبونس للكلاينت
                String responseBase64 =
                        Base64.getEncoder().encodeToString(response);

                out.write(responseBase64.getBytes(StandardCharsets.UTF_8));
                out.flush();

                System.out.println("Service ticket sent to client");

            } catch (Exception e) {
                System.out.println("TGS error: " + e.getMessage());
            }
        }
    }


    // In this method im going to do msg(4):TGS → C : E(Kc,tgs, [Kc,v ‖ IDv ‖ TS4 ‖ Ticket_v])
    public static byte[] processRequest(String request, String ADc) {
        // Split request to get  IDv ‖ Ticket_tgs ‖ Authenticator_c
        String[] parts = request.split("\\|\\|");
        if (parts.length < 3) {
            throw new IllegalArgumentException("Malformed request: " + request);
        }
        String IDv = parts[0];
        String ticketTgsBase64 = parts[1];
        String authenticatorBase64 = parts[2];


        //===
        byte[] ticketBytes = Base64.getDecoder().decode(ticketTgsBase64);

        // decrypt Ticket_tgs using KTGS (only AS & TGS know it)

        byte[] decryptedTicket;
        try {
            decryptedTicket = DES.D(ticketBytes, KtgsKey.getEncoded());

        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to decrypt Ticket: " + e.getMessage());
        }

        String ticket = new String(decryptedTicket, StandardCharsets.UTF_8);

        // Ticket: Kc_tgs || IDc || ADc || IDtgs || TS2 || Lifetime2
        String[] ticketParts = ticket.split("\\|\\|");

        String Kc_tgsBase64 = ticketParts[0];
        String IDc = ticketParts[1];
        String ADc_ticket = ticketParts[2];
        String IDtgs = ticketParts[3];
        long TS2 = Long.parseLong(ticketParts[4]);
        long lifetime2 = Long.parseLong(ticketParts[5]);


        //===
        //-Verifying
        //*IDtgs
        if (!IDtgs.equals("tgs_service")) {
            throw new IllegalArgumentException("Wrong TGS identity");
        }

        //*client address
        if (!ADc_ticket.equals(ADc)) {
            throw new IllegalArgumentException("Client address mismatch");
        }

        //*check ticket lifetime
        long now = System.currentTimeMillis();
        if (now > TS2 + lifetime2) {
            throw new IllegalArgumentException("Ticket expired");
        }

        //-Kctgs
        byte[] kcTgsBytes = Base64.getDecoder().decode(Kc_tgsBase64);
        SecretKey Kc_tgs = new SecretKeySpec(kcTgsBytes, "DES");


        //====
        //-Verify Authenticator
        byte[] authBytes = Base64.getDecoder().decode(authenticatorBase64);
        byte[] decryptedAuth;

        try {
            decryptedAuth = DES.D(authBytes, Kc_tgs.getEncoded());
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to decrypt Authenticator: " + e.getMessage());
        }

        String authenticator = new String(decryptedAuth, StandardCharsets.UTF_8);

        //-Authenticator: IDc || TS3
        String[] authParts = authenticator.split("\\|\\|");
        String IDc_auth = authParts[0];
        long TS3 = Long.parseLong(authParts[1]);

        //*check IDc match
        if (!IDc.equals(IDc_auth)) {
            throw new IllegalArgumentException("IDc mismatch");
        }

        // check freshness (replay protection)
        if (Math.abs(now - TS3) > 300000) { // 5 minutes
            throw new SecurityException("Authenticator expired");
        }


        //====
        // TGS → C

        // generate session key between client and service V
        SecretKey Kc_v = generateKcv();

        // timestamp and lifetime for service ticket
        long TS4 = System.currentTimeMillis();
        long lifetime4 = 300000;

        //Ticket
        String ticketVBase64 = generateTicketv(Kc_v, IDc, ADc, IDv, TS4, lifetime4);

        String KcVString = Base64.getEncoder().encodeToString(Kc_v.getEncoded());


        // Kc,v || IDv || TS4 || Ticket_v
        String responseToClient = KcVString + "||" + IDv + "||" + TS4 + "||" + ticketVBase64;

        // encrypt with Kctgs
        byte[] encryptedResponse = DES.E(responseToClient.getBytes(StandardCharsets.UTF_8), Kc_tgs.getEncoded());

        return encryptedResponse;

    }

    private static SecretKey generateKcv() {
        return DES.generateRandomKey();
    }


    //method for generating Ticket_v
// Ticketv = E(Kv, [Kc,v || IDc || ADc || IDv || TS4 || Lifetime4])
    public static String generateTicketv(SecretKey Kc_v, String IDc, String ADc, String IDv, long TS4, long lifetime4) {

        // convert Kc,v to string so we can send it inside the ticket
        String KcVString = Base64.getEncoder().encodeToString(Kc_v.getEncoded());

        //the ticket before encryption
        String ticketV_NotEnc = KcVString + "||" + IDc + "||" + ADc + "||" + IDv + "||" + TS4 + "||" + lifetime4;

        byte[] ticketVBytes = ticketV_NotEnc.getBytes(StandardCharsets.UTF_8);

        // encrypt Ticket using Kv
        byte[] encryptedTicketV = DES.E(ticketVBytes, KvKey.getEncoded());

        // return as Base64 so it can be sent as string
        return Base64.getEncoder().encodeToString(encryptedTicketV);
    }


}

