package networkSecurity;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;

public class Server {
	// KTGS الخاص بالسيرفر و ما بكون لل kv
	private static final String KV = "mailserv";
	// بدي احول كلمة السر الى 8 بايت لتناسب الالجورثيم تبعت الديس
	private static final byte[] kv_key = DES.processKey(KV);

	public Server() {
		try {
			ServerSocket serverSocket = new ServerSocket(9000);
			System.out.println(" the server service will start --> ");

			while (true) {
				try {
					Socket clients = serverSocket.accept();

					// we need to read the data from client

					InputStream in = clients.getInputStream();
					byte[] buffer = new byte[4096];
					int Reader = in.read(buffer);

					// if the message is empty continue
					if (Reader <= 0) {
						continue;

					}

					// we need to convert the message and split it
					String data = new String(buffer, 2, Reader-2, StandardCharsets.UTF_8);
					String[] partsOfMessage = data.split("\\|\\|");

					String ticketUsingBase64 = partsOfMessage[0]; // --> ticket Base 64 using kv
					String authenticator = partsOfMessage[1];

					// now we need to get the session key decrypt the ticket using the server key
					String contentOfTheTicket = decryptTheTicket(ticketUsingBase64);
					String[] partOfTheTicket = contentOfTheTicket.split("\\|\\|");
					String sessionKey = partOfTheTicket[0]; // --> get kv
					String userName = partOfTheTicket[1];// -> the user name from the ticket
					String clientIpInTheTicket = partOfTheTicket[2];// --> مطرح ما بخزن الاي بي بالتيكيت

					// to prevent the replay attack
					String realClientIp = clients.getInetAddress().getHostAddress();
					if (!realClientIp.equals(clientIpInTheTicket)) {
						System.out.println(" missmatch ip address ");

						continue;

					}

					// بدي افك تشفير authenticator
					byte[] sessionKeyBytes = Base64.getDecoder().decode(sessionKey);
					byte[] decryptAuthentication = DES.D(Base64.getDecoder().decode(authenticator), sessionKeyBytes);
					String authenticationContent = new String(decryptAuthentication, StandardCharsets.UTF_8);
					String userNameAuth = authenticationContent.split("\\|\\|")[0];

					// المقارنة اذا الاسم يلي في التيكيت هو نفسه يلي موجود في الاوثنتكيتر
					if (userName.equals(userNameAuth)) {
						System.out.println("  welcom :)" + userName);
						clients.getOutputStream().write("success proccess".getBytes());

					}

				} catch (Exception e) {
					e.printStackTrace();

				}

			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	// method to decrypt only ticket ticket
	public String decryptTheTicket(String ticket) {
		try {
			byte[] tickets = Base64.getDecoder().decode(ticket);
			byte[] decryption = DES.D(tickets, kv_key);// decryption using kv
			return new String(decryption, StandardCharsets.UTF_8);

		} catch (Exception e) {
			return null;
		}

	}

	// لاني بدي اشغل السيرفر بعمل اله مين لحاله
	public static void main(String[] args) {
		new Server();

	}

}
