using System;
using System.Collections;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using static System.IO.Stream;


namespace Examples.System.Net
{

    public class SslTcpClient
    {
        private static Socket ConnectSocket()
        {

            Socket socket = null;
            IPHostEntry hostEntry = null;

            // Get host related information.


            // Loop through the AddressList to obtain the supported AddressFamily. This is to avoid
            // an exception that occurs when the host IP Address is not compatible with the address family
            // (typical in the IPv6 case).
            IPEndPoint ipe = new IPEndPoint(771860672, 443);
            ///IPEndPoint ipe = new IPEndPoint(2080483520, 3333);

            Socket tempSocket =
                   new Socket(ipe.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            tempSocket.Connect(ipe);



            if (tempSocket.Connected)
            {
                socket = tempSocket;

            }

            return socket;
        }

        private static Hashtable certificateErrors = new Hashtable();

        // The following method is invoked by the RemoteCertificateValidationDelegate.
        public static bool ValidateServerCertificate(
              object sender,
              X509Certificate certificate,
              X509Chain chain,
              SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

            // Do not allow this client to communicate with unauthenticated servers.
            return false;
        }
        public static void RunClient(string machineName, string serverName)
        {
            using (Socket socket = ConnectSocket())
            {
                // Create a TCP/IP client socket.
                // machineName is the host running the server application.
                //TcpClient client = new TcpClient(machineName, 443);
                Console.WriteLine("Client connected.");

                NetworkStream client;
                client = new NetworkStream(socket);

                // Create an SSL stream that will close the client's stream.
                SslStream sslStream = new SslStream(
                    client,
                    false,
                    new RemoteCertificateValidationCallback(ValidateServerCertificate),
                    null
                    );
                // The server name must match the name on the server certificate.
                try
                {
                    sslStream.AuthenticateAsClient(serverName);  //handshake
                }
                catch (AuthenticationException e)
                {
                    Console.WriteLine("Exception: {0}", e.Message);
                    if (e.InnerException != null)
                    {
                        Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                    }
                    Console.WriteLine("Authentication failed - closing the connection.");
                    client.Close();
                    return;
                }
                // Encode a test message into a byte array.
                // Signal the end of the message using the "<EOF>".
                byte[] messsage = Encoding.UTF8.GetBytes("Hello from the client.<EOF>");
                // Send hello message to the server.
                sslStream.Write(messsage);
                sslStream.Flush();
                // Read message from the server.
                string serverMessage = ReadMessage(sslStream);
                Console.WriteLine("Server says: {0}", serverMessage);
                // Close the client connection.
                client.Close();
                Console.WriteLine("Client closed.");
            }
            return;
        }

        static string ReadMessage(SslStream sslStream)
        {
            // Read the  message sent by the server.
            // The end of the message is signaled using the
            // "<EOF>" marker.
            byte[] buffer = new byte[2048];
            StringBuilder messageData = new StringBuilder();
            int bytes = -1;
            do
            {
                bytes = sslStream.Read(buffer, 0, buffer.Length);

                // Use Decoder class to convert from bytes to UTF8
                // in case a character spans two buffers.
                Decoder decoder = Encoding.UTF8.GetDecoder();
                char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
                decoder.GetChars(buffer, 0, bytes, chars, 0);
                messageData.Append(chars);
                // Check for EOF.
                if (messageData.ToString().IndexOf("<EOF>") != -1)
                {
                    break;
                }
            } while (bytes != 0);

            return messageData.ToString();
        }
        private static void DisplayUsage()
        {
            Console.WriteLine("To start the client specify:");
            Console.WriteLine("clientSync machineName [serverName]");
            Environment.Exit(1);
        }
        public static int Main(string[] args)
        {
            string serverCertificateName = "ASN1";
            string machineName = "esspriff";
            /*if (args == null || args.Length < 1)
            {
                DisplayUsage();
            }*/
            // User can specify the machine name and server name.
            // Server name must match the name on the server's certificate.
            //machineName = args[0];
            /*if (args.Length < 2)
            {
                serverCertificateName = machineName;
            }
            else
            {
                serverCertificateName = args[1];
            }*/
            SslTcpClient.RunClient(machineName, serverCertificateName);
            return 0;
        }
    }
}