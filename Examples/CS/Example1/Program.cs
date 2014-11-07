using System;
using System.Net.Sockets;
using BroccoliSharp;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            using (BroConnection connection = new BroConnection("bro.yourorg.com:1234"))
            {
                // Establish event handler for received Bro events
                connection.ReceivedEvent += connection_ReceivedEvent;

                // Register for event "foo"
                connection.RegisterForEvent("foo");

                // Connect to remote Bro
                connection.Connect();

                Console.WriteLine("Peer class = " + connection.PeerClass);

                // Create a new event
                BroEvent bar = new BroEvent("bar");

                bar.AddParameter("Text parameter");
                bar.AddParameter(true);
                bar.AddParameter("192.168.1.1", BroType.IpAddr);
                bar.AddParameter(new BroPort(80, ProtocolType.Tcp));
                bar.AddParameter(2, BroType.Enum, "transport_proto");
                bar.AddParameter(BroTime.Now);

                // Send the event
                bool result = connection.SendEvent(bar);
                Console.WriteLine("Event \"bar\" {0}", result ? "was sent or queued for later delivery" : "failed to send or queue");

                // Wait for events to be received
                Console.ReadLine();

                // Unregister from event "foo"
                connection.UnregisterForEvent("foo");
            }
        }

        // Bro event handler
        static void connection_ReceivedEvent(object sender, BroEventArgs e)
        {
            // Raised when a new Bro event is received
            switch (e.EventName)
            {
                case "foo":
                    // Handle foo event
                    Console.WriteLine("Received event \"foo\" with {0} parameters at {1}", e.Parameters.Length, e.EventTime);

                    for (int i = 0; i < e.Parameters.Length; i++)
                        Console.WriteLine("    Event \"foo\" parameter[{0}] = {1}", i, e.Parameters[i]);

                    break;
                default:
                    Console.WriteLine("Received unexpected event \"{0}\".", e.EventName);
                    break;
            }
        }
    }
}
