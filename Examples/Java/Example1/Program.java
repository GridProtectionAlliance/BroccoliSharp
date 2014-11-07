package Example;

// Imports based on IKVM.NET stubs: http://sourceforge.net/p/ikvm/wiki/Ikvmstub/
import cli.BroccoliSharp.*;
import cli.System.Net.Sockets.*;

public class Program
{
    public static void main(String[] args)
    {
        BroConnection connection = new BroConnection("bro.yourorg.com:1234");

        // Establish event handler for received Bro events
        connection.add_ReceivedEvent(new EventHandler<BroEventArgs>(connection_ReceivedEvent));

        // Register for event "foo"
        connection.RegisterForEvent("foo");

        // Connect to remote Bro
        connection.Connect();

        System.out.println("Peer class = " + connection.get_PeerClass());

        // Create a new event
        BroEvent bar = new BroEvent("bar");

        bar.AddParameter("Text parameter");
        bar.AddParameter(true);
        bar.AddParameter("192.168.1.1", BroType.IpAddr);
        bar.AddParameter(new BroPort(80, ProtocolType.Tcp));
        bar.AddParameter(2, BroType.Enum, "transport_proto");
        bar.AddParameter(BroTime.get_Now());

        // Send the event
        bool result = connection.SendEvent(bar);
        System.out.format("Event \"bar\" %s%n", result ? "was sent or queued for later delivery" : "failed to send or queue");

        // Wait for events to be received
        System.in.read();

        // Unregister from event "foo"
        connection.UnregisterForEvent("foo");
		connection.Dispose();
    }

    // Bro event handler
    static void connection_ReceivedEvent(object sender, BroEventArgs e)
    {
        // Raised when a new Bro event is received
        String eventName = e.get_EventName();
        IBroValue[] parameters = e.get_Parameters();
        
        switch (eventName)
        {
            case "foo":
                // Handle foo event
                System.out.format("Received event \"foo\" with %d parameters at %s%n", parameters.length, e.get_EventTime().ToString());

                for (int i = 0; i < parameters.length; i++)
                    System.out.format("    Event \"foo\" parameter[%d] = %s%n", i, parameters[i].toString());

                break;
            default:
                System.out.format("Received unexpected event \"%s\".%n", eventName);
                break;
        }
    }
}
