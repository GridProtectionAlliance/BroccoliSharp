Option Strict On
Imports BroccoliSharp
Imports System.Net.Sockets

Module Program

    Sub Main()

        Using connection As New BroConnection("bro.yourorg.com:1234")
            ' Establish event handler for received Bro events
            AddHandler connection.ReceivedEvent, AddressOf connection_ReceivedEvent

            ' Register for event "foo"
            connection.RegisterForEvent("foo")

            ' Connect to remote Bro
            connection.Connect()

            Console.WriteLine("Peer class = " + connection.PeerClass)

            ' Create a new event
            Dim bar As New BroEvent("bar")

            bar.AddParameter("Text parameter")
            bar.AddParameter(True)
            bar.AddParameter("192.168.1.1", BroType.IpAddr)
            bar.AddParameter(New BroPort(80, ProtocolType.Tcp))
            bar.AddParameter(2, BroType.Enum, "transport_proto")
            bar.AddParameter(BroTime.Now)

            ' Send the event
            Dim result As Boolean = connection.SendEvent(bar)
            Console.WriteLine("Event ""bar"" {0}", IIf(result, "was sent or queued for later delivery", "failed to send or queue"))

            ' Process any incoming events...
			connection.ProcessInput()
            
			Console.ReadLine()

            ' Unregister from event "foo"
            connection.UnregisterForEvent("foo")
        End Using

    End Sub

    ' Bro event handler
    Sub connection_ReceivedEvent(sender As Object, e As BroEventArgs)

        ' Raised when a new Bro event is received
        Select Case e.EventName
            Case "foo"
                ' Handle foo event
                Console.WriteLine("Received event ""foo"" with {0} parameters at {1}", e.Parameters.Length, e.EventTime)

                For i As Integer = 0 To e.Parameters.Length - 1
                    Console.WriteLine("    Event ""foo"" parameter[{0}] = {1}", i, e.Parameters(i))
                Next
            Case Else
                Console.WriteLine("Received unexpected event ""{0}"".", e.EventName)
        End Select

    End Sub

End Module
