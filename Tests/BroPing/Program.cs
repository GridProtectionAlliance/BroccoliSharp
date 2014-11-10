using System;
using System.Threading;
using BroccoliSharp;

namespace BroPing
{
    class Program
    {
        static int Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("Usage:");
                Console.WriteLine("    BroPing host:port");
                return 1;
            }

            try
            {
                string hostName = args[0];

                Console.WriteLine("Attempting to establish Bro connection to \"{0}\"...", hostName);

                // Create the connection object
                using (BroConnection connection = new BroConnection(hostName))
                {
                    // Register to receive the pong event
                    connection.RegisterForEvent("pong", e =>
                    {
                        BroRecord pongData = e.Parameters[0];
                        DateTime dst_time = pongData["dst_time"];
                        DateTime src_time = pongData["src_time"];

                        Console.WriteLine("pong event from {0}: seq={1}, time={2}/{3} s",
                            hostName,
                            pongData["seq"],
                            (dst_time - src_time).TotalSeconds,
                            (BroTime.Now - src_time).TotalSeconds);
                    });

                    connection.Connect();

                    Console.WriteLine("Bro connection established. Starting ping cycle, press any key to cancel...");

                    BroRecord pingData = new BroRecord();
                    int seq = 0;

                    // Define columns without any initial value
                    pingData.Add("seq", BroType.Count);
                    pingData.Add("src_time", BroType.Time);

                    while (!Console.KeyAvailable)
                    {
                        pingData["seq"] = new BroValue(seq++, BroType.Count);
                        pingData["src_time"] = BroTime.Now;
                        connection.SendEvent("ping", pingData);
                        Thread.Sleep(1000);
                    }
                }

                return 0;
            }
            catch (Exception ex)
            {
                Console.Write("Exception: {0}{1}", ex.Message, Environment.NewLine);
                return 1;
            }
        }
    }
}
