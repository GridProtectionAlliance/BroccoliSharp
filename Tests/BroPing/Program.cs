using System;
using System.Threading;
using BroccoliSharp;

namespace BroPing
{
    class Program
    {
        private static string s_hostName;

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
                s_hostName = args[0];

                // Create the connection object
                using (BroConnection connection = new BroConnection(s_hostName))
                {
                    // Register to receive the pong event
                    connection.RegisterForEvent("pong", e =>
                    {
                        BroRecord pongData = e.Parameters[0];
                        DateTime dst_time = pongData["dst_time"];
                        DateTime src_time = pongData["src_time"];

                        Console.WriteLine("pong event from {0}: seq={1}, time={2}/{3} s",
                            s_hostName,
                            pongData["seq"],
                            (dst_time - src_time).TotalSeconds,
                            (BroTime.Now - src_time).TotalSeconds);
                    });

                    connection.Connect();

                    Console.WriteLine("Bro connection established. Starting ping cycle, press any key to cancel...");

                    BroRecord pingData = new BroRecord();
                    int seq = 0;

                    pingData.Add(seq, BroType.Count, "seq");
                    pingData.Add(BroTime.Now, "src_time");

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
                Console.Write("Exception: {0}", ex.Message);
                return 1;
            }
        }
    }
}
