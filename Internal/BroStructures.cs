//******************************************************************************************************
//  BroStructures.cs - Gbtc
//
//  Copyright © 2014, Grid Protection Alliance.  All Rights Reserved.
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted
//  provided that the following conditions are met:
//
//  (1) Redistributions of source code must retain the above copyright notice, this list of conditions
//      and the following disclaimer.
//
//  (2) Redistributions in binary form must reproduce the above copyright notice, this list of
//      conditions and the following disclaimer in the documentation and/or other materials provided
//      with the distribution.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
//  FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
//  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
//  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
//  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
//  OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//  Code Modification History:
//  ----------------------------------------------------------------------------------------------------
//  10/14/2014 - J. Ritchie Carroll
//       Generated original version of source code.
//
//******************************************************************************************************

using System;
using System.Runtime.InteropServices;

namespace BroccoliSharp.Internal
{
    // Statistical properties of a given connection
    [StructLayout(LayoutKind.Sequential)]
    internal struct bro_conn_stats
    {
        public int tx_buflen;                   // Number of bytes to process in output buffer
        public int rx_buflen;                   // Number of bytes to process in input buffer
    };

    // Ports in Broccoli do not only consist of a number but also indicate whether they are TCP or UDP
    [StructLayout(LayoutKind.Sequential)]
    internal struct bro_port
    {
        public ulong port_num;                  // Port number in host byte order
        public int port_proto;                  // IPPROTO_xxx
    };

    // IP addresses are 16-bytes in network byte order
    // IPv4 addresses use the standard IPv4-in-IPv6 mapping: 10 bytes off, 2 bytes on, then 4 bytes of the address
    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct bro_addr
    {
        public fixed uint addr[4];              // IP address in network byte order
    }

    // Subnets are a 16-byte address with a prefix width in bits
    [StructLayout(LayoutKind.Sequential)]
    internal struct bro_subnet
    {
        public bro_addr sn_net;                 // IP address in network byte order
        public uint sn_width;                   // Length of prefix to consider
    }

    // BroStrings are used to access string parameters in received events
    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct bro_string
    {
        public uint str_len;                    // String length
        public byte* str_val;                   // String bytes
    };

    // Encapsulation of arguments passed to an event callback, for the compact style of argument passing
    [StructLayout(LayoutKind.Sequential)]
    internal struct bro_ev_arg
    {
        public IntPtr arg_data;                 // Pointer to the actual event argument
        public BroType arg_type;                // A BRO_TYPE_xxx constant
    }

    // Metadata for an event, passed to callbacks of the BroCompactEventFunc prototype
    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct bro_ev_meta
    {
        public IntPtr ev_name;                  // The name of the event
        public double ev_ts;                    // Timestamp of event, taken from BroEvent itself
        public int ev_numargs;                  // How many arguments are passed
        public bro_ev_arg* ev_args;             // Array of BroEvArgs, one for each argument
        public /*const*/ IntPtr ev_start;       // Start pointer to serialized version of currently processed event
        public /*const*/ IntPtr ev_end;         // End pointer to serialized version of currently processed event
    }

    // Unix timestamp
    [StructLayout(LayoutKind.Sequential)]
    internal struct timeval
    {
        public uint tv_sec;                     // Epoch seconds
        public uint tv_usec;                    // Microseconds
    }

    // Generic libpcap per-packet information
    [StructLayout(LayoutKind.Sequential)]
    internal struct pcap_pkthdr
    {
        public timeval ts;                      // Timestamp
        public uint caplen;                     // Length of portion present
        public uint len;                        // Length of packet (off wire)
    }
}