//******************************************************************************************************
//  InternalExtensions.cs - Gbtc
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
using System.Net;
using System.Runtime.InteropServices;
#if !DNET45
using System.Net.Sockets;
#endif

namespace BroccoliSharp.Internal
{
    // Defines extension functions for internal use related to Bro structures and types.
    internal static class InternalExtensions
    {
        // Get address bytes of a bro_addr structure
        public static unsafe byte[] GetAddressBytes(this bro_addr address)
        {
            byte[] addressBytes = new byte[16];

            fixed (byte* pAddressBytes = &addressBytes[0])
            {
                for (int i = 0; i < 4; i++)
                {
                    *(uint*)(pAddressBytes + i * sizeof(uint)) = address.addr[i];
                }
            }

            return addressBytes;
        }

        // Determines if one bro_addr structure is equal to another
        public static unsafe bool ValueEquals(this bro_addr address1, bro_addr address2)
        {
            for (int i = 0; i < 4; i++)
            {
                if (address1.addr[i] != address2.addr[i])
                    return false;
            }

            return true;
        }

        // Converts an IPAddress to a bro_addr
        public static unsafe bro_addr ConvertToBroAddr(this IPAddress ipAddress)
        {
            bro_addr broAddress = new bro_addr();

            byte[] addressBytes = ipAddress.MapToIPv6().GetAddressBytes();

            fixed (byte* pAddressBytes = &addressBytes[0])
            {
                for (int i = 0; i < 4; i++)
                {
                    broAddress.addr[i] = *(uint*)(pAddressBytes + i * sizeof(uint));
                }
            }

            return broAddress;
        }

        internal static bool IsInvalid(this IntPtr ptr)
        {
            return ptr == IntPtr.Zero;
        }

        internal static bool IsInvalid(this SafeHandle ptr)
        {
            return ptr.IsInvalid;
        }

#if DNET45
        internal static bool IsIPv4MappedAddress(this IPAddress value)
        {
            return value.IsIPv4MappedToIPv6;
        }
#else
        // The following functionality is new to .NET 4.5 and not available in older versions:

        // Determine if IPv6 based address is mapped to an IPv4 address
        internal static bool IsIPv4MappedAddress(this IPAddress value)
        {
            // If IP address is not IPv6, it cannot be a mapped address
            if (value.AddressFamily != AddressFamily.InterNetworkV6)
                return false;

            ushort[] numbers = value.GetNumbers();

            for (int i = 0; i < 5; i++)
            {
                if (numbers[i] != 0)
                    return false;
            }

            return numbers[5] == ushort.MaxValue;
        }

        // Maps an address to IPv6
        internal static IPAddress MapToIPv6(this IPAddress value)
        {
            // If IP address is already IPv6, just return it
            if (value.AddressFamily == AddressFamily.InterNetworkV6)
                return value;

#pragma warning disable 618
            long address = value.Address; // Address property is obsolete
            ushort[] numbers = new ushort[8];
            byte[] array = new byte[16];
            int index = 0;

            numbers[5] = ushort.MaxValue;
            numbers[6] = (ushort)((address & 65280L) >> 8 | (address & (long)byte.MaxValue) << 8);
            numbers[7] = (ushort)((address & 4278190080L) >> 24 | (address & 16711680L) >> 8);

            for (int i = 0; i < 8; i++)
            {
                array[index++] = (byte)(numbers[i] >> 8 & 255);
                array[index++] = (byte)(numbers[i] & 255);
            }

            return new IPAddress(array, 0U);
        }

        // Maps an address to IPv4
        internal static IPAddress MapToIPv4(this IPAddress value)
        {
            // If IP address is already IPv4, just return it
            if (value.AddressFamily == AddressFamily.InterNetwork)
                return value;

            ushort[] numbers = value.GetNumbers();

            return new IPAddress((long)(((int)numbers[6] & 65280) >> 8 | ((int)numbers[6] & (int)byte.MaxValue) << 8 | (((int)numbers[7] & 65280) >> 8 | ((int)numbers[7] & (int)byte.MaxValue) << 8) << 16));
        }

        // Gets the 16-bit address numbers of an IPv6 address
        private static ushort[] GetNumbers(this IPAddress value)
        {
            byte[] address = value.GetAddressBytes();
            ushort[] numbers = new ushort[8];

            for (int i = 0; i < 8; i++)
            {
                numbers[i] = (ushort)((int)address[i * 2] * 256 + (int)address[i * 2 + 1]);
            }

            return numbers;
        }
#endif
    }
}
