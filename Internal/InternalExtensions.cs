//******************************************************************************************************
//  InternalExtensions.cs - Gbtc
//
//  Copyright © 2014, Grid Protection Alliance.  All Rights Reserved.
//
//  Licensed to the Grid Protection Alliance (GPA) under one or more contributor license agreements. See
//  the NOTICE file distributed with this work for additional information regarding copyright ownership.
//  The GPA licenses this file to you under the Eclipse Public License -v 1.0 (the "License"); you may
//  not use this file except in compliance with the License. You may obtain a copy of the License at:
//
//      http://www.opensource.org/licenses/eclipse-1.0.php
//
//  Unless agreed to in writing, the subject software distributed under the License is distributed on an
//  "AS-IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. Refer to the
//  License for the specific language governing permissions and limitations.
//
//  Code Modification History:
//  ----------------------------------------------------------------------------------------------------
//  10/14/2014 - J. Ritchie Carroll
//       Generated original version of source code.
//
//******************************************************************************************************

using System.Net;

namespace BroccoliSharp.Internal
{
    // Defines extension functions for internal use related to Bro structures and types.
    internal static class InternalExtensions
    {
        // Get address bytes of a bro_addr structure
        public unsafe static byte[] GetAddressBytes(this bro_addr address)
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
        public unsafe static bool ValueEquals(this bro_addr address1, bro_addr address2)
        {
            for (int i = 0; i < 4; i++)
            {
                if (address1.addr[i] != address2.addr[i])
                    return false;
            }

            return true;
        }

        // Converts an IPAddress to a bro_addr
        public unsafe static bro_addr ConvertToBroAddr(this IPAddress ipAddress)
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
    }
}
