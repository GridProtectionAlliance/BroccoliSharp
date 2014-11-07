//******************************************************************************************************
//  BroTypes.cs - Gbtc
//
//  Copyright © 2014, Grid Protection Alliance.  All Rights Reserved.
//
//  Licensed to the Grid Protection Alliance (GPA) under one or more contributor license agreements. See
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

namespace BroccoliSharp
{
    /// <summary>
    /// Bro value type enumeration.
    /// </summary>
    /// <remarks>
    /// See <a href="https://www.bro.org/sphinx/broccoli-api/broccoli_8h.html">Macros</a> in <c>broccoli.h</c> file.
    /// </remarks>
    public enum BroType
    {
        /// <summary>
        /// Unknown type. <c>BRO_TYPE_UNKNOWN</c>
        /// </summary>
        Unknown = 0,
        /// <summary>
        /// Boolean type, <see cref="int"/> value-type. <c>BRO_TYPE_BOOL</c>
        /// </summary>
        Bool = 1,
        /// <summary>
        /// Integer type, <see cref="ulong"/> value-type. <c>BRO_TYPE_INT</c>
        /// </summary>
        Int = 2,
        /// <summary>
        /// Count type, <see cref="ulong"/> value-type. <c>BRO_TYPE_COUNT</c>
        /// </summary>
        Count = 3,
        /// <summary>
        /// Counter type, <see cref="ulong"/> value-type. <c>BRO_TYPE_COUNTER</c>
        /// </summary>
        Counter = 4,
        /// <summary>
        /// Double type, <see cref="double"/> value-type. <c>BRO_TYPE_DOUBLE</c>
        /// </summary>
        Double = 5,
        /// <summary>
        /// Time type, <see cref="BroTime"/> value-type. <c>BRO_TYPE_TIME</c>
        /// </summary>
        Time = 6,
        /// <summary>
        /// Interval type, <see cref="double"/> value-type. <c>BRO_TYPE_INTERVAL</c>
        /// </summary>
        Interval = 7,
        /// <summary>
        /// String type, <see cref="BroString"/> reference-type. <c>BRO_TYPE_STRING</c>
        /// </summary>
        String = 8,
        /// <summary>
        /// Patten type (currently unsupported in Bro). <c>BRO_TYPE_PATTERN</c>
        /// </summary>
        Pattern = 9,    // Scripts support this, but Bro values do not
        /// <summary>
        /// Enumeration type, <see cref="ulong"/> value-type. <c>BRO_TYPE_ENUM</c>
        /// </summary>
        Enum = 10,
        /// <summary>
        /// Timer type (currently unsupported in Bro). <c>BRO_TYPE_TIMER</c>
        /// </summary>
        Timer = 11,
        /// <summary>
        /// Port type, <see cref="BroPort"/> value-type. <c>BRO_TYPE_PORT</c>
        /// </summary>
        Port = 12,
        /// <summary>
        /// IP address type, <see cref="BroAddress"/> value-type. <c>BRO_TYPE_IPADDR</c>
        /// </summary>
        IpAddr = 13,
        /// <summary>
        /// Subnet type, <see cref="BroSubnet"/> value-type. <c>BRO_TYPE_SUBNET</c>
        /// </summary>
        Subnet = 14,
        /// <summary>
        /// Any type (currently unsupported in Bro). <c>BRO_TYPE_ANY</c>
        /// </summary>
        Any = 15,
        /// <summary>
        /// Table type, <see cref="BroTable"/> reference-type. <c>BRO_TYPE_TABLE</c>
        /// </summary>
        Table = 16,
        /// <summary>
        /// Union type (current unsupported in Bro). <c>BRO_TYPE_UNION</c>
        /// </summary>
        Union = 17,
        /// <summary>
        /// Record type, <see cref="BroRecord"/> reference-type. <c>BRO_TYPE_RECORD</c>
        /// </summary>
        Record = 18,
        /// <summary>
        /// List type (used to represent BroRecord based composite BroTable key). <c>BRO_TYPE_LIST</c>
        /// </summary>
        List = 19,      // Mechanically represents a BroType.Record, not its own type
        /// <summary>
        /// Function type (currently unsupported in Bro). <c>BRO_TYPE_FUNC</c>
        /// </summary>
        Func = 20,
        /// <summary>
        /// File type (currently unsupported in Bro). <c>BRO_TYPE_FILE</c>
        /// </summary>
        File = 21,
        /// <summary>
        /// Vector type, <see cref="BroVector"/> reference-type. <c>BRO_TYPE_VECTOR</c>
        /// </summary>
        Vector = 22,
        /// <summary>
        /// Error type (currently unsupported in Bro). <c>BRO_TYPE_ERROR</c>
        /// </summary>
        Error = 23,
#if BRO_PCAP_SUPPORT
        /// <summary>
        /// Packet type, <see cref="BroPacket"/> reference-type. <c>BRO_TYPE_PACKET</c>
        /// </summary>
#else
        /// <summary>
        /// Packet type (this build does not include PCAP support). <c>BRO_TYPE_PACKET</c>
        /// </summary>
#endif
        Packet = 24,    // CAUTION -- for Broccoli use, not defined in Bro!
        /// <summary>
        /// Set type, <see cref="BroSet"/> reference-type. <c>BRO_TYPE_SET</c>
        /// </summary>
        Set = 25,       // CAUTION -- for Broccoli use, not defined in Bro!

        //Max = 26      // Broccoli defines BRO_TYPE_MAX to represent maximum value used for type validation - not a type
    }
}