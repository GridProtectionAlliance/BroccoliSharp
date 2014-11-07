//******************************************************************************************************
//  BroTypeExtensions.cs - Gbtc
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

using System;
using System.Collections;

namespace BroccoliSharp
{
    /// <summary>
    /// Defines extension functions for the <see cref="BroType"/> enumeration.
    /// </summary>
    public static class BroTypeExtensions
    {
        /// <summary>
        /// Determines if <see cref="BroType"/> is a value-type (from perspective of BroccoliSharp library not Broccoli API).
        /// </summary>
        /// <param name="type">Bro type to test.</param>
        /// <returns><c>true</c> if Bro <paramref name="type"/> is a value-type; otherwise, <c>false</c>.</returns>
        public static bool IsValueType(this BroType type)
        {
            switch (type)
            {
                case BroType.Bool:
                case BroType.Int:
                case BroType.Count:
                case BroType.Counter:
                case BroType.Enum:
                case BroType.Double:
                case BroType.Time:
                case BroType.Interval:
                case BroType.Port:      // Value-type BroPort structure wraps bro_port structure
                case BroType.IpAddr:    // Value-type BroAddress structure wraps bro_addr structure
                case BroType.Subnet:    // Value-type BroSubnet structure wraps bro_subnet structure
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Determines if <see cref="BroType"/> is a reference-type (from perspective of BroccoliSharp library not Broccoli API).
        /// </summary>
        /// <param name="type">Bro type to test.</param>
        /// <returns><c>true</c> if Bro <paramref name="type"/> is a reference-type; otherwise, <c>false</c>.</returns>
        /// <remarks>
        /// Reference types in BroccoliSharp implement <see cref="IDisposable"/>.
        /// </remarks>
        public static bool IsReferenceType(this BroType type)
        {
            switch (type)
            {
                case BroType.String:    // Reference-type BroString class wraps bro_string structure
                case BroType.Table:
                case BroType.List:
                case BroType.Record:
                case BroType.Vector:
                case BroType.Packet:
                case BroType.Set:
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Determines if <see cref="BroType"/> is an opaque reference-type.
        /// </summary>
        /// <param name="type">Bro type to test.</param>
        /// <returns><c>true</c> if Bro <paramref name="type"/> is an opaque reference-type; otherwise, <c>false</c>.</returns>
        public static bool IsOpaqueType(this BroType type)
        {
            return type != BroType.String && type.IsReferenceType();
        }

        /// <summary>
        /// Determines if <see cref="BroType"/> is a currently unsupported type.
        /// </summary>
        /// <param name="type">Bro type to test.</param>
        /// <returns><c>true</c> if Bro <paramref name="type"/> is an unsupported type; otherwise, <c>false</c>.</returns>
        public static bool IsUnsupportedType(this BroType type)
        {
            switch (type)
            {
                case BroType.Pattern:
                case BroType.Timer:
                case BroType.Any:
                case BroType.Union:
                case BroType.Func:
                case BroType.File:
                case BroType.Error:
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Determines if <see cref="BroType"/> is an <see cref="IEnumerable"/> type.
        /// </summary>
        /// <param name="type">Bro type to test.</param>
        /// <returns><c>true</c> if Bro <paramref name="type"/> is an <see cref="IEnumerable"/> type; otherwise, <c>false</c>.</returns>
        public static bool IsEnumerableType(this BroType type)
        {
            switch (type)
            {
                case BroType.Table:
                case BroType.List:
                case BroType.Record:
                case BroType.Vector:
                case BroType.Set:
                    return true;
            }

            return false;
        }
    }
}
