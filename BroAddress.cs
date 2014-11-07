//******************************************************************************************************
//  BroAddress.cs - Gbtc
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
//  10/24/2014 - J. Ritchie Carroll
//       Generated original version of source code.
//
//******************************************************************************************************

using System;
using System.Net;
using System.Net.Sockets;
using BroccoliSharp.Internal;

namespace BroccoliSharp
{
    /// <summary>
    /// Represents an immutable Bro IP address. Implicitly castable as an <see cref="IPAddress"/>.
    /// </summary>
    /// <remarks>
    /// Managed wrapper structure for <a href="https://www.bro.org/sphinx/broccoli-api/structbro__addr.html">bro_addr</a> structure.
    /// </remarks>
    public struct BroAddress : IEquatable<BroAddress>
    {
        #region [ Members ]

        // Fields
        private readonly bro_addr m_address;

        #endregion

        #region [ Constructors ]

        /// <summary>
        /// Creates a new <see cref="BroAddress"/> from a host name or IP address string.
        /// </summary>
        /// <param name="hostNameOrAddress">DNS host name or IP address.</param>
        /// <exception cref="ArgumentNullException"><paramref name="hostNameOrAddress"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The length of <paramref name="hostNameOrAddress"/> is greater than 255 characters.</exception>
        /// <exception cref="SocketException">An error is encountered when resolving <paramref name="hostNameOrAddress"/>.</exception>
        /// <exception cref="ArgumentException"><paramref name="hostNameOrAddress"/> is an invalid IP address.</exception>
        public BroAddress(string hostNameOrAddress)
            : this(Dns.GetHostAddresses(hostNameOrAddress)[0])
        {
        }

        /// <summary>
        /// Creates a new <see cref="BroAddress"/> from an existing IP <paramref name="address"/>.
        /// </summary>
        /// <param name="address"><see cref="IPAddress"/> used to initialize <see cref="BroAddress"/>.</param>
        /// <exception cref="ArgumentNullException"><paramref name="address"/> is <c>null</c>.</exception>
        public BroAddress(IPAddress address)
        {
            if ((object)address == null)
                throw new ArgumentNullException("address");

            m_address = address.ConvertToBroAddr();
        }

        // Creates a new Bro IP address from an existing Bro IP address
        internal BroAddress(bro_addr sourceAddress)
        {
            m_address = sourceAddress;
        }

        #endregion

        #region [ Properties ]

        /// <summary>
        /// Gets address bytes, in network order, of this <see cref="BroAddress"/>.
        /// </summary>
        /// <remarks>
        /// Returns bytes of the <c>addr</c> value from the <a href="https://www.bro.org/sphinx/broccoli-api/structbro__addr.html">bro_addr</a> structure.
        /// </remarks>
        public byte[] AddressBytes
        {
            get
            {
                return m_address.GetAddressBytes();
            }
        }

        /// <summary>
        /// Gets flag that determines if this <see cref="BroAddress"/> is based on an IPv4-mapped address.
        /// </summary>
        /// <remarks>
        /// This property returns equivalent value to Broccoli <c>bro_util_is_v4_addr</c> API function.
        /// </remarks>
        public bool IsIPv4MappedAddress
        {
            get
            {
                return ToIPAddress().IsIPv4MappedToIPv6;
            }
        }

        #endregion

        #region [ Methods ]

        /// <summary>
        /// Determines whether the specified <see cref="Object"/> is equal to the current <see cref="BroAddress"/>.
        /// </summary>
        /// <returns>
        /// <c>true</c> if the specified object is equal to the current object; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="obj">The object to compare with the current object. </param>
        public override bool Equals(object obj)
        {
            if (obj is BroAddress)
                return Equals((BroAddress)obj);

            return false;
        }

        /// <summary>
        /// Indicates whether the current <see cref="BroAddress"/> is equal to another <see cref="BroAddress"/>.
        /// </summary>
        /// <returns>
        /// <c>true</c> if this <see cref="BroAddress"/> is equal to the <paramref name="other"/> <see cref="BroAddress"/>; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="other">A <see cref="BroAddress"/> to compare with this <see cref="BroAddress"/>.</param>
        public bool Equals(BroAddress other)
        {
            // Compare address values for Bro IP addresses
            return m_address.ValueEquals(other.m_address);
        }

        /// <summary>
        /// Gets a hash code for this <see cref="BroAddress"/>. 
        /// </summary>
        /// <returns>
        /// A hash code for the current <see cref="BroAddress"/>.
        /// </returns>
        public override int GetHashCode()
        {
            return m_address.GetHashCode();
        }

        /// <summary>
        /// Returns an <see cref="IPAddress"/> representation of this <see cref="BroAddress"/>.
        /// </summary>
        /// <returns><see cref="IPAddress"/> representation of this <see cref="BroAddress"/>.</returns>
        public IPAddress ToIPAddress()
        {
            return new IPAddress(AddressBytes);
        }

        /// <summary>
        /// Returns a string that represents this <see cref="BroAddress"/>.
        /// </summary>
        /// <returns>
        /// A string that represents this <see cref="BroAddress"/>.
        /// </returns>
        public override string ToString()
        {
            if (IsIPv4MappedAddress)
                return ToIPAddress().MapToIPv4().ToString();

            return ToIPAddress().ToString();
        }

        // Get Bro address structure value
        internal bro_addr GetValue()
        {
            return m_address;
        }

        #endregion

        #region [ Operators ]

        #region [ Equality Operators ]

        /// <summary>
        /// Equality operator for <see cref="BroAddress"/>.
        /// </summary>
        /// <param name="left">Left <see cref="BroAddress"/> operand to test for equality.</param>
        /// <param name="right">Right <see cref="BroAddress"/> operand to test for equality.</param>
        /// <returns><c>true</c> if <paramref name="left"/> parameter is equal to <paramref name="right"/> parameter; otherwise, <c>false</c>.</returns>
        public static bool operator ==(BroAddress left, BroAddress right)
        {
            return left.Equals(right);
        }

        /// <summary>
        /// Inequality operator for <see cref="BroAddress"/>.
        /// </summary>
        /// <param name="left">Left <see cref="BroAddress"/> operand to test for inequality.</param>
        /// <param name="right">Right <see cref="BroAddress"/> operand to test for inequality.</param>
        /// <returns><c>true</c> if <paramref name="left"/> parameter is equal to <paramref name="right"/> parameter; otherwise, <c>false</c>.</returns>
        public static bool operator !=(BroAddress left, BroAddress right)
        {
            return !(left == right);
        }

        #endregion

        #region [ Implicit BroAddress <=> IPAddress Conversions ]

        /// <summary>
        /// Implicitly converts <see cref="IPAddress"/> value to a <see cref="BroAddress"/>.
        /// </summary>
        /// <param name="value">An <see cref="IPAddress"/> value.</param>
        /// <returns>A <see cref="BroAddress"/> object.</returns>
        public static implicit operator BroAddress(IPAddress value)
        {
            return new BroAddress(value);
        }

        /// <summary>
        /// Implicitly converts <see cref="BroAddress"/> to a <see cref="IPAddress"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroAddress"/> object.</param>
        /// <returns>An <see cref="IPAddress"/> value.</returns>
        public static implicit operator IPAddress(BroAddress value)
        {
            return value.ToIPAddress();
        }

        #endregion

        #endregion
    }
}
