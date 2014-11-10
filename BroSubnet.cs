//******************************************************************************************************
//  BroSubnet.cs - Gbtc
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
    /// Represents an immutable Bro subnet.
    /// </summary>
    /// <remarks>
    /// Managed wrapper structure for <a href="https://www.bro.org/sphinx/broccoli-api/structbro__subnet.html">bro_subnet</a> structure.
    /// </remarks>
    public struct BroSubnet : IEquatable<BroSubnet>
    {
        #region [ Members ]

        // Fields
        private readonly bro_subnet m_subnet;

        #endregion

        #region [ Constructors ]

        /// <summary>
        /// Creates a new <see cref="BroSubnet"/> from a host name or IP address string and <paramref name="width"/>.
        /// </summary>
        /// <param name="hostNameOrAddress">DNS host name or IP address.</param>
        /// <param name="width">Width of IP address to consider.</param>
        /// <exception cref="ArgumentNullException"><paramref name="hostNameOrAddress"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The length of <paramref name="hostNameOrAddress"/> is greater than 255 characters.</exception>
        /// <exception cref="SocketException">An error is encountered when resolving <paramref name="hostNameOrAddress"/>.</exception>
        /// <exception cref="ArgumentException"><paramref name="hostNameOrAddress"/> is an invalid IP address.</exception>
        public BroSubnet(string hostNameOrAddress, uint width)
            : this(Dns.GetHostAddresses(hostNameOrAddress)[0], width)
        {
        }

        /// <summary>
        /// Creates a new <see cref="BroSubnet"/> from existing IP <paramref name="address"/> and <paramref name="width"/>.
        /// </summary>
        /// <param name="address"><see cref="BroAddress"/> of subnet.</param>
        /// <param name="width">Width of <paramref name="address"/> to consider.</param>
        /// <exception cref="ArgumentNullException"><paramref name="address"/> is <c>null</c>.</exception>
        public BroSubnet(IPAddress address, uint width)
        {
            if ((object)address == null)
                throw new ArgumentNullException("address");

            m_subnet.sn_net = address.ConvertToBroAddr();
            m_subnet.sn_width = width;
        }

        /// <summary>
        /// Creates a new <see cref="BroSubnet"/> from existing Bro <paramref name="address"/> and <paramref name="width"/>.
        /// </summary>
        /// <param name="address"><see cref="BroAddress"/> of subnet.</param>
        /// <param name="width">Width of <paramref name="address"/> to consider.</param>
        /// <exception cref="ArgumentNullException"><paramref name="address"/> is <c>null</c>.</exception>
        public BroSubnet(BroAddress address, uint width)
        {
            if ((object)address == null)
                throw new ArgumentNullException("address");

            m_subnet.sn_net = address.GetValue();
            m_subnet.sn_width = width;
        }

        // Creates a new Bro subnet from an existing Bro subnet
        internal BroSubnet(bro_subnet sourceSubnet)
        {
            m_subnet = sourceSubnet;
        }

        #endregion

        #region [ Properties ]

        /// <summary>
        /// Gets address bytes, in network order, of this <see cref="BroSubnet"/>.
        /// </summary>
        /// <remarks>
        /// Returns bytes of the <c>sn_net</c> value from the <a href="https://www.bro.org/sphinx/broccoli-api/structbro__subnet.html">bro_subnet</a> structure.
        /// </remarks>
        public byte[] AddressBytes
        {
            get
            {
                return m_subnet.sn_net.GetAddressBytes();
            }
        }

        /// <summary>
        /// Gets width of IP address to consider for this <see cref="BroSubnet"/>.
        /// </summary>
        /// <remarks>
        /// Returns the <c>sn_width</c> value from the <a href="https://www.bro.org/sphinx/broccoli-api/structbro__subnet.html">bro_subnet</a> structure.
        /// </remarks>
        public uint Width
        {
            get
            {
                return m_subnet.sn_width;
            }
        }

        /// <summary>
        /// Gets flag that determines if this <see cref="BroSubnet"/> is based on an IPv4-mapped address.
        /// </summary>
        /// <remarks>
        /// This property returns equivalent value to Broccoli <c>bro_util_is_v4_addr</c> API function.
        /// </remarks>
        public bool IsIPv4MappedAddress
        {
            get
            {
                // Using internal extension function instead of directly calling the
                // IsIPv4MappedToIPv6 property since this is only in .NET 4.5:
                return ToIPAddress().IsIPv4MappedAddress();
            }
        }

        #endregion

        #region [ Methods ]

        /// <summary>
        /// Determines whether the specified <see cref="Object"/> is equal to the current <see cref="BroSubnet"/>.
        /// </summary>
        /// <returns>
        /// <c>true</c> if the specified object is equal to the current object; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="obj">The object to compare with the current object. </param>
        public override bool Equals(object obj)
        {
            if (obj is BroSubnet)
                return Equals((BroSubnet)obj);

            return false;
        }

        /// <summary>
        /// Indicates whether the current <see cref="BroSubnet"/> is equal to another <see cref="BroSubnet"/>.
        /// </summary>
        /// <returns>
        /// <c>true</c> if this <see cref="BroSubnet"/> is equal to the <paramref name="other"/> <see cref="BroSubnet"/>; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="other">A <see cref="BroSubnet"/> to compare with this <see cref="BroSubnet"/>.</param>
        public bool Equals(BroSubnet other)
        {
            // Compare widths
            if (m_subnet.sn_width != other.m_subnet.sn_width)
                return false;

            // Compare address values for IP addresses
            return m_subnet.sn_net.ValueEquals(other.m_subnet.sn_net);
        }

        /// <summary>
        /// Gets a hash code for this <see cref="BroSubnet"/>. 
        /// </summary>
        /// <returns>
        /// A hash code for the current <see cref="BroSubnet"/>.
        /// </returns>
        public override int GetHashCode()
        {
            return m_subnet.GetHashCode();
        }

        /// <summary>
        /// Returns an <see cref="IPAddress"/> representation of this <see cref="BroSubnet"/>.
        /// </summary>
        /// <returns><see cref="IPAddress"/> representation of this <see cref="BroSubnet"/>.</returns>
        public IPAddress ToIPAddress()
        {
            return new IPAddress(AddressBytes);
        }

        /// <summary>
        /// Returns a string that represents this <see cref="BroSubnet"/>.
        /// </summary>
        /// <returns>
        /// A string that represents this <see cref="BroSubnet"/>.
        /// </returns>
        public override string ToString()
        {
            if (IsIPv4MappedAddress)
                return string.Format("{0}/{1}", ToIPAddress().MapToIPv4(), m_subnet.sn_width);

            return string.Format("{0}/{1}", ToIPAddress(), m_subnet.sn_width);
        }

        // Get Bro subnet structure value
        internal bro_subnet GetValue()
        {
            return m_subnet;
        }

        #endregion

        #region [ Operators ]

        #region [ Equality Operators ]

        /// <summary>
        /// Equality operator for <see cref="BroSubnet"/>.
        /// </summary>
        /// <param name="left">Left <see cref="BroSubnet"/> operand to test for equality.</param>
        /// <param name="right">Right <see cref="BroSubnet"/> operand to test for equality.</param>
        /// <returns><c>true</c> if <paramref name="left"/> parameter is equal to <paramref name="right"/> parameter; otherwise, <c>false</c>.</returns>
        public static bool operator ==(BroSubnet left, BroSubnet right)
        {
            return left.Equals(right);
        }

        /// <summary>
        /// Inequality operator for <see cref="BroSubnet"/>.
        /// </summary>
        /// <param name="left">Left <see cref="BroSubnet"/> operand to test for inequality.</param>
        /// <param name="right">Right <see cref="BroSubnet"/> operand to test for inequality.</param>
        /// <returns><c>true</c> if <paramref name="left"/> parameter is equal to <paramref name="right"/> parameter; otherwise, <c>false</c>.</returns>
        public static bool operator !=(BroSubnet left, BroSubnet right)
        {
            return !(left == right);
        }

        #endregion

        #region [ Implicit BroSubnet => BroAddress Conversion ]

        /// <summary>
        /// Implicitly converts address of <see cref="BroSubnet"/> object to a <see cref="BroAddress"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroSubnet"/> object.</param>
        /// <returns>A <see cref="BroAddress"/> object.</returns>
        public static implicit operator BroAddress(BroSubnet value)
        {
            return new BroAddress(value.GetValue().sn_net);
        }

        #endregion

        #endregion
    }
}
