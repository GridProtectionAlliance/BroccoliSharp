//******************************************************************************************************
//  BroPort.cs - Gbtc
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
using System.Net.Sockets;
using BroccoliSharp.Internal;

namespace BroccoliSharp
{
    /// <summary>
    /// Represents an immutable Bro port and protocol type.
    /// </summary>
    /// <remarks>
    /// Managed wrapper structure for <a href="https://www.bro.org/sphinx/broccoli-api/structbro__port.html">bro_port</a> structure.
    /// </remarks>
    public struct BroPort : IEquatable<BroPort>
    {
        #region [ Members ]

        // Fields
        private readonly bro_port m_port;

        #endregion

        #region [ Constructors ]

        /// <summary>
        /// Creates a new <see cref="BroPort"/> for the specified port <paramref name="number"/> and integer <paramref name="protocolType"/>.
        /// </summary>
        /// <param name="number">Port number.</param>
        /// <param name="protocolType">Protocol type.</param>
        public BroPort(ulong number, int protocolType)
        {
            m_port.port_num = number;
            m_port.port_proto = protocolType;
        }

        /// <summary>
        /// Creates a new <see cref="BroPort"/> for the specified port <paramref name="number"/> and <paramref name="protocolType"/> enumeration value.
        /// </summary>
        /// <param name="number">Port number.</param>
        /// <param name="protocolType">Protocol type.</param>
        public BroPort(ulong number, ProtocolType protocolType)
        {
            m_port.port_num = number;
            m_port.port_proto = (int)protocolType;
        }

        /// <summary>
        /// Creates a new <see cref="BroPort"/> for the specified port <paramref name="number"/> and <paramref name="protocol"/> string.
        /// </summary>
        /// <param name="number">Port number.</param>
        /// <param name="protocol">String representation of protocol type.</param>
        /// <exception cref="ArgumentException"><paramref name="protocol"/> can be parsed as a <see cref="System.Net.Sockets.ProtocolType"/> enumerated value.</exception>
        public BroPort(ulong number, string protocol)
        {
            ProtocolType protocolType;

            if (Enum.TryParse(protocol, true, out protocolType))
            {
                m_port.port_num = number;
                m_port.port_proto = (int)protocolType;
            }
            else
            {
                throw new ArgumentException("Not a valid protocol type.", "protocol");
            }
        }

        // Creates a new Bro port from an existing Bro port
        internal BroPort(bro_port sourcePort)
        {
            m_port = sourcePort;
        }

        #endregion

        #region [ Properties ]

        /// <summary>
        /// Gets the port number of this <see cref="BroPort"/>.
        /// </summary>
        /// <remarks>
        /// Returns the <c>port_num</c> value from the <a href="https://www.bro.org/sphinx/broccoli-api/structbro__port.html">bro_port</a> structure.
        /// </remarks>
        public ulong Number
        {
            get
            {
                return m_port.port_num;
            }
        }

        /// <summary>
        /// Gets the <see cref="System.Net.Sockets.ProtocolType"/> of this <see cref="BroPort"/>.
        /// </summary>
        /// <remarks>
        /// Returns the <c>port_proto</c> value as a <see cref="System.Net.Sockets.ProtocolType"/> enumeration value from the <a href="https://www.bro.org/sphinx/broccoli-api/structbro__port.html">bro_port</a> structure.
        /// </remarks>
        public ProtocolType ProtocolType
        {
            get
            {
                if (Enum.IsDefined(typeof(ProtocolType), m_port.port_proto))
                    return (ProtocolType)m_port.port_proto;

                return ProtocolType.Unknown;
            }
        }

        /// <summary>
        /// Gets raw protocol type number.
        /// </summary>
        /// <remarks>
        /// Property exists to return actual protocol type integer in rare case that there is no
        /// corresponding <see cref="System.Net.Sockets.ProtocolType"/> enumeration.
        /// </remarks>
        /// <remarks>
        /// Returns the <c>port_proto</c> value from the <a href="https://www.bro.org/sphinx/broccoli-api/structbro__port.html">bro_port</a> structure.
        /// </remarks>
        public int RawProtocolType
        {
            get
            {
                return m_port.port_proto;
            }
        }

        #endregion

        #region [ Methods ]

        /// <summary>
        /// Determines whether the specified <see cref="Object"/> is equal to the current <see cref="BroPort"/>.
        /// </summary>
        /// <returns>
        /// <c>true</c> if the specified object is equal to the current object; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="obj">The object to compare with the current object. </param>
        public override bool Equals(object obj)
        {
            if (obj is BroPort)
                return Equals((BroPort)obj);

            return false;
        }

        /// <summary>
        /// Indicates whether the current <see cref="BroPort"/> is equal to another <see cref="BroPort"/>.
        /// </summary>
        /// <returns>
        /// <c>true</c> if this <see cref="BroPort"/> is equal to the <paramref name="other"/> <see cref="BroPort"/>; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="other">A <see cref="BroPort"/> to compare with this <see cref="BroPort"/>.</param>
        public bool Equals(BroPort other)
        {
            // Compare port numbers
            if (m_port.port_num != other.m_port.port_num)
                return false;

            // Compare protocol types
            if (m_port.port_proto != other.m_port.port_proto)
                return false;

            return true;
        }

        /// <summary>
        /// Gets a hash code for this <see cref="BroPort"/>. 
        /// </summary>
        /// <returns>
        /// A hash code for the current <see cref="BroPort"/>.
        /// </returns>
        public override int GetHashCode()
        {
            return m_port.GetHashCode();
        }

        /// <summary>
        /// Returns a string that represents this <see cref="BroPort"/>.
        /// </summary>
        /// <returns>
        /// A string that represents this <see cref="BroPort"/>.
        /// </returns>
        public override string ToString()
        {
            if (ProtocolType != ProtocolType.Unknown)
                return string.Format("[{0}/{1}]", m_port.port_num, ProtocolType.ToString().ToLowerInvariant());

            return string.Format("[{0}/iproto({1})]", m_port.port_num, RawProtocolType);
        }

        // Get Bro port structure value
        internal bro_port GetValue()
        {
            return m_port;
        }

        #endregion

        #region [ Operators ]

        #region [ Equality Operators ]

        /// <summary>
        /// Equality operator for <see cref="BroPort"/>.
        /// </summary>
        /// <param name="left">Left <see cref="BroPort"/> operand to test for equality.</param>
        /// <param name="right">Right <see cref="BroPort"/> operand to test for equality.</param>
        /// <returns><c>true</c> if <paramref name="left"/> parameter is equal to <paramref name="right"/> parameter; otherwise, <c>false</c>.</returns>
        public static bool operator ==(BroPort left, BroPort right)
        {
            return left.Equals(right);
        }

        /// <summary>
        /// Inequality operator for <see cref="BroPort"/>.
        /// </summary>
        /// <param name="left">Left <see cref="BroPort"/> operand to test for inequality.</param>
        /// <param name="right">Right <see cref="BroPort"/> operand to test for inequality.</param>
        /// <returns><c>true</c> if <paramref name="left"/> parameter is equal to <paramref name="right"/> parameter; otherwise, <c>false</c>.</returns>
        public static bool operator !=(BroPort left, BroPort right)
        {
            return !(left == right);
        }

        #endregion

        #region [ Implicit BroPort => ulong Conversion ]

        /// <summary>
        /// Implicitly converts <see cref="BroPort"/> object to a <see cref="ulong"/> based on port number.
        /// </summary>
        /// <param name="value">A <see cref="BroPort"/> object.</param>
        /// <returns>A <see cref="ulong"/> value.</returns>
        public static implicit operator ulong(BroPort value)
        {
            return value.GetValue().port_num;
        }

        #endregion

        #endregion
    }
}
