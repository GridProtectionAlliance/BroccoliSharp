//******************************************************************************************************
//  BroField.cs - Gbtc
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
//  10/29/2014 - J. Ritchie Carroll
//       Generated original version of source code.
//
//******************************************************************************************************

using System;
using System.Net;

namespace BroccoliSharp
{
    /// <summary>
    /// Represents a <see cref="BroValue"/> with a field name as a column in a <see cref="BroRecord"/>. Implicitly
    /// castable to all <see cref="BroType"/> wrapper classes, structures and applicable .NET data types.
    /// </summary>
    /// <remarks>
    /// <see cref="BroField.Name"/> can be an empty string when source <see cref="BroRecord"/> represents a <see cref="BroType.List">BroType.List</see>.
    /// </remarks>
    public class BroField : BroValue, IEquatable<BroField>
    {
        #region [ Members ]

        // Fields
        private string m_name;

        #endregion

        #region [ Constructors ]

        /// <summary>
        /// Creates a new <see cref="BroField"/> from the provided <paramref name="value"/>, <paramref name="type"/> and specified field <paramref name="name"/>.
        /// </summary>
        /// <param name="value">Value of <see cref="BroValue"/>.</param>
        /// <param name="type"><see cref="BroType"/> of <see cref="BroValue"/>.</param>
        /// <param name="name">The field name for the <see cref="BroField"/>, can be empty string for <see cref="BroType.List">BroType.List</see> source.</param>
        /// <param name="typeName">Optional name of specialized type of <paramref name="value"/>.</param>
        /// <remarks>
        /// Field <paramref name="name"/> is optional when using field with a <see cref="BroRecord"/> implemented as a <see cref="BroType.List">BroType.List</see>.
        /// </remarks>
        /// <exception cref="NotSupportedException">Type is currently unsupported in Bro.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="name"/> is <c>null</c>.</exception>
        public BroField(object value, BroType type, string name = "", string typeName = null)
            : base(value, type, typeName)
        {
            if ((object)name == null)
                throw new ArgumentNullException("name");

            m_name = name;
        }

        /// <summary>
        /// Creates a new <see cref="BroField"/> from the provided <paramref name="value"/> and specified field <paramref name="name"/>.
        /// </summary>
        /// <param name="value"><see cref="BroValue"/> for <see cref="BroField"/> to be based upon.</param>
        /// <param name="name">The field name for the <see cref="BroField"/>, can be empty string for <see cref="BroType.List">BroType.List</see> source.</param>
        /// <remarks>
        /// Field <paramref name="name"/> is optional when using field with a <see cref="BroRecord"/> implemented as a <see cref="BroType.List">BroType.List</see>.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="name"/> is <c>null</c>.</exception>
        public BroField(BroValue value, string name = "")
            : this(
                (object)value == null ? null : value.Value,
                (object)value == null ? BroType.Unknown : value.Type, name,
                (object)value == null ? null : value.TypeName)
        {
        }

        #endregion

        #region [ Properties ]

        /// <summary>
        /// Gets or sets the name of this <see cref="BroField"/>.
        /// </summary>
        public string Name
        {
            get
            {
                return m_name;
            }
            set
            {
                m_name = value;
            }
        }

        #endregion

        #region [ Methods ]

        /// <summary>
        /// Determines whether the specified <see cref="Object"/> is equal to the current <see cref="BroField"/>.
        /// </summary>
        /// <returns>
        /// <c>true</c> if the specified object is equal to the current object; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="obj">The object to compare with the current object. </param>
        public override bool Equals(object obj)
        {
            BroField field = obj as BroField;

            if ((object)field != null)
                return Equals(field);

            BroValue value = obj as BroValue;

            return (object)value != null && Equals(value);
        }

        /// <summary>
        /// Indicates whether the current <see cref="BroField"/> is equal to another <see cref="BroField"/> of the same <see cref="BroType"/>.
        /// </summary>
        /// <returns>
        /// <c>true</c> if this <see cref="BroField"/> is equal to the <paramref name="other"/> <see cref="BroField"/>; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="other">A <see cref="BroField"/> to compare with this <see cref="BroField"/>.</param>
        public bool Equals(BroField other)
        {
            if ((object)other == null)
                return false;

            if (ReferenceEquals(this, other))
                return true;

            return string.Compare(m_name, other.m_name, StringComparison.Ordinal) == 0 && base.Equals(other);
        }

        /// <summary>
        /// Gets a hash code for this <see cref="BroField"/>. 
        /// </summary>
        /// <returns>
        /// A hash code for the current <see cref="BroField"/>.
        /// </returns>
        public override int GetHashCode()
        {
            if ((object)m_name == null)
                return base.GetHashCode();

            return m_name.GetHashCode() ^ base.GetHashCode();
        }

        #endregion

        #region [ Operators ]

        #region [ Equality Operators ]

        /// <summary>
        /// Equality operator for <see cref="BroField"/>.
        /// </summary>
        /// <param name="left">Left <see cref="BroField"/> operand to test for equality.</param>
        /// <param name="right">Right <see cref="BroField"/> operand to test for equality.</param>
        /// <returns><c>true</c> if <paramref name="left"/> parameter is equal to <paramref name="right"/> parameter; otherwise, <c>false</c>.</returns>
        public static bool operator ==(BroField left, BroField right)
        {
            if ((object)left == null && (object)right == null)
                return true;

            if ((object)left == null || (object)right == null)
                return false;

            return left.Equals(right);
        }

        /// <summary>
        /// Inequality operator for <see cref="BroField"/>.
        /// </summary>
        /// <param name="left">Left <see cref="BroField"/> operand to test for inequality.</param>
        /// <param name="right">Right <see cref="BroField"/> operand to test for inequality.</param>
        /// <returns><c>true</c> if <paramref name="left"/> parameter is equal to <paramref name="right"/> parameter; otherwise, <c>false</c>.</returns>
        public static bool operator !=(BroField left, BroField right)
        {
            return !(left == right);
        }

        #endregion

        // Implicit conversions from BroField to other types managed by BroValue conversions

        #region [ Implicit BroField <= BroString / String Conversions ]

        /// <summary>
        /// Implicitly converts <see cref="BroString"/> value to a <see cref="BroField"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroString"/> object.</param>
        /// <returns>A <see cref="BroField"/> object.</returns>
        public static implicit operator BroField(BroString value)
        {
            return new BroField(value, BroType.String);
        }

        /// <summary>
        /// Implicitly converts <see cref="string"/> value to a <see cref="BroField"/>.
        /// </summary>
        /// <param name="value">A <see cref="string"/> value.</param>
        /// <returns>A <see cref="BroField"/> object.</returns>
        public static implicit operator BroField(string value)
        {
            return new BroField((BroString)value, BroType.String);
        }

        #endregion

        #region [ Implicit BroField <= BroPort Conversion ]

        /// <summary>
        /// Implicitly converts <see cref="BroPort"/> value to a <see cref="BroField"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroPort"/> object.</param>
        /// <returns>A <see cref="BroField"/> object.</returns>
        public static implicit operator BroField(BroPort value)
        {
            return new BroField(value, BroType.Port);
        }

        #endregion

        #region [ Implicit BroField <= BroAddress / IPAddress Conversions]

        /// <summary>
        /// Implicitly converts <see cref="BroAddress"/> value to a <see cref="BroField"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroAddress"/> object.</param>
        /// <returns>A <see cref="BroField"/> object.</returns>
        public static implicit operator BroField(BroAddress value)
        {
            return new BroField(value, BroType.IpAddr);
        }

        /// <summary>
        /// Implicitly converts <see cref="IPAddress"/> value to a <see cref="BroField"/>.
        /// </summary>
        /// <param name="value">An <see cref="IPAddress"/> value.</param>
        /// <returns>A <see cref="BroField"/> object.</returns>
        public static implicit operator BroField(IPAddress value)
        {
            return (BroAddress)value;
        }

        #endregion

        #region [ Implicit BroField <= BroSubnet Conversion ]

        /// <summary>
        /// Implicitly converts <see cref="BroSubnet"/> value to a <see cref="BroField"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroSubnet"/> object.</param>
        /// <returns>A <see cref="BroField"/> object.</returns>
        public static implicit operator BroField(BroSubnet value)
        {
            return new BroField(value, BroType.Subnet);
        }

        #endregion

        #region [ Implicit BroField <= BroVector Conversion ]

        /// <summary>
        /// Implicitly converts <see cref="BroVector"/> value to a <see cref="BroField"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroVector"/> object.</param>
        /// <returns>A <see cref="BroField"/> object.</returns>
        public static implicit operator BroField(BroVector value)
        {
            return new BroField(value, BroType.Vector);
        }

        #endregion

        #region [ Implicit BroField <= BroRecord Conversion ]

        /// <summary>
        /// Implicitly converts <see cref="BroRecord"/> value to a <see cref="BroField"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroRecord"/> object.</param>
        /// <returns>A <see cref="BroField"/> object.</returns>
        public static implicit operator BroField(BroRecord value)
        {
            return new BroField(value, BroType.Record);
        }

        #endregion

        #region [ Implicit BroField <= BroTable Conversion ]

        /// <summary>
        /// Implicitly converts <see cref="BroTable"/> value to a <see cref="BroField"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroTable"/> object.</param>
        /// <returns>A <see cref="BroField"/> object.</returns>
        public static implicit operator BroField(BroTable value)
        {
            return new BroField(value, BroType.Table);
        }

        #endregion

        #region [ Implicit BroField <= BroSet Conversion ]

        /// <summary>
        /// Implicitly converts <see cref="BroSet"/> value to a <see cref="BroField"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroSet"/> object.</param>
        /// <returns>A <see cref="BroField"/> object.</returns>
        public static implicit operator BroField(BroSet value)
        {
            return new BroField(value, BroType.Set);
        }

        #endregion

#if BRO_PCAP_SUPPORT
        #region [ Implicit BroField <= BroPacket Conversion ]

        /// <summary>
        /// Implicitly converts <see cref="BroPacket"/> value to a <see cref="BroField"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroPacket"/> object.</param>
        /// <returns>A <see cref="BroField"/> object.</returns>
        public static implicit operator BroField(BroPacket value)
        {
            return new BroField(value, BroType.Packet);
        }

        #endregion
#endif

        #region [ Implicit BroField <= BroTime / DateTime Conversions ]

        /// <summary>
        /// Implicitly converts <see cref="BroTime"/> value to a <see cref="BroField"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroTime"/> value.</param>
        /// <returns>A <see cref="BroField"/> object.</returns>
        public static implicit operator BroField(BroTime value)
        {
            return new BroField(value, BroType.Time);
        }

        /// <summary>
        /// Implicitly converts <see cref="DateTime"/> value to a <see cref="BroField"/>.
        /// </summary>
        /// <param name="value">A <see cref="DateTime"/> value.</param>
        /// <returns>A <see cref="BroField"/> object.</returns>
        public static implicit operator BroField(DateTime value)
        {
            return (BroTime)value;
        }

        #endregion

        #region [ Implicit BroField <= Boolean Conversion ]

        /// <summary>
        /// Implicitly converts <see cref="bool"/> value to a <see cref="BroField"/>.
        /// </summary>
        /// <param name="value">A <see cref="bool"/> value.</param>
        /// <returns>A <see cref="BroField"/> object.</returns>
        public static implicit operator BroField(bool value)
        {
            return new BroField(value ? ~0 : 0, BroType.Bool);
        }

        #endregion

        #endregion
    }
}
