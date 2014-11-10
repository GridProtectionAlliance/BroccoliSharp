//******************************************************************************************************
//  BroValue.cs - Gbtc
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
//  10/22/2014 - J. Ritchie Carroll
//       Generated original version of source code.
//
//******************************************************************************************************

using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
using BroccoliSharp.Internal;

namespace BroccoliSharp
{
    /// <summary>
    /// Represents a Bro value. Implicitly castable to all <see cref="BroType"/> wrapper classes,
    /// structures and applicable .NET data types.
    /// </summary>
    /// <include file='Documentation\BroValue.xml' path='/doc/*'/>
    public class BroValue : IEquatable<BroValue>
    {
        #region [ Members ]

        // Fields
        private readonly BroType m_type;
        private readonly object m_value;
        private string m_typeName;

        #endregion

        #region [ Constructors ]

        /// <summary>
        /// Creates a new <see cref="BroValue"/>.
        /// </summary>
        /// <param name="value">Value of <see cref="BroValue"/>.</param>
        /// <param name="type"><see cref="BroType"/> of <see cref="BroValue"/>.</param>
        /// <param name="typeName">Optional name of specialized type of <see cref="BroValue"/>.</param>
        /// <exception cref="InvalidOperationException">BroValue <paramref name="type"/> is mismatched for <paramref name="value"/>.</exception>
        public BroValue(object value, BroType type, string typeName = null)
        {
            m_type = type;
            m_typeName = typeName;

            // Attempt to create Bro value from provided object value
            if (m_type.IsValueType())
                m_value = CreateValueTypeFromObject(value, type);
            else
                m_value = CreateReferenceTypeFromObject(value, type);
        }

        // Creates a new Bro value directly from provided values - no type-checking, use with caution
        internal BroValue(BroType type, object value)
        {
            m_value = value;
            m_type = type;
            m_typeName = null;
        }

        #endregion

        #region [ Properties ]

        /// <summary>
        /// Gets type of <see cref="BroValue"/>.
        /// </summary>
        public BroType Type
        {
            get
            {
                return m_type;
            }
        }

        /// <summary>
        /// Gets or sets optional name of specialized type of <see cref="BroValue"/>.
        /// </summary>
        public string TypeName
        {
            get
            {
                return m_typeName;
            }
            set
            {
                // Could make Bro value immutable by making this property read-only,
                // but the class is more useful when it's not.
                m_typeName = value;
            }
        }

        /// <summary>
        /// Gets value of <see cref="BroValue"/>.
        /// </summary>
        public object Value
        {
            get
            {
                if (m_type == BroType.Unknown)
                    return null;

                // Get boxed object value for value-type values
                if (m_type.IsValueType())
                {
                    switch (m_type)
                    {
                        case BroType.Bool:
                            return GetValueAsInt();
                        case BroType.Int:
                        case BroType.Count:
                        case BroType.Counter:
                        case BroType.Enum:
                            return GetValueAsULong();
                        case BroType.Double:
                        case BroType.Time:
                        case BroType.Interval:
                            return GetValueAsDouble();
                        case BroType.Port:
                            return GetValueAsBroPort();
                        case BroType.IpAddr:
                            return GetValueAsBroAddress();
                        case BroType.Subnet:
                            return GetValueAsBroSubnet();
                    }
                }

                // Return reference to object for reference-types
                return m_value;
            }
        }

        /// <summary>
        /// Gets a flag that determines if this <see cref="BroValue"/> as an assigned value.
        /// </summary>
        public bool HasValue
        {
            get
            {
                return m_value != null;
            }
        }

        #endregion

        #region [ Methods ]

        /// <summary>
        /// Determines whether the specified <see cref="Object"/> is equal to the current <see cref="BroValue"/>.
        /// </summary>
        /// <returns>
        /// <c>true</c> if the specified object is equal to the current object; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="obj">The object to compare with the current object. </param>
        public override bool Equals(object obj)
        {
            BroValue value = obj as BroValue;

            return (object)value != null && Equals(value);
        }

        /// <summary>
        /// Indicates whether the current <see cref="BroValue"/> is equal to another <see cref="BroValue"/> of the same <see cref="BroType"/>.
        /// </summary>
        /// <returns>
        /// <c>true</c> if this <see cref="BroValue"/> is equal to the <paramref name="other"/> <see cref="BroValue"/>; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="other">A <see cref="BroValue"/> to compare with this <see cref="BroValue"/>.</param>
        public bool Equals(BroValue other)
        {
            if ((object)other == null)
                return false;

            if (ReferenceEquals(this, other))
                return true;

            if (string.Compare(m_typeName, other.m_typeName, StringComparison.Ordinal) != 0)
                return false;

            if (m_type == other.m_type)
            {
                if (m_type.IsValueType())
                {
                    switch (m_type)
                    {
                        case BroType.Unknown:
                            break;
                        // For value-types, we compare by value
                        case BroType.Bool:
                            return GetValueAsInt() == other.GetValueAsInt();
                        case BroType.Int:
                        case BroType.Count:
                        case BroType.Counter:
                        case BroType.Enum:
                            return GetValueAsULong() == other.GetValueAsULong();
                        case BroType.Double:
                        case BroType.Time:
                        case BroType.Interval:
                            return GetValueAsDouble() == other.GetValueAsDouble();
                        case BroType.Port:
                            return GetValueAsBroPort() == other.GetValueAsBroPort();
                        case BroType.IpAddr:
                            return GetValueAsBroAddress() == other.GetValueAsBroAddress();
                        case BroType.Subnet:
                            return GetValueAsBroSubnet() == other.GetValueAsBroSubnet();
                        // Compare string values for Bro strings
                        case BroType.String:
                            return (Value as BroString) == (other.Value as BroString);
                        // For opaque reference-types, we compare value pointers
                        case BroType.Table:
                        case BroType.Record:
                        case BroType.List:
                        case BroType.Vector:
                        case BroType.Packet:
                        case BroType.Set:
                            return GetValuePtr() == other.GetValuePtr();
                        default:
                            return false;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Gets a hash code for this <see cref="BroValue"/>. 
        /// </summary>
        /// <returns>
        /// A hash code for the current <see cref="BroValue"/>.
        /// </returns>
        public override int GetHashCode()
        {
            int hashCode = 0;

            if (m_type.IsValueType())
            {
                switch (m_type)
                {
                    case BroType.Bool:
                        hashCode = GetValueAsInt().GetHashCode();
                        break;
                    case BroType.Int:
                    case BroType.Count:
                    case BroType.Counter:
                    case BroType.Enum:
                        hashCode = GetValueAsULong().GetHashCode();
                        break;
                    case BroType.Double:
                    case BroType.Time:
                    case BroType.Interval:
                        hashCode = GetValueAsDouble().GetHashCode();
                        break;
                    case BroType.Port:
                        hashCode = GetValueAsBroPort().GetHashCode();
                        break;
                    case BroType.IpAddr:
                        hashCode = GetValueAsBroAddress().GetHashCode();
                        break;
                    case BroType.Subnet:
                        hashCode = GetValueAsBroSubnet().GetHashCode();
                        break;
                }
            }
            else
            {
                if (m_type == BroType.String)
                {
                    BroString str = m_value as BroString;
                    if ((object)str != null)
                        hashCode = str.GetHashCode();
                }
                else
                {
                    hashCode = GetValuePtr().GetHashCode();
                }
            }

            if ((object)m_typeName == null)
                return (int)(m_type.GetHashCode() ^ hashCode);

            return (int)(m_type.GetHashCode() ^ m_typeName.GetHashCode() ^ hashCode);
        }

        /// <summary>
        /// Returns a string that represents this <see cref="BroValue"/>.
        /// </summary>
        /// <returns>
        /// A string that represents this <see cref="BroValue"/>.
        /// </returns>
        public override string ToString()
        {
            return Value.ToString();
        }

        // Executes an API call using Bro value with a fixed memory pointer (if needed)
        internal unsafe T ExecuteWithFixedPtr<T>(Func<IntPtr, T> operation)
        {
            if (m_type.IsValueType())
            {
                switch (m_type)
                {
                    case BroType.Port:
                        // Handle obtaining pointer for bro_port structure in managed memory space
                        bro_port port = GetValueAsBroPort().GetValue();
                        return operation(new IntPtr(&port));
                    case BroType.IpAddr:
                        // Handle obtaining pointer for bro_addr structure in managed memory space
                        bro_addr address = GetValueAsBroAddress().GetValue();
                        return operation(new IntPtr(&address));
                    case BroType.Subnet:
                        // Handle obtaining pointer for bro_subnet structure in managed memory space
                        bro_subnet subnet = GetValueAsBroSubnet().GetValue();
                        return operation(new IntPtr(&subnet));
                    default:
                        // Handle obtaining pointer for native value-types in managed memory space
                        byte[] buffer = GetValueBuffer();

                        fixed (void* pValue = &buffer[0])
                        {
                            return operation(new IntPtr(pValue));
                        }
                }
            }

            if ((object)m_value == null)
                return operation(IntPtr.Zero);

            // Handle obtaining pointer for bro_string structure in managed memory space
            if (m_type == BroType.String)
            {
                BroString broString = m_value as BroString;

                if ((object)broString == null)
                    return operation(IntPtr.Zero);

                bro_string str = broString.GetValue();
                return operation(new IntPtr(&str));
            }

            // Handle obtaining pointer for opaque reference-types - Bro API calls
            // do not modify value pointers, so this is safe:
            return operation(GetValuePtr().DangerousGetHandle());
        }

        // ***************************************************************************************
        //
        //    These functions should only be called when the BroType has already been validated
        //
        // ***************************************************************************************

        // Get internal value as a value-type buffer
        private byte[] GetValueBuffer()
        {
            byte[] buffer = m_value as byte[];

            if ((object)buffer == null)
                throw new InvalidOperationException("BroValue was not initialized as a value-type.");

            return buffer;
        }

        // Gets value pointer for opaque reference-types.
        internal SafeHandle GetValuePtr()
        {
            // Can only get pointer to Bro base object for opaque reference-types
            if (m_value != null)
            {
                switch (m_type)
                {
                    case BroType.Table:
                        BroTable table = m_value as BroTable;
                        if ((object)table != null)
                            return table.GetValuePtr();
                        break;
                    case BroType.List:
                    case BroType.Record:
                        BroRecord record = m_value as BroRecord;
                        if ((object)record != null)
                            return record.GetValuePtr();
                        break;
                    case BroType.Vector:
                        BroVector vector = m_value as BroVector;
                        if ((object)vector != null)
                            return vector.GetValuePtr();
                        break;
#if BRO_PCAP_SUPPORT
                    case BroType.Packet:
                        BroPacket packet = m_value as BroPacket;
                        if ((object)packet != null)
                            return packet.GetValuePtr();
                        break;
#endif
                    case BroType.Set:
                        BroSet set = m_value as BroSet;
                        if ((object)set != null)
                            return set.GetValuePtr();
                        break;
                }
            }

            if (m_value is IntPtr)
                return new BroUnknownPtr((IntPtr)m_value);

            return new BroUnknownPtr(IntPtr.Zero);
        }

        // Get Bro value as an int (typically for bool values)
        internal unsafe int GetValueAsInt()
        {
            byte[] buffer = GetValueBuffer();

            if (buffer.Length != sizeof(int))
                throw new InvalidOperationException("BroValue was not initialized as a boolean with sizeof(int)).");

            fixed (void* pValue = &buffer[0])
            {
                return *(int*)pValue;
            }
        }

        // Get Bro value as an ulong
        internal unsafe ulong GetValueAsULong()
        {
            byte[] buffer = GetValueBuffer();

            if (buffer.Length != sizeof(ulong))
                throw new InvalidOperationException("BroValue was not initialized an int, counter, count or enum with sizeof(ulong).");

            fixed (void* pValue = &buffer[0])
            {
                return *(ulong*)pValue;
            }
        }

        // Get Bro value as a double
        internal unsafe double GetValueAsDouble()
        {
            byte[] buffer = GetValueBuffer();

            if (buffer.Length != sizeof(double))
                throw new InvalidOperationException("BroValue was not initialized as double, time or interval with sizeof(double).");

            fixed (void* pValue = &buffer[0])
            {
                return *(double*)pValue;
            }
        }

        // Get Bro value as a BroPort
        internal unsafe BroPort GetValueAsBroPort()
        {
            byte[] buffer = GetValueBuffer();

            if (buffer.Length != sizeof(BroPort))
                throw new InvalidOperationException("BroValue was not initialized as a BroPort.");

            fixed (void* pValue = &buffer[0])
            {
                return *(BroPort*)pValue;
            }
        }

        // Get Bro value as a BroAddress
        internal unsafe BroAddress GetValueAsBroAddress()
        {
            byte[] buffer = GetValueBuffer();

            if (buffer.Length != sizeof(BroAddress))
                throw new InvalidOperationException("BroValue was not initialized as a BroAddress.");

            fixed (void* pValue = &buffer[0])
            {
                return *(BroAddress*)pValue;
            }
        }

        // Get Bro value as a BroSubnet
        internal unsafe BroSubnet GetValueAsBroSubnet()
        {
            byte[] buffer = GetValueBuffer();

            if (buffer.Length != sizeof(BroSubnet))
                throw new InvalidOperationException("BroValue was not initialized as a BroSubnet.");

            fixed (void* pValue = &buffer[0])
            {
                return *(BroSubnet*)pValue;
            }
        }

        #endregion

        #region [ Operators ]

        #region [ Equality Operators ]

        /// <summary>
        /// Equality operator for <see cref="BroValue"/>.
        /// </summary>
        /// <param name="left">Left <see cref="BroValue"/> operand to test for equality.</param>
        /// <param name="right">Right <see cref="BroValue"/> operand to test for equality.</param>
        /// <returns><c>true</c> if <paramref name="left"/> parameter is equal to <paramref name="right"/> parameter; otherwise, <c>false</c>.</returns>
        public static bool operator ==(BroValue left, BroValue right)
        {
            if ((object)left == null && (object)right == null)
                return true;

            if ((object)left == null || (object)right == null)
                return false;

            return left.Equals(right);
        }

        /// <summary>
        /// Inequality operator for <see cref="BroValue"/>.
        /// </summary>
        /// <param name="left">Left <see cref="BroValue"/> operand to test for inequality.</param>
        /// <param name="right">Right <see cref="BroValue"/> operand to test for inequality.</param>
        /// <returns><c>true</c> if <paramref name="left"/> parameter is equal to <paramref name="right"/> parameter; otherwise, <c>false</c>.</returns>
        public static bool operator !=(BroValue left, BroValue right)
        {
            return !(left == right);
        }

        #endregion

        #region [ Implicit BroValue <=> BroString / String Conversions ]

        /// <summary>
        /// Implicitly converts <see cref="BroString"/> value to a <see cref="BroValue"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroString"/> object.</param>
        /// <returns>A <see cref="BroValue"/> object.</returns>
        public static implicit operator BroValue(BroString value)
        {
            return new BroValue(value, BroType.String);
        }

        /// <summary>
        /// Implicitly converts <see cref="BroValue"/> to a <see cref="BroString"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroValue"/> object.</param>
        /// <returns>A <see cref="BroString"/> object.</returns>
        public static implicit operator BroString(BroValue value)
        {
            if ((object)value == null)
                return null;

            if (value.Type == BroType.String)
                return (BroString)value.Value;

            return null;
        }

        /// <summary>
        /// Implicitly converts <see cref="string"/> value to a <see cref="BroValue"/>.
        /// </summary>
        /// <param name="value">A <see cref="string"/> value.</param>
        /// <returns>A <see cref="BroValue"/> object.</returns>
        public static implicit operator BroValue(string value)
        {
            return new BroValue((BroString)value, BroType.String);
        }

        /// <summary>
        /// Implicitly converts <see cref="BroValue"/> to a <see cref="string"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroValue"/> object.</param>
        /// <returns>A <see cref="string"/> value.</returns>
        public static implicit operator string(BroValue value)
        {
            return (BroString)value;
        }

        #endregion

        #region [ Implicit BroValue <=> BroPort Conversions ]

        /// <summary>
        /// Implicitly converts <see cref="BroPort"/> value to a <see cref="BroValue"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroPort"/> object.</param>
        /// <returns>A <see cref="BroValue"/> object.</returns>
        public static implicit operator BroValue(BroPort value)
        {
            return new BroValue(value, BroType.Port);
        }

        /// <summary>
        /// Implicitly converts <see cref="BroValue"/> to a <see cref="BroPort"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroValue"/> object.</param>
        /// <returns>A <see cref="BroPort"/> object.</returns>
        public static implicit operator BroPort(BroValue value)
        {
            if ((object)value == null)
                return default(BroPort);

            if (value.Type == BroType.Port)
                return value.GetValueAsBroPort();

            return default(BroPort);
        }

        #endregion

        #region [ Implicit BroValue <=> BroAddress / IPAddress Conversions]

        /// <summary>
        /// Implicitly converts <see cref="BroAddress"/> value to a <see cref="BroValue"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroAddress"/> object.</param>
        /// <returns>A <see cref="BroValue"/> object.</returns>
        public static implicit operator BroValue(BroAddress value)
        {
            return new BroValue(value, BroType.IpAddr);
        }

        /// <summary>
        /// Implicitly converts <see cref="BroValue"/> to a <see cref="BroAddress"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroValue"/> object.</param>
        /// <returns>A <see cref="BroAddress"/> object.</returns>
        public static implicit operator BroAddress(BroValue value)
        {
            if ((object)value == null)
                return default(BroAddress);

            if (value.Type == BroType.IpAddr)
                return value.GetValueAsBroAddress();

            if (value.Type == BroType.Subnet)
                return value.GetValueAsBroSubnet();

            return default(BroAddress);
        }

        /// <summary>
        /// Implicitly converts <see cref="IPAddress"/> value to a <see cref="BroValue"/>.
        /// </summary>
        /// <param name="value">An <see cref="IPAddress"/> value.</param>
        /// <returns>A <see cref="BroValue"/> object.</returns>
        public static implicit operator BroValue(IPAddress value)
        {
            return (BroAddress)value;
        }

        /// <summary>
        /// Implicitly converts <see cref="BroValue"/> to an <see cref="IPAddress"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroValue"/> object.</param>
        /// <returns>An <see cref="IPAddress"/> value.</returns>
        public static implicit operator IPAddress(BroValue value)
        {
            if ((object)value == null)
                return null;

            return (BroAddress)value;
        }

        #endregion

        #region [ Implicit BroValue <=> BroSubnet Conversions ]

        /// <summary>
        /// Implicitly converts <see cref="BroSubnet"/> value to a <see cref="BroValue"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroSubnet"/> object.</param>
        /// <returns>A <see cref="BroValue"/> object.</returns>
        public static implicit operator BroValue(BroSubnet value)
        {
            return new BroValue(value, BroType.Subnet);
        }

        /// <summary>
        /// Implicitly converts <see cref="BroValue"/> to a <see cref="BroSubnet"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroValue"/> object.</param>
        /// <returns>A <see cref="BroSubnet"/> object.</returns>
        public static implicit operator BroSubnet(BroValue value)
        {
            if ((object)value == null)
                return default(BroSubnet);

            if (value.Type == BroType.Subnet)
                return value.GetValueAsBroSubnet();

            return default(BroSubnet);
        }

        #endregion

        #region [ Implicit BroValue <=> BroVector Conversions ]

        /// <summary>
        /// Implicitly converts <see cref="BroVector"/> value to a <see cref="BroValue"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroVector"/> object.</param>
        /// <returns>A <see cref="BroValue"/> object.</returns>
        public static implicit operator BroValue(BroVector value)
        {
            return new BroValue(value, BroType.Vector);
        }

        /// <summary>
        /// Implicitly converts <see cref="BroValue"/> to a <see cref="BroVector"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroValue"/> object.</param>
        /// <returns>A <see cref="BroVector"/> object.</returns>
        public static implicit operator BroVector(BroValue value)
        {
            if ((object)value == null)
                return null;

            if (value.Type == BroType.Vector)
                return (BroVector)value.Value;

            return null;
        }

        #endregion

        #region [ Implicit BroValue <=> BroRecord Conversions ]

        /// <summary>
        /// Implicitly converts <see cref="BroRecord"/> value to a <see cref="BroValue"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroRecord"/> object.</param>
        /// <returns>A <see cref="BroValue"/> object.</returns>
        public static implicit operator BroValue(BroRecord value)
        {
            return new BroValue(value, BroType.Record);
        }

        /// <summary>
        /// Implicitly converts <see cref="BroValue"/> to a <see cref="BroRecord"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroValue"/> object.</param>
        /// <returns>A <see cref="BroRecord"/> object.</returns>
        public static implicit operator BroRecord(BroValue value)
        {
            if ((object)value == null)
                return null;

            if (value.Type == BroType.Record || value.Type == BroType.List)
                return (BroRecord)value.Value;

            return null;
        }

        #endregion

        #region [ Implicit BroValue <=> BroTable Conversions ]

        /// <summary>
        /// Implicitly converts <see cref="BroTable"/> value to a <see cref="BroValue"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroTable"/> object.</param>
        /// <returns>A <see cref="BroValue"/> object.</returns>
        public static implicit operator BroValue(BroTable value)
        {
            return new BroValue(value, BroType.Table);
        }

        /// <summary>
        /// Implicitly converts <see cref="BroValue"/> to a <see cref="BroTable"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroValue"/> object.</param>
        /// <returns>A <see cref="BroTable"/> object.</returns>
        public static implicit operator BroTable(BroValue value)
        {
            if ((object)value == null)
                return null;

            if (value.Type == BroType.Table)
                return (BroTable)value.Value;

            return null;
        }

        #endregion

        #region [ Implicit BroValue <=> BroSet Conversions ]

        /// <summary>
        /// Implicitly converts <see cref="BroSet"/> value to a <see cref="BroValue"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroSet"/> object.</param>
        /// <returns>A <see cref="BroValue"/> object.</returns>
        public static implicit operator BroValue(BroSet value)
        {
            return new BroValue(value, BroType.Set);
        }

        /// <summary>
        /// Implicitly converts <see cref="BroValue"/> to a <see cref="BroSet"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroValue"/> object.</param>
        /// <returns>A <see cref="BroSet"/> object.</returns>
        public static implicit operator BroSet(BroValue value)
        {
            if ((object)value == null)
                return null;

            if (value.Type == BroType.Set)
                return (BroSet)value.Value;

            return null;
        }

        #endregion

#if BRO_PCAP_SUPPORT
        #region [ Implicit BroValue <=> BroPacket Conversions ]

        /// <summary>
        /// Implicitly converts <see cref="BroPacket"/> value to a <see cref="BroValue"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroPacket"/> object.</param>
        /// <returns>A <see cref="BroValue"/> object.</returns>
        public static implicit operator BroValue(BroPacket value)
        {
            return new BroValue(value, BroType.Packet);
        }

        /// <summary>
        /// Implicitly converts <see cref="BroValue"/> to a <see cref="BroPacket"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroValue"/> object.</param>
        /// <returns>A <see cref="BroPacket"/> object.</returns>
        public static implicit operator BroPacket(BroValue value)
        {
            if ((object)value == null)
                return null;

            if (value.Type == BroType.Packet)
                return (BroPacket)value.Value;

            return null;
        }

        #endregion
#endif

        #region [ Implicit BroValue <=> BroTime / DateTime Conversions ]

        /// <summary>
        /// Implicitly converts <see cref="BroTime"/> value to a <see cref="BroValue"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroTime"/> value.</param>
        /// <returns>A <see cref="BroValue"/> object.</returns>
        public static implicit operator BroValue(BroTime value)
        {
            return new BroValue(value, BroType.Time);
        }

        /// <summary>
        /// Implicitly converts <see cref="BroValue"/> to a <see cref="BroTime"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroValue"/> object.</param>
        /// <returns>A <see cref="BroTime"/> value.</returns>
        public static implicit operator BroTime(BroValue value)
        {
            return (double)value;
        }

        /// <summary>
        /// Implicitly converts <see cref="DateTime"/> value to a <see cref="BroValue"/>.
        /// </summary>
        /// <param name="value">A <see cref="DateTime"/> value.</param>
        /// <returns>A <see cref="BroValue"/> object.</returns>
        public static implicit operator BroValue(DateTime value)
        {
            return (BroTime)value;
        }

        /// <summary>
        /// Implicitly converts <see cref="BroValue"/> to a <see cref="DateTime"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroValue"/> object.</param>
        /// <returns>A <see cref="DateTime"/> value.</returns>
        public static implicit operator DateTime(BroValue value)
        {
            return (BroTime)value;
        }

        #endregion

        #region [ Implicit BroValue <=> Boolean Conversions ]

        /// <summary>
        /// Implicitly converts <see cref="bool"/> value to a <see cref="BroValue"/>.
        /// </summary>
        /// <param name="value">A <see cref="bool"/> value.</param>
        /// <returns>A <see cref="BroValue"/> object.</returns>
        public static implicit operator BroValue(bool value)
        {
            return new BroValue(value ? ~0 : 0, BroType.Bool);
        }

        /// <summary>
        /// Implicitly converts <see cref="BroValue"/> to a <see cref="bool"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroValue"/> object.</param>
        /// <returns>A <see cref="bool"/> value.</returns>
        /// <exception cref="InvalidCastException">Cannot cast BroValue to a bool.</exception>
        public static implicit operator bool(BroValue value)
        {
            return (int)value != 0;
        }

        #endregion

        #region [ Implicit BroValue => Native Value-type Conversions ]

        // Cannot implicitly cast other value-types to a BroValue without knowing the desired type.
        // To create a native value-type based BroValue just use the BroValue common constructor
        // or value method overloads that accept the BroType.

        /// <summary>
        /// Implicitly converts <see cref="BroValue"/> to a <see cref="int"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroValue"/> object.</param>
        /// <returns>A <see cref="int"/> value.</returns>
        public static implicit operator int(BroValue value)
        {
            if ((object)value == null)
                return default(int);

            if (value.Type == BroType.Bool)
                return value.GetValueAsInt();

            return Convert.ToInt32(value.Value);
        }

        /// <summary>
        /// Implicitly converts <see cref="BroValue"/> to a <see cref="ulong"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroValue"/> object.</param>
        /// <returns>A <see cref="ulong"/> value.</returns>
        /// <exception cref="InvalidCastException">Cannot cast BroValue to a ulong.</exception>
        public static implicit operator ulong(BroValue value)
        {
            if ((object)value == null)
                return default(ulong);

            switch (value.Type)
            {
                case BroType.Int:
                case BroType.Count:
                case BroType.Counter:
                case BroType.Enum:
                    return value.GetValueAsULong();
                default:
                    return Convert.ToUInt32(value.Value);
            }
        }

        /// <summary>
        /// Implicitly converts <see cref="BroValue"/> to a <see cref="double"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroValue"/> object.</param>
        /// <returns>A <see cref="double"/> value.</returns>
        /// <exception cref="InvalidCastException">Cannot cast BroValue to a double.</exception>
        public static implicit operator double(BroValue value)
        {
            if ((object)value == null)
                return default(double);

            switch (value.Type)
            {
                case BroType.Double:
                case BroType.Time:
                case BroType.Interval:
                    return value.GetValueAsDouble();
                default:
                    return Convert.ToDouble(value.Value);
            }
        }

        #endregion

        #endregion

        #region [ Static ]

        // Static Methods

        // Creates a new value-type buffer from an existing object value
        private static unsafe byte[] CreateValueTypeFromObject(object sourceValue, BroType type)
        {
            byte[] buffer = null;

            // Create value-type value from boxed object value
            switch (type)
            {
                case BroType.Bool:
                    buffer = new byte[sizeof(int)];

                    fixed (void* pValue = &buffer[0])
                    {
                        *(int*)pValue = (Convert.ToInt32(sourceValue) == 0 ? 0 : ~0);
                    }
                    break;
                case BroType.Int:
                case BroType.Count:
                case BroType.Counter:
                case BroType.Enum:
                    buffer = new byte[sizeof(ulong)];

                    fixed (void* pValue = &buffer[0])
                    {
                        *(ulong*)pValue = Convert.ToUInt64(sourceValue);
                    }
                    break;
                case BroType.Double:
                case BroType.Time:
                case BroType.Interval:
                    buffer = new byte[sizeof(double)];

                    fixed (void* pValue = &buffer[0])
                    {
                        if (sourceValue is BroTime)
                            *(double*)pValue = (BroTime)sourceValue;
                        else if (sourceValue is DateTime)
                            *(double*)pValue = (BroTime)(DateTime)sourceValue;
                        else
                            *(double*)pValue = Convert.ToDouble(sourceValue);
                    }
                    break;
                case BroType.Port:
                    buffer = new byte[sizeof(BroPort)];

                    fixed (void* pValue = &buffer[0])
                    {
                        if (sourceValue is BroPort)
                            *(BroPort*)pValue = (BroPort)sourceValue;
                        else
                            throw new InvalidOperationException("BroValue of type \"Port\" can only reference a BroPort.");
                    }
                    break;
                case BroType.IpAddr:
                    buffer = new byte[sizeof(BroAddress)];

                    fixed (void* pValue = &buffer[0])
                    {
                        if (sourceValue is BroAddress)
                            *(BroAddress*)pValue = (BroAddress)sourceValue;
                        else if (sourceValue is BroSubnet)
                            *(BroAddress*)pValue = (BroSubnet)sourceValue;
                        else if (sourceValue is string)
                            *(BroAddress*)pValue = new BroAddress(sourceValue as string);
                        else if (sourceValue is IPAddress)
                            *(BroAddress*)pValue = (IPAddress)sourceValue;
                        else
                            throw new InvalidOperationException("BroValue of type \"IpAddr\" can only reference a BroAddress.");
                    }
                    break;
                case BroType.Subnet:
                    buffer = new byte[sizeof(BroSubnet)];

                    fixed (void* pValue = &buffer[0])
                    {
                        if (sourceValue is BroSubnet)
                            *(BroSubnet*)pValue = (BroSubnet)sourceValue;
                        else
                            throw new InvalidOperationException("BroValue of type \"Subnet\" can only reference a BroSubnet.");
                    }
                    break;
            }

            return buffer;
        }

        // Create a new reference-type from an existing object value
        private static object CreateReferenceTypeFromObject(object sourceValue, BroType type)
        {
            // Validate and create reference-type value - null is a valid value
            if (sourceValue == null)
                return null;

            switch (type)
            {
                case BroType.String:
                    BroString str = sourceValue as BroString;

                    if ((object)str == null)
                    {
                        // Handle direct BroString creation from a string
                        if (sourceValue is string)
                            return new BroString(sourceValue as string);

                        throw new InvalidOperationException("BroValue of type \"String\" can only reference a BroString.");
                    }

                    return str;
                case BroType.Table:
                    BroTable table = sourceValue as BroTable;

                    if ((object)table == null)
                    {
                        // Handle direct BroTable creation from an IDictionary<BroValue, BroValue>
                        if (sourceValue is IDictionary<BroValue, BroValue>)
                            return new BroTable(sourceValue as IDictionary<BroValue, BroValue>);

                        throw new InvalidOperationException("BroValue of type \"Table\" can only reference a BroTable.");
                    }

                    return table;
                case BroType.List:
                case BroType.Record:
                    BroRecord record = sourceValue as BroRecord;

                    if ((object)record == null)
                    {
                        // Handle direct BroRecord creation from an IEnumerable<BroField>
                        if (sourceValue is IEnumerable<BroField>)
                            return new BroRecord(sourceValue as IEnumerable<BroField>);

                        throw new InvalidOperationException("BroValue of type \"Record\" or \"List\" can only reference a BroRecord.");
                    }

                    return record;
                case BroType.Vector:
                    BroVector vector = sourceValue as BroVector;

                    if ((object)vector == null)
                    {
                        // Handle direct BroVector creation from an IEnumerable<BroValue>
                        if (sourceValue is IEnumerable<BroValue>)
                            return new BroVector(sourceValue as IEnumerable<BroValue>);

                        throw new InvalidOperationException("BroValue of type \"Vector\" can only reference a BroVector.");
                    }

                    return vector;
#if BRO_PCAP_SUPPORT
                case BroType.Packet:
                    BroPacket packet = sourceValue as BroPacket;

                    if ((object)packet == null)
                        throw new InvalidOperationException("BroValue of type \"Packet\" can only reference a BroPacket.");

                    return packet;
#endif
                case BroType.Set:
                    BroSet set = sourceValue as BroSet;

                    if ((object)set == null)
                    {
                        // Handle direct BroSet creation from an IEnumerable<BroValue>
                        if (sourceValue is IEnumerable<BroValue>)
                            return new BroSet(sourceValue as IEnumerable<BroValue>);

                        throw new InvalidOperationException("BroValue of type \"Set\" can only reference a BroSet.");
                    }

                    return set;
            }

            return null;
        }

        // Create a new Bro value from existing source value pointer
        internal static unsafe BroValue CreateFromPtr(IntPtr sourcePtr, BroType type)
        {
            byte[] buffer;
            object value;

            switch (type)
            {
                // Assign pointed-to value for value types
                case BroType.Bool:
                    buffer = new byte[sizeof(int)];

                    if (sourcePtr != IntPtr.Zero)
                    {
                        fixed (void* pValue = &buffer[0])
                        {
                            *(int*)pValue = *(int*)sourcePtr.ToPointer();
                        }
                    }

                    value = buffer;
                    break;
                case BroType.Int:
                case BroType.Count:
                case BroType.Counter:
                case BroType.Enum:
                    buffer = new byte[sizeof(ulong)];

                    if (sourcePtr != IntPtr.Zero)
                    {
                        fixed (void* pValue = &buffer[0])
                        {
                            *(ulong*)pValue = *(ulong*)sourcePtr.ToPointer();
                        }
                    }

                    value = buffer;
                    break;
                case BroType.Double:
                case BroType.Time:
                case BroType.Interval:
                    buffer = new byte[sizeof(double)];

                    if (sourcePtr != IntPtr.Zero)
                    {
                        fixed (void* pValue = &buffer[0])
                        {
                            *(double*)pValue = *(double*)sourcePtr.ToPointer();
                        }
                    }

                    value = buffer;
                    break;
                // Create wrapper structure for pointed-to bro base struct for value-types
                case BroType.Port:
                    buffer = new byte[sizeof(BroPort)];

                    if (sourcePtr != IntPtr.Zero)
                    {
                        fixed (void* pValue = &buffer[0])
                        {
                            *(BroPort*)pValue = new BroPort(*(bro_port*)sourcePtr.ToPointer());
                        }
                    }

                    value = buffer;
                    break;
                case BroType.IpAddr:
                    buffer = new byte[sizeof(BroAddress)];

                    if (sourcePtr != IntPtr.Zero)
                    {
                        fixed (void* pValue = &buffer[0])
                        {
                            *(BroAddress*)pValue = new BroAddress(*(bro_addr*)sourcePtr.ToPointer());
                        }
                    }

                    value = buffer;
                    break;
                case BroType.Subnet:
                    buffer = new byte[sizeof(BroSubnet)];

                    if (sourcePtr != IntPtr.Zero)
                    {
                        fixed (void* pValue = &buffer[0])
                        {
                            *(BroSubnet*)pValue = new BroSubnet(*(bro_subnet*)sourcePtr.ToPointer());
                        }
                    }

                    value = buffer;
                    break;
                // Create wrapper class for pointed-to bro base object for reference-types
                case BroType.String:
                    value = new BroString(*(bro_string*)sourcePtr.ToPointer());
                    break;
                case BroType.Table:
                    value = new BroTable(new BroTablePtr(sourcePtr, false));
                    break;
                case BroType.List:
                case BroType.Record:
                    value = new BroRecord(new BroRecordPtr(sourcePtr, false));
                    break;
                case BroType.Vector:
                    value = new BroVector(new BroVectorPtr(sourcePtr, false));
                    break;
#if BRO_PCAP_SUPPORT
                case BroType.Packet:
                    value = new BroPacket(new BroPacketPtr(sourcePtr, false));
                    break;
#endif
                case BroType.Set:
                    value = new BroSet(new BroSetPtr(sourcePtr, false));
                    break;
                default:
                    // For received values of unsupported types, just provide original pointer as the value,
                    // this could be used as a handy way to get custom data back through BroccoliSharp
                    value = sourcePtr;
                    break;
            }

            return new BroValue(value, type);
        }

        #endregion
    }
}
