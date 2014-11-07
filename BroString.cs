//******************************************************************************************************
//  BroString.cs - Gbtc
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
using BroccoliSharp.Internal;

namespace BroccoliSharp
{
    /// <summary>
    /// Represents an immutable Bro string. Implicitly castable as a <see cref="string"/>.
    /// </summary>
    /// <remarks>
    /// Managed wrapper class for <a href="https://www.bro.org/sphinx/broccoli-api/structbro__string.html">bro_string</a> structure.
    /// </remarks>
    public class BroString : IEquatable<BroString>, IDisposable
    {
        #region [ Members ]

        // Fields
        private bro_string m_value;
        private bool m_disposed;

        #endregion

        #region [ Constructors ]

        /// <summary>
        /// Creates a new <see cref="BroString"/>.
        /// </summary>
        public BroString()
        {
            BroApi.bro_string_init(ref m_value);
        }

        /// <summary>
        /// Creates a new <see cref="BroString"/> from an existing string.
        /// </summary>
        /// <param name="value">String value used to initialize <see cref="BroString"/>.</param>
        public BroString(string value)
            : this()
        {
            BroApi.bro_string_set(ref m_value, value);
        }

        // Creates a new Bro string from an existing Bro string
        internal BroString(bro_string sourceString)
            : this()
        {
            BroApi.bro_string_assign(ref sourceString, ref m_value);
        }

        /// <summary>
        /// Releases the unmanaged resources before this <see cref="BroString"/> object is reclaimed by <see cref="GC"/>.
        /// </summary>
        ~BroString()
        {
            Dispose(false);
        }

        #endregion

        #region [ Properties ]

        /// <summary>
        /// Gets the number of characters in this <see cref="BroString"/>.
        /// </summary>
        /// <remarks>
        /// Returns the <c>str_len</c> value (accessed via the <c>bro_string_get_length</c> function) from the 
        /// <a href="https://www.bro.org/sphinx/broccoli-api/structbro__string.html">bro_string</a> structure.
        /// </remarks>
        public int Length
        {
            get
            {
                return BroApi.bro_string_get_length(ref m_value);
            }
        }

        #endregion

        #region [ Methods ]

        /// <summary>
        /// Releases all the resources used by this <see cref="BroString"/> object.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases the unmanaged resources used by this <see cref="BroString"/> object and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!m_disposed)
            {
                try
                {
                    BroApi.bro_string_cleanup(ref m_value);
                }
                finally
                {
                    m_disposed = true;  // Prevent duplicate dispose.
                }
            }
        }

        /// <summary>
        /// Determines whether the specified <see cref="Object"/> is equal to the current <see cref="BroString"/>.
        /// </summary>
        /// <returns>
        /// <c>true</c> if the specified object is equal to the current object; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="obj">The object to compare with the current object. </param>
        public override bool Equals(object obj)
        {
            string nativeStr = obj as string;

            if ((object)nativeStr != null)
                return Equals(nativeStr);

            BroString broString = obj as BroString;

            return (object)broString != null && Equals(broString);
        }

        /// <summary>
        /// Indicates whether the current <see cref="BroString"/> is equal to another <see cref="BroString"/>.
        /// </summary>
        /// <returns>
        /// <c>true</c> if this <see cref="BroString"/> is equal to the <paramref name="other"/> <see cref="BroString"/>; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="other">A <see cref="BroString"/> to compare with this <see cref="BroString"/>.</param>
        public bool Equals(BroString other)
        {
            if ((object)other == null)
                return false;

            if (ReferenceEquals(this, other))
                return true;

            // Compare string values for Bro strings
            return string.Compare(ToString(), other.ToString(), StringComparison.Ordinal) == 0;
        }

        /// <summary>
        /// Gets a hash code for this <see cref="BroString"/>. 
        /// </summary>
        /// <returns>
        /// A hash code for the current <see cref="BroString"/>.
        /// </returns>
        public override int GetHashCode()
        {
            return ToString().GetHashCode();
        }

        /// <summary>
        /// Returns this <see cref="BroString"/> as .NET <see cref="string"/>.
        /// </summary>
        /// <returns>
        /// This <see cref="BroString"/> as .NET <see cref="string"/>.
        /// </returns>
        public unsafe override string ToString()
        {
            return new string(BroApi.bro_string_get_data(ref m_value), 0, Length);
        }

        // Get Bro string structure value
        internal bro_string GetValue()
        {
            return m_value;
        }

        #endregion

        #region [ Operators ]

        #region [ Equality Operators ]

        /// <summary>
        /// Equality operator for <see cref="BroString"/>.
        /// </summary>
        /// <param name="left">Left <see cref="BroString"/> operand to test for equality.</param>
        /// <param name="right">Right <see cref="BroString"/> operand to test for equality.</param>
        /// <returns><c>true</c> if <paramref name="left"/> parameter is equal to <paramref name="right"/> parameter; otherwise, <c>false</c>.</returns>
        public static bool operator ==(BroString left, BroString right)
        {
            if ((object)left == null && (object)right == null)
                return true;

            if ((object)left == null || (object)right == null)
                return false;

            return left.Equals(right);
        }

        /// <summary>
        /// Inequality operator for <see cref="BroString"/>.
        /// </summary>
        /// <param name="left">Left <see cref="BroString"/> operand to test for inequality.</param>
        /// <param name="right">Right <see cref="BroString"/> operand to test for inequality.</param>
        /// <returns><c>true</c> if <paramref name="left"/> parameter is equal to <paramref name="right"/> parameter; otherwise, <c>false</c>.</returns>
        public static bool operator !=(BroString left, BroString right)
        {
            return !(left == right);
        }

        #endregion

        #region [ Implicit BroString <=> string Conversions ]

        /// <summary>
        /// Implicitly converts <see cref="string"/> value to a <see cref="BroString"/>.
        /// </summary>
        /// <param name="value">A <see cref="string"/> value.</param>
        /// <returns>A <see cref="BroString"/> object.</returns>
        public static implicit operator BroString(string value)
        {
            return new BroString(value);
        }

        /// <summary>
        /// Implicitly converts <see cref="BroString"/> to a <see cref="string"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroString"/> object.</param>
        /// <returns>A <see cref="string"/> value.</returns>
        public static implicit operator string(BroString value)
        {
            return (object)value == null ? null : value.ToString();
        }

        #endregion

        #endregion
    }
}