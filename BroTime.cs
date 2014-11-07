//******************************************************************************************************
//  BroTime.cs - Gbtc
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
using System.Globalization;
using BroccoliSharp.Internal;

namespace BroccoliSharp
{
    /// <summary>
    /// Represents an immutable Bro time value. Implicitly castable as a <see cref="double"/> and a <see cref="DateTime"/>.
    /// </summary>
    public struct BroTime
    {
        #region [ Members ]

        // Fields
        private readonly double m_value;

        #endregion

        #region [ Constructors ]

        /// <summary>
        /// Creates a new <see cref="BroTime"/> from an existing <see cref="double"/> <paramref name="value"/>.
        /// </summary>
        /// <param name="value">Bro time value.</param>
        public BroTime(double value)
        {
            m_value = value;
        }

        /// <summary>
        /// Creates a new <see cref="BroTime"/> from an existing <see cref="DateTime"/> <paramref name="value"/>.
        /// </summary>
        /// <param name="value">Date-time value.</param>
        public BroTime(DateTime value)
        {
            m_value = (value.ToUniversalTime() - Epoch).TotalSeconds;
        }

        #endregion

        #region [ Properties ]

        /// <summary>
        /// Gets <see cref="BroTime"/> value.
        /// </summary>
        public double Value
        {
            get
            {
                return m_value;
            }
        }

        #endregion

        #region [ Methods ]

        /// <summary>
        /// Converts <see cref="BroTime"/> to a .NET <see cref="DateTime"/>.
        /// </summary>
        /// <returns>This <see cref="BroTime"/> as a .NET <see cref="DateTime"/>.</returns>
        public DateTime ToDateTime()
        {
            return Epoch.AddSeconds(m_value);
        }

        /// <summary>
        /// Returns a string that represents this <see cref="BroTime"/>.
        /// </summary>
        /// <returns>
        /// A string that represents this <see cref="BroTime"/>.
        /// </returns>
        public override string ToString()
        {
            return ToDateTime().ToString();
        }

        /// <summary>
        /// Returns a string that represents this <see cref="BroTime"/> using the specified <paramref name="format"/>.
        /// </summary>
        /// <returns>
        /// A string representation this <see cref="BroTime"/> value as specified by <paramref name="format"/>.
        /// </returns>
        /// <param name="format">A <see cref="DateTime"/> format string.</param>
        /// <exception cref="FormatException">
        /// The length of <paramref name="format"/> is 1, and it is not one of the format specifier characters defined for <see cref="DateTimeFormatInfo"/> -or-
        ///<paramref name="format"/> does not contain a valid custom format pattern.
        ///</exception>
        public string ToString(string format)
        {
            return ToDateTime().ToString(format);
        }

        // Converts Bro time to a timeval structure
        internal timeval ToTimeVal()
        {
            DateTime value = ToDateTime();
            timeval ts = new timeval();

            double seconds = (value - Epoch).TotalSeconds;
            double wholeSeconds = Math.Truncate(seconds);

            ts.tv_sec = (uint)wholeSeconds;
            ts.tv_usec = (uint)((seconds - wholeSeconds) * 1000000.0D);

            return ts;
        }

        #endregion

        #region [ Operators ]

        /// <summary>
        /// Implicitly converts <see cref="double"/> value to a <see cref="BroTime"/>.
        /// </summary>
        /// <param name="value">A <see cref="double"/> value.</param>
        /// <returns>A <see cref="BroTime"/> object.</returns>
        public static implicit operator BroTime(double value)
        {
            return new BroTime(value);
        }

        /// <summary>
        /// Implicitly converts <see cref="BroTime"/> to a <see cref="double"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroTime"/> object.</param>
        /// <returns>A <see cref="double"/> value.</returns>
        public static implicit operator double(BroTime value)
        {
            return value.m_value;
        }

        /// <summary>
        /// Implicitly converts <see cref="DateTime"/> value to a <see cref="BroTime"/>.
        /// </summary>
        /// <param name="value">A <see cref="DateTime"/> value.</param>
        /// <returns>A <see cref="BroTime"/> object.</returns>
        public static implicit operator BroTime(DateTime value)
        {
            return new BroTime(value);
        }

        /// <summary>
        /// Implicitly converts <see cref="BroTime"/> to a <see cref="DateTime"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroTime"/> object.</param>
        /// <returns>A <see cref="DateTime"/> value.</returns>
        public static implicit operator DateTime(BroTime value)
        {
            return value.ToDateTime();
        }

        #endregion

        #region [ Static ]

        // Static Fields

        /// <summary>
        /// Date-time representing 1/1/1970 UTC.
        /// </summary>
        public static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        // Static Properties

        /// <summary>
        /// Gets current time, in UTC, as a <see cref="BroTime"/> value.
        /// </summary>
        public static BroTime Now
        {
            get
            {
                return new BroTime(DateTime.UtcNow);
            }
        }

        #endregion
    }
}
