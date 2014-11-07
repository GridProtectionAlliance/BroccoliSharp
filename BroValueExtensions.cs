//******************************************************************************************************
//  BroValueExtensions.cs - Gbtc
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
using System.Linq;

namespace BroccoliSharp
{
    /// <summary>
    /// Defines extension functions for the <see cref="BroValue"/> interface.
    /// </summary>
    public static class BroValueExtensions
    {
        /// <summary>
        /// Attempts to get a new <see cref="BroValue"/> based on the provided <paramref name="value"/> converted to the specified <paramref name="type"/>.
        /// </summary>
        /// <param name="value"><see cref="BroValue"/> to convert.</param>
        /// <param name="type"><see cref="BroType"/> to convert to.</param>
        /// <returns><see cref="BroValue"/> converted to <paramref name="type"/> if successful; otherwise, <c>null</c>.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="value"/> is <c>null</c>.</exception>
        public static BroValue ConvertToType(this BroValue value, BroType type)
        {
            if ((object)value == null)
                throw new ArgumentNullException("value");

            if (value.Type == type)
                return value;

            switch (value.Type)
            {
                case BroType.Bool:
                    return ConvertIntToType(value.GetValueAsInt(), type);
                case BroType.Int:
                case BroType.Count:
                case BroType.Counter:
                case BroType.Enum:
                    return ConvertULongToType(value.GetValueAsULong(), type);
                case BroType.Double:
                case BroType.Time:
                case BroType.Interval:
                    return ConvertDoubleToType(value.GetValueAsDouble(), type);
                case BroType.Port:
                    return ConvertBroPortToType(value.GetValueAsBroPort(), type);
                case BroType.IpAddr:
                    return ConvertBroAddressToType(value.GetValueAsBroAddress(), type);
                case BroType.Subnet:
                    return ConvertBroSubnetToType(value.GetValueAsBroSubnet(), type);
                case BroType.String:
                    return ConvertBroStringToType(value.Value as BroString, type);
                case BroType.Table:
                    return ConvertBroTableToType(value.Value as BroTable, type);
                case BroType.List:
                case BroType.Record:
                    return ConvertBroRecordToType(value.Value as BroRecord, type);
                case BroType.Vector:
                    return ConvertBroVectorToType(value.Value as BroVector, type);
                case BroType.Set:
                    return ConvertBroSetToType(value.Value as BroSet, type);
            }

            return null;
        }

        private static BroValue ConvertIntToType(int value, BroType type)
        {
            switch (type)
            {
                case BroType.Int:
                case BroType.Count:
                case BroType.Counter:
                case BroType.Enum:
                    return new BroValue(Convert.ToUInt64(value), type);
                case BroType.Double:
                case BroType.Time:
                case BroType.Interval:
                    return new BroValue(Convert.ToDouble(value), type);
                case BroType.String:
                    return new BroValue(value.ToString(), type);
            }

            return null;
        }

        private static BroValue ConvertULongToType(ulong value, BroType type)
        {
            switch (type)
            {
                case BroType.Bool:
                    return new BroValue(Convert.ToInt32(value) == 0 ? 0 : ~0, type);
                case BroType.Int:
                case BroType.Count:
                case BroType.Counter:
                case BroType.Enum:
                    return new BroValue(value, type);
                case BroType.Double:
                case BroType.Time:
                case BroType.Interval:
                    return new BroValue(Convert.ToDouble(value), type);
                case BroType.String:
                    return new BroValue(value.ToString(), type);
            }

            return null;
        }

        private static BroValue ConvertDoubleToType(double value, BroType type)
        {
            switch (type)
            {
                case BroType.Bool:
                    return new BroValue(Convert.ToInt32(value) == 0 ? 0 : ~0, type);
                case BroType.Int:
                case BroType.Count:
                case BroType.Counter:
                case BroType.Enum:
                    return new BroValue(Convert.ToUInt64(value), type);
                case BroType.Double:
                case BroType.Time:
                case BroType.Interval:
                    return new BroValue(value, type);
                case BroType.String:
                    return new BroValue(value.ToString(), type);
            }

            return null;
        }

        private static BroValue ConvertBroStringToType(BroString value, BroType type)
        {
            string str = value;

            if ((object)str != null)
            {
                switch (type)
                {
                    case BroType.Bool:
                        int parsedInt;

                        if (int.TryParse(str, out parsedInt))
                            return new BroValue(parsedInt == 0 ? 0 : ~0, type);

                        bool parsedBool;

                        if (bool.TryParse(str, out parsedBool))
                            return new BroValue(parsedBool ? ~0 : 0, type);

                        break;
                    case BroType.Int:
                    case BroType.Count:
                    case BroType.Counter:
                    case BroType.Enum:
                        ulong parsedULong;

                        if (ulong.TryParse(str, out parsedULong))
                            return new BroValue(parsedULong, type);

                        break;
                    case BroType.Double:
                    case BroType.Time:
                    case BroType.Interval:
                        double parsedDouble;

                        if (double.TryParse(str, out parsedDouble))
                            return new BroValue(parsedDouble, type);

                        break;
                    case BroType.IpAddr:
                        return new BroValue(new BroAddress(str), type);
                }
            }

            return null;
        }

        private static BroValue ConvertBroPortToType(BroPort value, BroType type)
        {
            ulong number = value.Number;

            switch (type)
            {
                case BroType.Bool:
                    return new BroValue(Convert.ToInt32(number) == 0 ? 0 : ~0, type);
                case BroType.Int:
                case BroType.Count:
                case BroType.Counter:
                case BroType.Enum:
                    return new BroValue(number, type);
                case BroType.Double:
                case BroType.Time:
                case BroType.Interval:
                    return new BroValue(Convert.ToDouble(number), type);
                case BroType.String:
                    return new BroValue(value.ToString(), type);
            }

            return null;
        }

        private static BroValue ConvertBroAddressToType(BroAddress value, BroType type)
        {
            if (type == BroType.String)
                return new BroValue(value.ToString(), type);

            return null;
        }

        private static BroValue ConvertBroSubnetToType(BroSubnet value, BroType type)
        {
            switch (type)
            {
                case BroType.String:
                    return new BroValue(value.ToString(), type);
                case BroType.IpAddr:
                    return new BroValue((BroAddress)value, type);
            }

            return null;
        }

        private static BroValue ConvertBroTableToType(BroTable value, BroType type)
        {
            if ((object)value != null && type == BroType.Set)
                return new BroValue((BroSet)value, type);

            return null;
        }

        private static BroValue ConvertBroRecordToType(BroRecord value, BroType type)
        {
            if ((object)value != null)
            {
                switch (type)
                {
                    case BroType.List:
                    case BroType.Record:
                        return new BroValue(value, type);
                    case BroType.Vector:
                        return new BroValue(new BroVector(value), type);
                    case BroType.Set:
                        return new BroValue(new BroSet(value), type);
                }
            }

            return null;
        }

        private static BroValue ConvertBroVectorToType(BroVector value, BroType type)
        {
            if ((object)value != null)
            {
                switch (type)
                {
                    case BroType.List:
                    case BroType.Record:
                        return new BroValue(new BroRecord(value.Select(val => new BroField(val))), type);
                    case BroType.Set:
                        return new BroValue(new BroSet(value), type);
                }
            }

            return null;
        }

        private static BroValue ConvertBroSetToType(BroSet value, BroType type)
        {
            if ((object)value != null)
            {
                switch (type)
                {
                    case BroType.List:
                    case BroType.Record:
                        return new BroValue(new BroRecord(value.Select(val => new BroField(val))), type);
                    case BroType.Vector:
                        return new BroValue(new BroVector(value), type);
                }
            }

            return null;
        }
    }
}
