//******************************************************************************************************
//  BroTable.cs - Gbtc
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
using System.Collections;
using System.Collections.Generic;
using BroccoliSharp.Internal;

namespace BroccoliSharp
{
    /// <summary>
    /// Represents a Bro table implemented as an <see cref="IDictionary{TKey, TValue}">IDictionary&lt;BroValue, BroValue&gt;</see>.
    /// </summary>
    /// <include file='Documentation\BroTable.xml' path='/doc/*'/>
    public class BroTable : IDictionary<BroValue, BroValue>, IDisposable
    {
        #region [ Members ]

        // Fields
        private IntPtr m_table;
        private bool m_disposed;

        #endregion

        #region [ Constructors ]

        /// <summary>
        /// Creates a new <see cref="BroTable"/>/
        /// </summary>
        /// <exception cref="OutOfMemoryException">Failed to create Bro table.</exception>
        public BroTable()
        {
            m_table = BroApi.bro_table_new();

            if (m_table == IntPtr.Zero)
                throw new OutOfMemoryException("Failed to create Bro table.");
        }

        /// <summary>
        /// Creates a new <see cref="BroTable"/> from an existing dictionary of <see cref="BroValue"/> items.
        /// </summary>
        /// <param name="values">Dictionary of <see cref="BroValue"/> items.</param>
        /// <remarks>
        /// First item in <paramref name="values"/> will determine key and value type for the table.
        /// If other items do not have the same key and value type as the first item, they will not be added.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="values"/> is <c>null</c>.</exception>
        /// <exception cref="OutOfMemoryException">Failed to create Bro table.</exception>
        public BroTable(IDictionary<BroValue, BroValue> values)
            : this()
        {
            if ((object)values == null)
                throw new ArgumentNullException("values");

            foreach (KeyValuePair<BroValue, BroValue> pair in values)
                Add(pair.Key, pair.Value);
        }

        // Create a new BroTable from an existing source table - have to clone source table since we don't own it
        internal BroTable(IntPtr sourceTable)
            : this()
        {
            if (sourceTable == IntPtr.Zero)
                return;

            BroType keyType = BroType.Unknown;
            BroType valueType = BroType.Unknown;

            BroApi.bro_table_get_types(sourceTable, ref keyType, ref valueType);

            BroApi.bro_table_foreach(sourceTable,
                (key, value, userData) =>
                {
                    try
                    {
                        BroApi.bro_table_insert(m_table, keyType, key, valueType, value);
                        return ~0;
                    }
                    catch
                    {
                        return 0;
                    }
                },
                IntPtr.Zero);
        }

        /// <summary>
        /// Releases the unmanaged resources before this <see cref="BroTable"/> object is reclaimed by <see cref="GC"/>.
        /// </summary>
        ~BroTable()
        {
            Dispose(false);
        }

        #endregion

        #region [ Properties ]

        /// <summary>
        /// Gets or sets the <see cref="BroValue"/> with the specified <paramref name="key"/> of <paramref name="keyType"/>.
        /// </summary>
        /// <param name="key">The <see cref="BroValue"/> key of the element to get or set.</param>
        /// <param name="keyType">The <see cref="BroType"/> of the <paramref name="key"/>.</param>
        /// <param name="keyTypeName">Optional name of specialized type of <paramref name="key"/>.</param>
        /// <returns>
        /// The <see cref="BroValue"/> with the specified <paramref name="key"/> if successful; otherwise, <c>null</c>.
        /// </returns>
        /// <exception cref="ArgumentNullException"><paramref name="value"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot get or add key/value pair, <see cref="BroTable"/> is disposed.</exception>
        /// <exception cref="InvalidOperationException">Failed to add <see cref="BroValue"/> for the specified <paramref name="key"/>.</exception>
        public BroValue this[object key, BroType keyType, string keyTypeName = null]
        {
            get
            {
                return this[new BroValue(key, keyType, keyTypeName)];
            }
            set
            {
                if (!Add(new BroValue(key, keyType, keyTypeName), value))
                    throw new InvalidOperationException(string.Format("Failed to add value for key \"{0}\".", key));
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="BroValue"/> with the specified <paramref name="key"/>.
        /// </summary>
        /// <param name="key">The <see cref="BroValue"/> key of the element to get or set.</param>
        /// <returns>
        /// The <see cref="BroValue"/> with the specified <paramref name="key"/> if successful; otherwise, <c>null</c>.
        /// </returns>
        /// <exception cref="ArgumentNullException"><paramref name="key"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="value"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot get or add key/value pair, <see cref="BroTable"/> is disposed.</exception>
        /// <exception cref="InvalidOperationException">Failed to add <see cref="BroValue"/> for the specified <paramref name="key"/>.</exception>
        public BroValue this[BroValue key]
        {
            get
            {
                if ((object)key == null)
                    throw new ArgumentNullException("key");

                if (m_table == IntPtr.Zero)
                    throw new ObjectDisposedException(string.Format("Cannot get value for key \"{0}\", Bro table is disposed.", key));

                IntPtr valuePtr = key.ExecuteWithFixedPtr(keyPtr => BroApi.bro_table_find(m_table, keyPtr));

                return BroValue.CreateFromPtr(valuePtr, ValueType);
            }
            set
            {
                if (!Add(key, value))
                    throw new InvalidOperationException(string.Format("Failed to add value for key \"{0}\".", key));
            }
        }

        /// <summary>
        /// Gets the <see cref="BroType"/> for keys of this <see cref="BroTable"/>.
        /// </summary>
        /// <remarks>
        /// First item added to the table will determine the key type for all subsequent key/value pairs.
        /// </remarks>
        public BroType KeyType
        {
            get
            {
                BroType keyType = BroType.Unknown;
                BroType valueType = BroType.Unknown;

                BroApi.bro_table_get_types(m_table, ref keyType, ref valueType);

                return keyType;
            }
        }

        /// <summary>
        /// Gets the <see cref="BroType"/> for values of this <see cref="BroTable"/>.
        /// </summary>
        /// <remarks>
        /// First item added to the table will determine the value type for all subsequent key/value pairs.
        /// </remarks>
        public BroType ValueType
        {
            get
            {
                BroType keyType = BroType.Unknown;
                BroType valueType = BroType.Unknown;

                BroApi.bro_table_get_types(m_table, ref keyType, ref valueType);

                return valueType;
            }
        }

        /// <summary>
        /// Gets the number of elements contained in this <see cref="BroTable"/>.
        /// </summary>
        /// <returns>
        /// The number of elements contained in this <see cref="BroTable"/>.
        /// </returns>
        public int Count
        {
            get
            {
                if (m_table != IntPtr.Zero)
                    return BroApi.bro_table_get_size(m_table);

                return 0;
            }
        }

        /// <summary>
        /// Gets a value indicating whether this <see cref="BroTable"/> is read-only.
        /// </summary>
        /// <returns>
        /// <c>true</c> if this <see cref="BroTable"/> is read-only; otherwise, <c>false</c>.
        /// </returns>
        /// <remarks>
        /// This always returns <c>false</c> for a <see cref="BroTable"/>.
        /// </remarks>>
        public bool IsReadOnly
        {
            get
            {
                return false;
            }
        }

        /// <summary>
        /// Gets an <see cref="ICollection{BroValue}"/> containing the keys of this <see cref="BroTable"/>.
        /// </summary>
        /// <returns>
        /// An <see cref="ICollection{BroValue}"/> containing the keys this <see cref="BroTable"/>.
        /// </returns>
        /// <exception cref="ObjectDisposedException">Cannot execute dictionary operation, <see cref="BroTable"/> is disposed.</exception>
        public ICollection<BroValue> Keys
        {
            get
            {
                return GetDictionary().Keys;
            }
        }

        /// <summary>
        /// Gets an <see cref="ICollection{BroValue}"/> containing the values of this <see cref="BroTable"/>.
        /// </summary>
        /// <returns>
        /// An <see cref="ICollection{BroValue}"/> containing the values this <see cref="BroTable"/>.
        /// </returns>
        /// <exception cref="ObjectDisposedException">Cannot execute dictionary operation, <see cref="BroTable"/> is disposed.</exception>
        public ICollection<BroValue> Values
        {
            get
            {
                return GetDictionary().Values;
            }
        }

        #endregion

        #region [ Methods ]

        /// <summary>
        /// Releases all the resources used by this <see cref="BroTable"/> object.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases the unmanaged resources used by this <see cref="BroTable"/> object and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!m_disposed)
            {
                try
                {
                    if (m_table != IntPtr.Zero)
                    {
                        BroApi.bro_table_free(m_table);
                        m_table = IntPtr.Zero;
                    }
                }
                finally
                {
                    m_disposed = true;  // Prevent duplicate dispose.
                }
            }
        }

        /// <summary>
        /// Adds an element with the provided <paramref name="key"/> of <paramref name="keyType"/> and 
        /// <paramref name="value"/> of <paramref name="valueType"/> to this <see cref="BroTable"/>.
        /// </summary>
        /// <param name="key">The key of the element to add.</param>
        /// <param name="keyType">The <see cref="BroType"/> of the <paramref name="key"/>.</param>
        /// <param name="value">The value of the element to add.</param>
        /// <param name="valueType">The <see cref="BroType"/> of the <paramref name="value"/>.</param>
        /// <param name="keyTypeName">Optional name of specialized type of <paramref name="key"/>.</param>
        /// <param name="valueTypeName">Optional name of specialized type of <paramref name="value"/>.</param>
        /// <returns><c>true</c> if successful; otherwise, <c>false</c>.</returns>
        /// <remarks>
        /// First item added to the table will determine the key and value type for all subsequent key/value pairs.
        /// Any key/value pairs attempted to be added that do not have the same types as the first key/value pair
        /// will fail to insert into the table.
        /// </remarks>
        /// <exception cref="ObjectDisposedException">Cannot add key/value pair, <see cref="BroTable"/> is disposed.</exception>
        public bool Add(object key, BroType keyType, object value, BroType valueType, string keyTypeName = null, string valueTypeName = null)
        {
            return Add(new BroValue(key, keyType, keyTypeName), new BroValue(value, valueType, valueTypeName));
        }

        /// <summary>
        /// Adds an element with the provided <paramref name="key"/> and <paramref name="value"/> to this <see cref="BroTable"/>.
        /// </summary>
        /// <param name="key">The <see cref="BroValue"/> to use as the key of the element to add.</param>
        /// <param name="value">The <see cref="BroValue"/> to use as the value of the element to add.</param>
        /// <returns><c>true</c> if successful; otherwise, <c>false</c>.</returns>
        /// <remarks>
        /// First item added to the table will determine the key and value type for all subsequent key/value pairs.
        /// Any key/value pairs attempted to be added that do not have the same types as the first key/value pair
        /// will fail to insert into the table.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="key"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="value"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot add key/value pair, <see cref="BroTable"/> is disposed.</exception>
        public bool Add(BroValue key, BroValue value)
        {
            if ((object)key == null)
                throw new ArgumentNullException("key");

            if ((object)value == null)
                throw new ArgumentNullException("value");

            if (m_table == IntPtr.Zero)
                throw new ObjectDisposedException("Cannot add key/value pair, Bro table is disposed.");

            return key.ExecuteWithFixedPtr(keyPtr => value.ExecuteWithFixedPtr(valuePtr => BroApi.bro_table_insert(m_table, key.Type, keyPtr, value.Type, valuePtr) != 0));
        }

        // Interface for dictionary returns no value
        void IDictionary<BroValue, BroValue>.Add(BroValue key, BroValue value)
        {
            Add(key, value);
        }

        /// <summary>
        /// Adds a key/value <paramref name="pair"/> to this <see cref="BroTable"/>.
        /// </summary>
        /// <param name="pair">The key/value pair to add to this <see cref="BroTable"/>.</param>
        /// <remarks>
        /// First item added to the table will determine the key and value type for all subsequent key/value pairs.
        /// Any key/value pairs attempted to be added that do not have the same types as the first key/value pair
        /// will fail to insert into the table.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="pair"/>.Key is <c>null</c>.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="pair"/>.Value is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot add key/value pair, <see cref="BroTable"/> is disposed.</exception>
        public void Add(KeyValuePair<BroValue, BroValue> pair)
        {
            Add(pair.Key, pair.Value);
        }

        /// <summary>
        /// Gets a clone of this <see cref="BroTable"/>.
        /// </summary>
        /// <returns>Clone of this <see cref="BroTable"/>.</returns>
        /// <exception cref="ObjectDisposedException">Cannot clone, <see cref="BroTable"/> is disposed.</exception>
        public BroTable Clone()
        {
            if (m_table == IntPtr.Zero)
                throw new ObjectDisposedException("Cannot clone, Bro table is disposed.");

            return new BroTable(m_table);
        }

        /// <summary>
        /// Removes all items from this <see cref="BroTable"/>.
        /// </summary>
        /// <exception cref="ObjectDisposedException">Cannot clear, <see cref="BroTable"/> is disposed.</exception>
        public void Clear()
        {
            if (m_table == IntPtr.Zero)
                throw new ObjectDisposedException("Cannot clear items, Bro table is disposed.");

            BroApi.bro_table_free(m_table);
            m_table = BroApi.bro_table_new();
        }

        /// <summary>
        /// Determines whether this <see cref="BroTable"/> contains specified key/value <paramref name="pair"/>.
        /// </summary>
        /// <param name="pair">The key/value pair to locate in this <see cref="BroTable"/>.</param>
        /// <returns>
        /// <c>true</c> if key/value <paramref name="pair"/> is found in this <see cref="BroTable"/>; otherwise, <c>false</c>.
        /// </returns>
        /// <remarks>
        /// <para>
        /// This function looks for an exact match of both the key and the value using a linear search. If you simply
        /// want to know if the table contains a key, use the optimal <see cref="ContainsKey(BroValue)"/> function instead.
        /// </para>
        /// <para>
        /// This method performs a linear search - an O(n) operation where n is <see cref="Count"/>.
        /// </para>
        /// </remarks>
        /// <exception cref="ObjectDisposedException">Cannot execute dictionary operation, <see cref="BroTable"/> is disposed.</exception>
        public bool Contains(KeyValuePair<BroValue, BroValue> pair)
        {
            if ((object)pair == null)
                throw new ArgumentNullException("pair");

            foreach (KeyValuePair<BroValue, BroValue> tablePair in this)
            {
                if (tablePair.Key == pair.Key && tablePair.Value == pair.Value)
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Determines whether this <see cref="BroTable"/> contains specified <paramref name="key"/> of <paramref name="keyType"/>.
        /// </summary>
        /// <param name="key">The key to locate in this <see cref="BroTable"/>.</param>
        /// <param name="keyType">The <see cref="BroType"/> of the <paramref name="key"/>.</param>
        /// <param name="keyTypeName">Optional name of specialized type of <paramref name="key"/>.</param>
        /// <returns>
        /// <c>true</c> if <paramref name="key"/> is found in this <see cref="BroTable"/>; otherwise, <c>false</c>.
        /// </returns>
        /// <exception cref="ObjectDisposedException">Cannot execute contains, <see cref="BroTable"/> is disposed.</exception>
        public bool ContainsKey(object key, BroType keyType, string keyTypeName = null)
        {
            return ContainsKey(new BroValue(key, keyType, keyTypeName));
        }

        /// <summary>
        /// Determines whether this <see cref="BroTable"/> contains specified <paramref name="key"/>.
        /// </summary>
        /// <param name="key">The <see cref="BroValue"/> to locate in this <see cref="BroTable"/>.</param>
        /// <returns>
        /// <c>true</c> if <paramref name="key"/> is found in this <see cref="BroTable"/>; otherwise, <c>false</c>.
        /// </returns>
        /// <exception cref="ObjectDisposedException">Cannot execute contains, <see cref="BroTable"/> is disposed.</exception>
        public bool ContainsKey(BroValue key)
        {
            if ((object)key == null)
                throw new ArgumentNullException("key");

            if (m_table == IntPtr.Zero)
                throw new ObjectDisposedException("Cannot execute contains, Bro table is disposed.");

            return key.ExecuteWithFixedPtr(ptr => BroApi.bro_table_find(m_table, ptr) != IntPtr.Zero);
        }

        /// <summary>
        /// Copies the elements of this <see cref="BroTable"/> to an <see cref="Array"/>, starting at a particular <see cref="Array"/> index.
        /// </summary>
        /// <param name="array">The one-dimensional <see cref="Array"/> that is the destination of the elements copied from <see cref="BroTable"/>. The <see cref="Array"/> must have zero-based indexing.</param>
        /// <param name="arrayIndex">The zero-based index in <paramref name="array"/> at which copying begins.</param>
        /// <exception cref="ArgumentNullException"><paramref name="array"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="arrayIndex"/> is less than 0.</exception>
        /// <exception cref="ArgumentException">The number of elements in the source <see cref="BroTable"/> is greater than the available space from <paramref name="arrayIndex"/> to the end of the destination <paramref name="array"/>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot copy to array, <see cref="BroTable"/> is disposed.</exception>
        public void CopyTo(KeyValuePair<BroValue, BroValue>[] array, int arrayIndex)
        {
            if ((object)array == null)
                throw new ArgumentNullException("array");

            if (arrayIndex < 0)
                throw new ArgumentOutOfRangeException("arrayIndex");

            if (Count > array.Length - arrayIndex)
                throw new ArgumentException("Not enough available space in destination array starting from specified array index to hold all source elements.");

            if (m_table == IntPtr.Zero)
                throw new ObjectDisposedException("Cannot copy to array, Bro table is disposed.");

            BroType keyType = BroType.Unknown;
            BroType valueType = BroType.Unknown;
            int i = 0;

            BroApi.bro_table_get_types(m_table, ref keyType, ref valueType);

            BroApi.bro_table_foreach(m_table,
                (key, value, userData) =>
                {
                    try
                    {
                        array[arrayIndex + i++] = new KeyValuePair<BroValue, BroValue>(BroValue.CreateFromPtr(key, keyType), BroValue.CreateFromPtr(value, valueType));
                        return ~0;
                    }
                    catch
                    {
                        return 0;
                    }
                },
                IntPtr.Zero);
        }

        /// <summary>
        /// Returns an enumerator that iterates through the collection.
        /// </summary>
        /// <returns>
        /// A <see cref="IEnumerator{T}"/> that can be used to iterate through the collection.
        /// </returns>
        /// <exception cref="ObjectDisposedException">Cannot execute dictionary operation, <see cref="BroTable"/> is disposed.</exception>
        public IEnumerator<KeyValuePair<BroValue, BroValue>> GetEnumerator()
        {
            foreach (KeyValuePair<BroValue, BroValue> pair in GetDictionary())
                yield return pair;
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        /// <summary>
        /// Removes the element with the specified <paramref name="key"/> from this <see cref="BroTable"/>.
        /// </summary>
        /// <param name="key">The key of the element to remove.</param>
        /// <returns>
        /// <c>true</c> if the element is successfully removed; otherwise, <c>false</c>.
        /// This method also returns <c>false</c> if <paramref name="key"/> was not found in <see cref="BroTable"/>.
        /// </returns>
        /// <remarks>
        /// This is not a native Bro table operation. Function will perform expected task, but for large data sets operation may be expensive.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="key"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot execute dictionary operation, <see cref="BroTable"/> is disposed.</exception>
        public bool Remove(BroValue key)
        {
            return ExecuteCloneOperation(dictionary => dictionary.Remove(key));
        }

        bool ICollection<KeyValuePair<BroValue, BroValue>>.Remove(KeyValuePair<BroValue, BroValue> pair)
        {
            return ExecuteCloneOperation(dictionary => ((IDictionary<BroValue, BroValue>)dictionary).Remove(pair));
        }

        /// <summary>
        /// Gets the <see cref="BroValue"/> associated with the specified <paramref name="key"/> of <paramref name="keyType"/>.
        /// </summary>
        /// <param name="key">The key whose value to get.</param>
        /// <param name="keyType">The <see cref="BroType"/> of the <paramref name="key"/>.</param>
        /// <param name="value">When method returns, the <see cref="BroValue"/> associated with the specified <paramref name="key"/>, if the key is found; otherwise, <c>null</c>. This parameter is passed uninitialized.</param>
        /// <param name="keyTypeName">Optional name of specialized type of <paramref name="key"/>.</param>
        /// <returns>
        /// <c>true</c> if this <see cref="BroTable"/> contains an element with the specified <paramref name="key"/>; otherwise, <c>false</c>.
        /// </returns>
        /// <exception cref="ObjectDisposedException">Cannot attempt to get value, <see cref="BroTable"/> is disposed.</exception>
        public bool TryGetValue(object key, BroType keyType, out BroValue value, string keyTypeName = null)
        {
            return TryGetValue(new BroValue(key, keyType, keyTypeName), out value);
        }

        /// <summary>
        /// Gets the <see cref="BroValue"/> associated with the specified <paramref name="key"/>.
        /// </summary>
        /// <param name="key">The <see cref="BroValue"/> key whose value to get.</param>
        /// <param name="value">When method returns, the <see cref="BroValue"/> associated with the specified <paramref name="key"/>, if the key is found; otherwise, <c>null</c>. This parameter is passed uninitialized.</param>
        /// <returns>
        /// <c>true</c> if this <see cref="BroTable"/> contains an element with the specified <paramref name="key"/>; otherwise, <c>false</c>.
        /// </returns>
        /// <exception cref="ArgumentNullException"><paramref name="key"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot attempt to get value, <see cref="BroTable"/> is disposed.</exception>
        public bool TryGetValue(BroValue key, out BroValue value)
        {
            return (object)(value = this[key]) != null;
        }

        private T ExecuteCloneOperation<T>(Func<Dictionary<BroValue, BroValue>, T> operation)
        {
            // Copy the Bro table items into a new Dictionary<Key, Value> data structure
            Dictionary<BroValue, BroValue> dictionary = GetDictionary();

            // Execute operation (with return value) on the dictionary
            T result = operation(dictionary);

            // Clear the items in the Bro table
            Clear();

            // Add the items back to the Bro table
            foreach (KeyValuePair<BroValue, BroValue> pair in dictionary)
                Add(pair.Key, pair.Value);

            return result;
        }

        // Gets current table as a Dictionary<BroValue, BroValue>
        private Dictionary<BroValue, BroValue> GetDictionary()
        {
            if (m_table == IntPtr.Zero)
                throw new ObjectDisposedException("Cannot execute dictionary operation, Bro table is disposed.");

            Dictionary<BroValue, BroValue> dictionary = new Dictionary<BroValue, BroValue>();
            BroType keyType = BroType.Unknown;
            BroType valueType = BroType.Unknown;

            BroApi.bro_table_get_types(m_table, ref keyType, ref valueType);

            BroApi.bro_table_foreach(m_table,
                (key, value, userData) =>
                {
                    try
                    {
                        dictionary.Add(BroValue.CreateFromPtr(key, keyType), BroValue.CreateFromPtr(value, valueType));
                        return ~0;
                    }
                    catch
                    {
                        return 0;
                    }
                },
                IntPtr.Zero);

            return dictionary;
        }

        // Get pointer to Bro table
        internal IntPtr GetValuePtr()
        {
            if (m_table == IntPtr.Zero)
                throw new ObjectDisposedException("Cannot get value pointer, Bro table is disposed.");

            return m_table;
        }

        #endregion

        #region [ Operators ]

        #region [ Implicit BroTable => BroSet Conversion ]

        /// <summary>
        /// Implicitly converts keys of a <see cref="BroTable"/> object to a <see cref="BroSet"/>.
        /// </summary>
        /// <param name="value">A <see cref="BroTable"/> object.</param>
        /// <returns>A <see cref="BroSet"/> object.</returns>
        public static implicit operator BroSet(BroTable value)
        {
            if ((object)value == null)
                return new BroSet();

            return new BroSet(value.Keys);
        }

        #endregion

        #endregion
    }
}
