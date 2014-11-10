//******************************************************************************************************
//  BroVector.cs - Gbtc
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
using System.Collections;
using System.Collections.Generic;
using BroccoliSharp.Internal;

namespace BroccoliSharp
{
    /// <summary>
    /// Represents a Bro vector implemented as an <see cref="IList{T}">IList&lt;BroValue&gt;</see>.
    /// </summary>
    /// <include file='Documentation\BroVector.xml' path='/doc/*'/>
    public class BroVector : IList<BroValue>, IDisposable
    {
        #region [ Members ]

        // Fields
        private BroVectorPtr m_vectorPtr;
        private bool m_disposed;

        #endregion

        #region [ Constructors ]

        /// <summary>
        /// Creates a new <see cref="BroVector"/>.
        /// </summary>
        /// <exception cref="OutOfMemoryException">Failed to create Bro vector.</exception>
        public BroVector()
        {
            m_vectorPtr = BroApi.bro_vector_new();

            if (m_vectorPtr.IsInvalid)
                throw new OutOfMemoryException("Failed to create Bro vector.");
        }

        /// <summary>
        /// Creates a new <see cref="BroVector"/> from an existing collection of <see cref="BroValue"/> items.
        /// </summary>
        /// <param name="values">Collection of <see cref="BroValue"/> items.</param>
        /// <exception cref="ArgumentNullException"><paramref name="values"/> is <c>null</c>.</exception>
        /// <exception cref="OutOfMemoryException">Failed to create Bro vector.</exception>
        public BroVector(IEnumerable<BroValue> values)
            : this()
        {
            if ((object)values == null)
                throw new ArgumentNullException("values");

            foreach (BroValue value in values)
                Add(value);
        }

        // Create new BroVector from an existing source vector - have to clone source vector since we don't own it
        internal BroVector(BroVectorPtr sourceVectorPtr)
            : this()
        {
            if (sourceVectorPtr.IsInvalid)
                return;

            int length = BroApi.bro_vector_get_length(sourceVectorPtr);

            for (int i = 0; i < length; i++)
            {
                BroType type = BroType.Unknown;
                IntPtr value = BroApi.bro_vector_get_nth_val(sourceVectorPtr, i, ref type);
                BroApi.bro_vector_add_val(m_vectorPtr, type, null, value);
            }
        }

        /// <summary>
        /// Releases the unmanaged resources before this <see cref="BroVector"/> object is reclaimed by <see cref="GC"/>.
        /// </summary>
        ~BroVector()
        {
            Dispose(false);
        }

        #endregion

        #region [ Properties ]

        /// <summary>
        /// Gets or sets the <see cref="BroValue"/> at the specified <paramref name="index"/>.
        /// </summary>
        /// <returns>
        /// The <see cref="BroValue"/> at the specified <paramref name="index"/>, or <c>null</c> if there was an issue retrieving value.
        /// </returns>
        /// <param name="index">The zero-based index of the element to get or set.</param>
        /// <exception cref="ObjectDisposedException">Cannot get or set <see cref="BroValue"/>, Bro vector is disposed.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="index"/> is not a valid index in this <see cref="BroVector"/>.</exception>
        /// <exception cref="ArgumentNullException">Cannot set a <c>null</c> <see cref="BroValue"/>.</exception>
        /// <exception cref="InvalidOperationException">Failed to update <see cref="BroValue"/> at <paramref name="index"/>.</exception>
        public BroValue this[int index]
        {
            get
            {
                if (m_vectorPtr.IsInvalid)
                    throw new ObjectDisposedException("Cannot get value, Bro vector is disposed.");

                if (index < 0 || index >= Count)
                    throw new ArgumentOutOfRangeException("index");

                BroType type = BroType.Unknown;
                IntPtr valuePtr = BroApi.bro_vector_get_nth_val(m_vectorPtr, index, ref type);

                return BroValue.CreateFromPtr(valuePtr, type);
            }
            set
            {
                if (m_vectorPtr.IsInvalid)
                    throw new ObjectDisposedException("Cannot set value, Bro vector is disposed.");

                if (index < 0 || index >= Count)
                    throw new ArgumentOutOfRangeException("index");

                if ((object)value == null)
                    throw new ArgumentNullException("value");

                if (value.ExecuteWithFixedPtr(ptr => BroApi.bro_vector_set_nth_val(m_vectorPtr, index, value.Type, value.TypeName, ptr) == 0))
                    throw new InvalidOperationException(string.Format("Failed to update value at index {0}.", index));
            }
        }

        /// <summary>
        /// Gets the number of elements contained in this <see cref="BroVector"/>.
        /// </summary>
        /// <returns>
        /// The number of elements contained in this <see cref="BroVector"/>.
        /// </returns>
        public int Count
        {
            get
            {
                if (!m_vectorPtr.IsInvalid)
                    return BroApi.bro_vector_get_length(m_vectorPtr);

                return 0;
            }
        }

        /// <summary>
        /// Gets a value indicating whether this <see cref="BroVector"/> is read-only.
        /// </summary>
        /// <returns>
        /// <c>true</c> if this <see cref="BroVector"/> is read-only; otherwise, <c>false</c>.
        /// </returns>
        /// <remarks>
        /// This always returns <c>false</c> for a <see cref="BroVector"/>.
        /// </remarks>>
        public bool IsReadOnly
        {
            get
            {
                return false;
            }
        }

        #endregion

        #region [ Methods ]

        /// <summary>
        /// Releases all the resources used by this <see cref="BroVector"/> object.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases the unmanaged resources used by this <see cref="BroVector"/> object and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!m_disposed)
            {
                try
                {
                    if ((object)m_vectorPtr != null && !m_vectorPtr.IsInvalid)
                        m_vectorPtr.Dispose();
                }
                finally
                {
                    m_disposed = true;  // Prevent duplicate dispose.
                }
            }
        }

        /// <summary>
        /// Adds <paramref name="value"/> of <paramref name="type"/> to this <see cref="BroVector"/>.
        /// </summary>
        /// <param name="value">The value to add to this <see cref="BroVector"/>.</param>
        /// <param name="type">The <see cref="BroType"/> of the <paramref name="value"/>.</param>
        /// <param name="typeName">Optional name of specialized type of <paramref name="value"/>.</param>
        /// <returns><c>true</c> if successful; otherwise, <c>false</c>.</returns>
        /// <exception cref="ObjectDisposedException">Cannot add item, <see cref="BroVector"/> is disposed.</exception>
        public bool Add(object value, BroType type, string typeName = null)
        {
            return Add(new BroValue(value, type, typeName));
        }

        /// <summary>
        /// Adds <paramref name="value"/> to this <see cref="BroVector"/>.
        /// </summary>
        /// <param name="value">The <see cref="BroValue"/> to add to this <see cref="BroVector"/>.</param>
        /// <returns><c>true</c> if successful; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">Cannot add a <c>null</c> <see cref="BroValue"/>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot add item, <see cref="BroVector"/> is disposed.</exception>
        public bool Add(BroValue value)
        {
            if ((object)value == null)
                throw new ArgumentNullException("value");

            if (m_vectorPtr.IsInvalid)
                throw new ObjectDisposedException("Cannot add value, Bro vector is disposed.");

            return value.ExecuteWithFixedPtr(ptr => BroApi.bro_vector_add_val(m_vectorPtr, value.Type, value.TypeName, ptr) != 0);
        }

        // Interface for collection returns no value
        void ICollection<BroValue>.Add(BroValue item)
        {
            Add(item);
        }

        /// <summary>
        /// Gets a clone of this <see cref="BroVector"/>.
        /// </summary>
        /// <returns>Clone of this <see cref="BroVector"/>.</returns>
        /// <exception cref="ObjectDisposedException">Cannot clone, <see cref="BroVector"/> is disposed.</exception>
        public BroVector Clone()
        {
            if (m_vectorPtr.IsInvalid)
                throw new ObjectDisposedException("Cannot clone, Bro vector is disposed.");

            return new BroVector(m_vectorPtr);
        }

        /// <summary>
        /// Removes all items from this <see cref="BroVector"/>.
        /// </summary>
        /// <exception cref="ObjectDisposedException">Cannot clear, <see cref="BroVector"/> is disposed.</exception>
        public void Clear()
        {
            if (m_vectorPtr.IsInvalid)
                throw new ObjectDisposedException("Cannot clear items, Bro vector is disposed.");

            m_vectorPtr.Dispose();
            m_vectorPtr = BroApi.bro_vector_new();
        }

        /// <summary>
        /// Determines whether this <see cref="BroVector"/> contains specified <paramref name="value"/>.
        /// </summary>
        /// <param name="value">The <see cref="BroValue"/> to locate in this <see cref="BroVector"/>.</param>
        /// <returns><c>true</c> if <paramref name="value"/> is found in this <see cref="BroVector"/>; otherwise, <c>false</c>.</returns>
        /// <remarks>
        /// This method performs a linear search - an O(n) operation where n is <see cref="Count"/>.
        /// </remarks>
        public bool Contains(BroValue value)
        {
            return IndexOf(value) > -1;
        }

        /// <summary>
        /// Copies the elements of this <see cref="BroVector"/> to an <see cref="Array"/>, starting at a particular <see cref="Array"/> index.
        /// </summary>
        /// <param name="array">The one-dimensional <see cref="Array"/> that is the destination of the elements copied from <see cref="BroVector"/>. The <see cref="Array"/> must have zero-based indexing.</param>
        /// <param name="arrayIndex">The zero-based index in <paramref name="array"/> at which copying begins.</param>
        /// <exception cref="ArgumentNullException"><paramref name="array"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="arrayIndex"/> is less than 0.</exception>
        /// <exception cref="ArgumentException">The number of elements in the source <see cref="BroVector"/> is greater than the available space from <paramref name="arrayIndex"/> to the end of the destination <paramref name="array"/>.</exception>
        public void CopyTo(BroValue[] array, int arrayIndex)
        {
            if ((object)array == null)
                throw new ArgumentNullException("array");

            if (arrayIndex < 0)
                throw new ArgumentOutOfRangeException("arrayIndex");

            if (Count > array.Length - arrayIndex)
                throw new ArgumentException("Not enough available space in destination array starting from specified array index to hold all source elements.");

            for (int i = 0; i < Count; i++)
                array[arrayIndex + i] = this[i];
        }

        /// <summary>
        /// Returns an enumerator that iterates through the collection.
        /// </summary>
        /// <returns>
        /// A <see cref="IEnumerator{T}"/> that can be used to iterate through the collection.
        /// </returns>
        public IEnumerator<BroValue> GetEnumerator()
        {
            for (int i = 0; i < Count; i++)
                yield return this[i];
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        /// <summary>
        /// Determines the index of the specified <paramref name="value"/> in this <see cref="BroVector"/>.
        /// </summary>
        /// <returns>
        /// The zero-based index of <paramref name="value"/> if found in the vector; otherwise, -1.
        /// </returns>
        /// <param name="value">The <see cref="BroValue"/> to locate in this <see cref="BroVector"/>.</param>
        /// <remarks>
        /// This method performs a linear search - an O(n) operation where n is <see cref="Count"/>.
        /// </remarks>
        public int IndexOf(BroValue value)
        {
            for (int i = 0; i < Count; i++)
            {
                if (this[i] == value)
                    return i;
            }

            return -1;
        }

        /// <summary>
        /// Inserts <paramref name="value"/> of <paramref name="type"/> in this <see cref="BroVector"/> at the specified <paramref name="index"/>.
        /// </summary>
        /// <param name="index">The zero-based index at which <paramref name="value"/> should be inserted.</param>
        /// <param name="value">The value to insert into this <see cref="BroVector"/>.</param>
        /// <param name="type">The <see cref="BroType"/> of the <paramref name="value"/>.</param>
        /// <param name="typeName">Optional name of specialized type of <paramref name="value"/>.</param>
        /// <remarks>
        /// This is not a native Bro vector operation. Function will perform expected task, but for large data sets operation may be expensive.
        /// </remarks>
        /// <exception cref="ObjectDisposedException">Cannot execute list operation, <see cref="BroVector"/> is disposed.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="index"/> is not a valid index in this <see cref="BroVector"/>.</exception>
        public void Insert(int index, object value, BroType type, string typeName = null)
        {
            Insert(index, new BroValue(value, type, typeName));
        }

        /// <summary>
        /// Inserts <paramref name="value"/> in this <see cref="BroVector"/> at the specified <paramref name="index"/>.
        /// </summary>
        /// <param name="index">The zero-based index at which <paramref name="value"/> should be inserted.</param>
        /// <param name="value">The <see cref="BroValue"/> to insert into this <see cref="BroVector"/>.</param>
        /// <remarks>
        /// This is not a native Bro vector operation. Function will perform expected task, but for large data sets operation may be expensive.
        /// </remarks>
        /// <exception cref="ObjectDisposedException">Cannot execute list operation, <see cref="BroVector"/> is disposed.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="index"/> is not a valid index in this <see cref="BroVector"/>.</exception>
        public void Insert(int index, BroValue value)
        {
            ExecuteCloneOperation(list => list.Insert(index, value));
        }

        /// <summary>
        /// Removes the <see cref="BroValue"/> item at the specified <paramref name="index"/>.
        /// </summary>
        /// <param name="index">The zero-based index of the item to remove.</param>
        /// <remarks>
        /// This is not a native Bro vector operation. Function will perform expected task, but for large data sets operation may be expensive.
        /// </remarks>
        /// <exception cref="ObjectDisposedException">Cannot execute list operation, <see cref="BroVector"/> is disposed.</exception>
        public void RemoveAt(int index)
        {
            ExecuteCloneOperation(list => list.RemoveAt(index));
        }

        /// <summary>
        /// Removes the first occurrence of the specified <see cref="BroValue"/> from this <see cref="BroVector"/>.
        /// </summary>
        /// <param name="value">The <see cref="BroValue"/> to remove from this <see cref="BroVector"/>.</param>
        /// <returns>
        /// <c>true</c> if <paramref name="value"/> was successfully removed from this <see cref="BroVector"/>; otherwise, <c>false</c>.
        /// This method also returns <c>false</c> if <paramref name="value"/> is not found in the original <see cref="BroVector"/>.
        /// </returns>
        /// <remarks>
        /// This is not a native Bro vector operation. Function will perform expected task, but for large data sets operation may be expensive.
        /// </remarks>
        /// <exception cref="ObjectDisposedException">Cannot execute list operation, <see cref="BroVector"/> is disposed.</exception>
        public bool Remove(BroValue value)
        {
            int index = IndexOf(value);

            if (index > -1)
            {
                RemoveAt(index);
                return true;
            }

            return false;
        }

        private void ExecuteCloneOperation(Action<List<BroValue>> operation)
        {
            if (m_vectorPtr.IsInvalid)
                throw new ObjectDisposedException("Cannot execute list operation, Bro table is disposed.");

            // Copy the Bro vector items into a new List<T> data structure
            List<BroValue> list = new List<BroValue>(this);

            // Execute operation on the list
            operation(list);

            // Clear the items in the Bro vector
            Clear();

            // Add the items back to the Bro vector
            foreach (BroValue item in list)
                Add(item);
        }

        // Get pointer to Bro vector
        internal BroVectorPtr GetValuePtr()
        {
            if (m_vectorPtr.IsInvalid)
                throw new ObjectDisposedException("Cannot get value pointer, Bro vector is disposed.");

            return m_vectorPtr;
        }

        #endregion
    }
}
