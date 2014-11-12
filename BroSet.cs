//******************************************************************************************************
//  BroSet.cs - Gbtc
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
    /// Represents a Bro set implemented as an <see cref="ISet{T}">ISet&lt;BroValue&gt;</see>.
    /// </summary>
    /// <include file='Documentation\BroSet.xml' path='/doc/*'/>
    public class BroSet : ISet<BroValue>, IDisposable
    {
        #region [ Members ]

        // Fields
#if USE_SAFE_HANDLES
        private BroSetPtr m_setPtr;
#else
        private IntPtr m_setPtr;
#endif
        private bool m_disposed;

        #endregion

        #region [ Constructors ]

        /// <summary>
        /// Creates a new <see cref="BroSet"/>.
        /// </summary>
        /// <exception cref="OutOfMemoryException">Failed to create Bro set.</exception>
        public BroSet()
        {
            m_setPtr = BroApi.bro_set_new();

            if (m_setPtr.IsInvalid())
                throw new OutOfMemoryException("Failed to create Bro set.");
        }

        /// <summary>
        /// Creates a new <see cref="BroSet"/> from an existing set of <see cref="BroValue"/> items.
        /// </summary>
        /// <param name="values">Collection of <see cref="BroValue"/> items.</param>
        /// <remarks>
        /// First item in <paramref name="values"/> will determine type for the set keys.
        /// If other items do not have the same type as the first item, they will not be added.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="values"/> is <c>null</c>.</exception>
        /// <exception cref="OutOfMemoryException">Failed to create Bro set.</exception>
        public BroSet(IEnumerable<BroValue> values)
            : this()
        {
            if ((object)values == null)
                throw new ArgumentNullException("values");

            foreach (BroValue value in values)
                Add(value);
        }

        // Create new BroSet from an existing source set - have to clone source set since we don't own it
#if USE_SAFE_HANDLES
        internal BroSet(BroSetPtr sourceSetPtr)
#else
        internal BroSet(IntPtr sourceSetPtr)
#endif
            : this()
        {
            if (sourceSetPtr.IsInvalid())
                return;

            BroType type = BroType.Unknown;

            BroApi.bro_set_get_type(sourceSetPtr, ref type);

            BroApi.bro_set_foreach(sourceSetPtr,
                (value, userData) =>
                {
                    try
                    {
                        BroApi.bro_set_insert(m_setPtr, type, value);
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
        /// Releases the unmanaged resources before this <see cref="BroSet"/> object is reclaimed by <see cref="GC"/>.
        /// </summary>
        ~BroSet()
        {
            Dispose(false);
        }

        #endregion

        #region [ Properties ]

        /// <summary>
        /// Gets the <see cref="BroType"/> of this <see cref="BroSet"/>.
        /// </summary>
        /// <remarks>
        /// First item added to the set will determine the type for all subsequent set keys.
        /// </remarks>
        public BroType Type
        {
            get
            {
                BroType type = BroType.Unknown;

                if (!m_setPtr.IsInvalid())
                    BroApi.bro_set_get_type(m_setPtr, ref type);

                return type;
            }
        }

        /// <summary>
        /// Gets the number of elements contained in this <see cref="BroSet"/>.
        /// </summary>
        /// <returns>
        /// The number of elements contained in this <see cref="BroSet"/>.
        /// </returns>
        public int Count
        {
            get
            {
                if (!m_setPtr.IsInvalid())
                    return BroApi.bro_set_get_size(m_setPtr);

                return 0;
            }
        }

        /// <summary>
        /// Gets a value indicating whether this <see cref="BroSet"/> is read-only.
        /// </summary>
        /// <returns>
        /// <c>true</c> if this <see cref="BroSet"/> is read-only; otherwise, <c>false</c>.
        /// </returns>
        /// <remarks>
        /// This always returns <c>false</c> for a <see cref="BroSet"/>.
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
        /// Releases all the resources used by this <see cref="BroSet"/> object.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases the unmanaged resources used by this <see cref="BroSet"/> object and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!m_disposed)
            {
                try
                {
#if USE_SAFE_HANDLES
                    if ((object)m_setPtr != null && !m_setPtr.IsInvalid())
                        m_setPtr.Dispose();
#else
                    if (m_setPtr != IntPtr.Zero)
                    {
                        BroApi.bro_set_free(m_setPtr);
                        m_setPtr = IntPtr.Zero;
                    }
#endif
                }
                finally
                {
                    m_disposed = true;  // Prevent duplicate dispose.
                }
            }
        }

        /// <summary>
        /// Adds <paramref name="value"/> of <paramref name="type"/> to this <see cref="BroSet"/>.
        /// </summary>
        /// <param name="value">The value to add to this <see cref="BroSet"/>.</param>
        /// <param name="type">The <see cref="BroType"/> of the <paramref name="value"/>.</param>
        /// <param name="typeName">Optional name of specialized type of <paramref name="value"/>.</param>
        /// <returns><c>true</c> if successful; otherwise, <c>false</c>.</returns>
        /// <remarks>
        /// First item added to the set will determine the type for all subsequent set keys. Any key values
        /// attempted to be added that are not the same type as the first key will fail to insert into the set.
        /// </remarks>
        /// <exception cref="ObjectDisposedException">Cannot add item, <see cref="BroSet"/> is disposed.</exception>
        public bool Add(object value, BroType type, string typeName = null)
        {
            return Add(new BroValue(value, type, typeName));
        }

        /// <summary>
        /// Adds <paramref name="value"/> to this <see cref="BroSet"/>.
        /// </summary>
        /// <param name="value">The <see cref="BroValue"/> to add to this <see cref="BroSet"/>.</param>
        /// <returns><c>true</c> if successful; otherwise, <c>false</c>.</returns>
        /// <remarks>
        /// First item added to the set will determine the type for all subsequent set keys. Any key values
        /// attempted to be added that are not the same type as the first key will fail to insert into the set.
        /// </remarks>
        /// <exception cref="ArgumentNullException">Cannot add a <c>null</c> <see cref="BroValue"/>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot add item, <see cref="BroSet"/> is disposed.</exception>
        public bool Add(BroValue value)
        {
            if ((object)value == null)
                throw new ArgumentNullException("value");

            if (m_setPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot add value, Bro set is disposed.");

            return value.ExecuteWithFixedPtr(ptr => BroApi.bro_set_insert(m_setPtr, value.Type, ptr) != 0);
        }

        // Interface for collection returns no value
        void ICollection<BroValue>.Add(BroValue item)
        {
            Add(item);
        }

        /// <summary>
        /// Gets a clone of this <see cref="BroSet"/>.
        /// </summary>
        /// <returns>Clone of this <see cref="BroSet"/>.</returns>
        /// <exception cref="ObjectDisposedException">Cannot clone, <see cref="BroSet"/> is disposed.</exception>
        public BroSet Clone()
        {
            if (m_setPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot clone, Bro set is disposed.");

            return new BroSet(m_setPtr);
        }

        /// <summary>
        /// Removes all items from this <see cref="BroSet"/>.
        /// </summary>
        /// <exception cref="ObjectDisposedException">Cannot clear, <see cref="BroSet"/> is disposed.</exception>
        public void Clear()
        {
            if (m_setPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot clear items, Bro set is disposed.");

#if USE_SAFE_HANDLES
            m_setPtr.Dispose();
#else
            BroApi.bro_set_free(m_setPtr);
#endif
            m_setPtr = BroApi.bro_set_new();
        }

        /// <summary>
        /// Determines whether this <see cref="BroSet"/> contains specified <paramref name="value"/> of <paramref name="type"/>.
        /// </summary>
        /// <param name="value">The value to locate in this <see cref="BroSet"/>.</param>
        /// <param name="type">The <see cref="BroType"/> of the <paramref name="value"/>.</param>
        /// <param name="typeName">Optional name of specialized type of <paramref name="value"/>.</param>
        /// <returns>
        /// <c>true</c> if <paramref name="value"/> is found in this <see cref="BroSet"/>; otherwise, <c>false</c>.
        /// </returns>
        /// <exception cref="ObjectDisposedException">Cannot execute contains, <see cref="BroSet"/> is disposed.</exception>
        public bool Contains(object value, BroType type, string typeName = null)
        {
            return Contains(new BroValue(value, type, typeName));
        }

        /// <summary>
        /// Determines whether this <see cref="BroSet"/> contains specified <paramref name="value"/>.
        /// </summary>
        /// <param name="value">The <see cref="BroValue"/> to locate in this <see cref="BroSet"/>.</param>
        /// <returns>
        /// <c>true</c> if <paramref name="value"/> is found in this <see cref="BroSet"/>; otherwise, <c>false</c>.
        /// </returns>
        /// <exception cref="ObjectDisposedException">Cannot execute contains, <see cref="BroSet"/> is disposed.</exception>
        public bool Contains(BroValue value)
        {
            if ((object)value == null)
                throw new ArgumentNullException("value");

            if (m_setPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot execute contains, Bro set is disposed.");

            return value.ExecuteWithFixedPtr(ptr => BroApi.bro_set_find(m_setPtr, ptr) != 0);
        }

        /// <summary>
        /// Copies the elements of this <see cref="BroSet"/> to an <see cref="Array"/>, starting at a particular <see cref="Array"/> index.
        /// </summary>
        /// <param name="array">The one-dimensional <see cref="Array"/> that is the destination of the elements copied from <see cref="BroSet"/>. The <see cref="Array"/> must have zero-based indexing.</param>
        /// <param name="arrayIndex">The zero-based index in <paramref name="array"/> at which copying begins.</param>
        /// <exception cref="ArgumentNullException"><paramref name="array"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="arrayIndex"/> is less than 0.</exception>
        /// <exception cref="ArgumentException">The number of elements in the source <see cref="BroSet"/> is greater than the available space from <paramref name="arrayIndex"/> to the end of the destination <paramref name="array"/>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot copy to array, <see cref="BroSet"/> is disposed.</exception>
        public void CopyTo(BroValue[] array, int arrayIndex)
        {
            if ((object)array == null)
                throw new ArgumentNullException("array");

            if (arrayIndex < 0)
                throw new ArgumentOutOfRangeException("arrayIndex");

            if (Count > array.Length - arrayIndex)
                throw new ArgumentException("Not enough available space in destination array starting from specified array index to hold all source elements.");

            if (m_setPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot copy to array, Bro set is disposed.");

            BroType type = this.Type;
            int i = 0;

            BroApi.bro_set_foreach(m_setPtr,
                (value, userData) =>
                {
                    try
                    {
                        array[arrayIndex + i++] = BroValue.CreateFromPtr(value, type);
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
        /// Removes all elements in the specified collection from the current set.
        /// </summary>
        /// <param name="other">The collection of items to remove from the set.</param>
        /// <remarks>
        /// This is not a native Bro set operation. Function will perform expected task, but for large data sets operation may be expensive.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="other"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot execute set operation, <see cref="BroSet"/> is disposed.</exception>
        public void ExceptWith(IEnumerable<BroValue> other)
        {
            ExecuteCloneOperation(set => set.ExceptWith(other));
        }

        /// <summary>
        /// Returns an enumerator that iterates through the collection.
        /// </summary>
        /// <returns>
        /// A <see cref="IEnumerator{T}"/> that can be used to iterate through the collection.
        /// </returns>
        /// <exception cref="ObjectDisposedException">Cannot get list, <see cref="BroSet"/> is disposed.</exception>
        public IEnumerator<BroValue> GetEnumerator()
        {
            foreach (BroValue value in ToList())
                yield return value;
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        /// <summary>
        /// Modifies the current set so that it contains only elements that are also in a specified collection.
        /// </summary>
        /// <param name="other">The collection to compare to the current set.</param>
        /// <remarks>
        /// This is not a native Bro set operation. Function will perform expected task, but for large data sets operation may be expensive.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="other"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot execute set operation, <see cref="BroSet"/> is disposed.</exception>
        public void IntersectWith(IEnumerable<BroValue> other)
        {
            ExecuteCloneOperation(set => set.IntersectWith(other));
        }

        /// <summary>
        /// Determines whether the current set is a proper (strict) subset of a specified collection.
        /// </summary>
        /// <param name="other">The collection to compare to the current set.</param>
        /// <returns>
        /// <c>true</c> if the current set is a proper subset of <paramref name="other"/>; otherwise, <c>false</c>.
        /// </returns>
        /// <remarks>
        /// This is not a native Bro set operation. Function will perform expected task, but for large data sets operation may be expensive.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="other"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot execute set operation, <see cref="BroSet"/> is disposed.</exception>
        public bool IsProperSubsetOf(IEnumerable<BroValue> other)
        {
            return ExecuteCloneOperation(set => set.IsProperSubsetOf(other));
        }

        /// <summary>
        /// Determines whether the current set is a proper (strict) superset of a specified collection.
        /// </summary>
        /// <param name="other">The collection to compare to the current set. </param>
        /// <returns>
        /// <c>true</c> if the current set is a proper superset of <paramref name="other"/>; otherwise, <c>false</c>.
        /// </returns>
        /// <remarks>
        /// This is not a native Bro set operation. Function will perform expected task, but for large data sets operation may be expensive.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="other"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot execute set operation, <see cref="BroSet"/> is disposed.</exception>
        public bool IsProperSupersetOf(IEnumerable<BroValue> other)
        {
            return ExecuteCloneOperation(set => set.IsProperSupersetOf(other));
        }

        /// <summary>
        /// Determines whether a set is a subset of a specified collection.
        /// </summary>
        /// <param name="other">The collection to compare to the current set.</param>
        /// <returns>
        /// <c>true</c> if the current set is a subset of <paramref name="other"/>; otherwise, <c>false</c>.
        /// </returns>
        /// <remarks>
        /// This is not a native Bro set operation. Function will perform expected task, but for large data sets operation may be expensive.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="other"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot execute set operation, <see cref="BroSet"/> is disposed.</exception>
        public bool IsSubsetOf(IEnumerable<BroValue> other)
        {
            return ExecuteCloneOperation(set => set.IsSubsetOf(other));
        }

        /// <summary>
        /// Determines whether the current set is a superset of a specified collection.
        /// </summary>
        /// <param name="other">The collection to compare to the current set.</param>
        /// <returns>
        /// <c>true</c> if the current set is a superset of <paramref name="other"/>; otherwise, <c>false</c>.
        /// </returns>
        /// <remarks>
        /// This is not a native Bro set operation. Function will perform expected task, but for large data sets operation may be expensive.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="other"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot execute set operation, <see cref="BroSet"/> is disposed.</exception>
        public bool IsSupersetOf(IEnumerable<BroValue> other)
        {
            return ExecuteCloneOperation(set => set.IsSupersetOf(other));
        }

        /// <summary>
        /// Determines whether the current set overlaps with the specified collection.
        /// </summary>
        /// <param name="other">The collection to compare to the current set.</param>
        /// <returns>
        /// <c>true</c> if the current set and <paramref name="other"/> share at least one common element; otherwise, <c>false</c>.
        /// </returns>
        /// <remarks>
        /// This is not a native Bro set operation. Function will perform expected task, but for large data sets operation may be expensive.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="other"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot execute set operation, <see cref="BroSet"/> is disposed.</exception>
        public bool Overlaps(IEnumerable<BroValue> other)
        {
            return ExecuteCloneOperation(set => set.Overlaps(other));
        }

        /// <summary>
        /// Removes the first occurrence of the specified <see cref="BroValue"/> from this <see cref="BroSet"/>.
        /// </summary>
        /// <param name="value">The <see cref="BroValue"/> to remove from this <see cref="BroSet"/>.</param>
        /// <returns>
        /// <c>true</c> if <paramref name="value"/> was successfully removed from this <see cref="BroSet"/>; otherwise, <c>false</c>.
        /// This method also returns <c>false</c> if <paramref name="value"/> is not found in the original <see cref="BroSet"/>.
        /// </returns>
        /// <remarks>
        /// This is not a native Bro set operation. Function will perform expected task, but for large data sets operation may be expensive.
        /// </remarks>
        /// <exception cref="ObjectDisposedException">Cannot execute set operation, <see cref="BroSet"/> is disposed.</exception>
        public bool Remove(BroValue value)
        {
            return ExecuteCloneOperation(set => set.Remove(value), true);
        }

        /// <summary>
        /// Determines whether the current set and the specified collection contain the same elements.
        /// </summary>
        /// <param name="other">The collection to compare to the current set.</param>
        /// <returns>
        /// <c>true</c> if the current set is equal to <paramref name="other"/>; otherwise, <c>false</c>.
        /// </returns>
        /// <remarks>
        /// This is not a native Bro set operation. Function will perform expected task, but for large data sets operation may be expensive.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="other"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot execute set operation, <see cref="BroSet"/> is disposed.</exception>
        public bool SetEquals(IEnumerable<BroValue> other)
        {
            return ExecuteCloneOperation(set => set.SetEquals(other));
        }

        /// <summary>
        /// Modifies the current set so that it contains only elements that are present either in the current set or in the specified collection, but not both. 
        /// </summary>
        /// <param name="other">The collection to compare to the current set.</param>
        /// <remarks>
        /// This is not a native Bro set operation. Function will perform expected task, but for large data sets operation may be expensive.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="other"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot execute set operation, <see cref="BroSet"/> is disposed.</exception>
        public void SymmetricExceptWith(IEnumerable<BroValue> other)
        {
            ExecuteCloneOperation(set => set.SymmetricExceptWith(other));
        }

        /// <summary>
        /// Converts this <see cref="BroSet"/> into a <see cref="List{BroValue}"/>.
        /// </summary>
        /// <returns>Current <see cref="BroSet"/> as a <see cref="List{BroValue}"/>.</returns>
        /// <exception cref="ObjectDisposedException">Cannot get list, <see cref="BroSet"/> is disposed.</exception>
        public List<BroValue> ToList()
        {
            if (m_setPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot get list, Bro set is disposed.");

            List<BroValue> list = new List<BroValue>(Count);
            BroType type = this.Type;

            BroApi.bro_set_foreach(m_setPtr,
                (value, userData) =>
                {
                    try
                    {
                        list.Add(BroValue.CreateFromPtr(value, type));
                        return ~0;
                    }
                    catch
                    {
                        return 0;
                    }
                },
                IntPtr.Zero);

            return list;
        }

        /// <summary>
        /// Modifies the current set so that it contains all elements that are present in either the current set or the specified collection.
        /// </summary>
        /// <param name="other">The collection to compare to the current set.</param>
        /// <remarks>
        /// This is not a native Bro set operation. Function will perform expected task, but for large data sets operation may be expensive.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="other"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot execute set operation, <see cref="BroSet"/> is disposed.</exception>
        public void UnionWith(IEnumerable<BroValue> other)
        {
            ExecuteCloneOperation(set => set.UnionWith(other));
        }

        private void ExecuteCloneOperation(Action<HashSet<BroValue>> operation)
        {
            // Copy the Bro set items into a new HashSet<T> data structure
            HashSet<BroValue> set = GetHashSet();

            // Execute operation on the hash-set
            operation(set);

            // Clear the items in the Bro set
            Clear();

            // Add the items back to the Bro set
            foreach (BroValue item in set)
                Add(item);
        }

        private T ExecuteCloneOperation<T>(Func<HashSet<BroValue>, T> operation, bool updateSet = false)
        {
            // Copy the Bro set items into a new HashSet<T> data structure
            HashSet<BroValue> set = GetHashSet();

            // Execute operation (with return value) on the hash-set
            T result = operation(set);

            // Only update set if operation modifies source data
            if (updateSet)
            {
                // Clear the items in the Bro set
                Clear();

                // Add the items back to the Bro set
                foreach (BroValue item in set)
                    Add(item);
            }

            return result;
        }

        // Gets current set as a HashSet<BroValue>
        private HashSet<BroValue> GetHashSet()
        {
            if (m_setPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot execute set operation, Bro set is disposed.");

            HashSet<BroValue> set = new HashSet<BroValue>();
            BroType type = this.Type;

            BroApi.bro_set_foreach(m_setPtr,
                (value, userData) =>
                {
                    try
                    {
                        set.Add(BroValue.CreateFromPtr(value, type));
                        return ~0;
                    }
                    catch
                    {
                        return 0;
                    }
                },
                IntPtr.Zero);

            return set;
        }

        // Get pointer to Bro set
#if USE_SAFE_HANDLES
        internal BroSetPtr GetValuePtr()
#else
        internal IntPtr GetValuePtr()
#endif
        {
            if (m_setPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot get value pointer, Bro set is disposed.");

            return m_setPtr;
        }

        #endregion
    }
}
