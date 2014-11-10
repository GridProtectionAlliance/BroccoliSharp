//******************************************************************************************************
//  BroRecord.cs - Gbtc
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
using System.Linq;
using System.Runtime.InteropServices;
using BroccoliSharp.Internal;

namespace BroccoliSharp
{
    /// <summary>
    /// Represents a Bro record implemented as an <see cref="IList{T}">IList&lt;BroField&gt;</see>.
    /// </summary>
    /// <include file='Documentation\BroRecord.xml' path='/doc/*'/>
    public class BroRecord : IList<BroField>, IDisposable
    {
        #region [ Members ]

        // Fields
        private BroRecordPtr m_recordPtr;
        private bool m_disposed;

        #endregion

        #region [ Constructors ]

        /// <summary>
        /// Creates a new <see cref="BroRecord"/>.
        /// </summary>
        /// <exception cref="OutOfMemoryException">Failed to create Bro record.</exception>
        public BroRecord()
        {
            m_recordPtr = BroApi.bro_record_new();

            if (m_recordPtr.IsInvalid)
                throw new OutOfMemoryException("Failed to create Bro record.");
        }

        /// <summary>
        /// Creates a new <see cref="BroRecord"/> from an existing collection of <see cref="BroField"/> items.
        /// </summary>
        /// <param name="values">Collection of <see cref="BroField"/> items.</param>
        /// <exception cref="ArgumentNullException"><paramref name="values"/> is <c>null</c>.</exception>
        /// <exception cref="OutOfMemoryException">Failed to create Bro record.</exception>
        public BroRecord(IEnumerable<BroField> values)
            : this()
        {
            if ((object)values == null)
                throw new ArgumentNullException("values");

            foreach (BroField value in values)
                Add(value);
        }

        // Create new BroRecord from an existing source record - have to clone source record since we don't own it
        internal BroRecord(BroRecordPtr sourceRecordPtr)
            : this()
        {
            if (sourceRecordPtr.IsInvalid)
                return;

            int length = BroApi.bro_record_get_length(sourceRecordPtr);

            for (int i = 0; i < length; i++)
            {
                BroType type = BroType.Unknown;
                IntPtr value = BroApi.bro_record_get_nth_val(sourceRecordPtr, i, ref type);
                string name = Marshal.PtrToStringAnsi(BroApi.bro_record_get_nth_name(sourceRecordPtr, i));
                BroApi.bro_record_add_val(m_recordPtr, name, type, null, value);
            }
        }

        /// <summary>
        /// Releases the unmanaged resources before this <see cref="BroRecord"/> object is reclaimed by <see cref="GC"/>.
        /// </summary>
        ~BroRecord()
        {
            Dispose(false);
        }

        #endregion

        #region [ Properties ]

        /// <summary>
        /// Gets or sets the <see cref="BroField"/> at the specified <paramref name="index"/>.
        /// </summary>
        /// <returns>
        /// The <see cref="BroField"/> at the specified <paramref name="index"/>, or <c>null</c> if there was an issue retrieving value.
        /// </returns>
        /// <param name="index">The zero-based index of the element to get or set.</param>
        /// <exception cref="ObjectDisposedException">Cannot get or set <see cref="BroField"/>, Bro record is disposed.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="index"/> is not a valid index in this <see cref="BroRecord"/>.</exception>
        /// <exception cref="ArgumentNullException">Cannot set a <c>null</c> <see cref="BroField"/>.</exception>
        /// <exception cref="InvalidOperationException">Failed to update <see cref="BroField"/> at <paramref name="index"/>.</exception>
        public BroField this[int index]
        {
            get
            {
                if (m_recordPtr.IsInvalid)
                    throw new ObjectDisposedException("Cannot get field, Bro record is disposed.");

                if (index < 0 || index >= Count)
                    throw new ArgumentOutOfRangeException("index");

                BroType type = BroType.Unknown;
                IntPtr valuePtr = BroApi.bro_record_get_nth_val(m_recordPtr, index, ref type);
                string name = Marshal.PtrToStringAnsi(BroApi.bro_record_get_nth_name(m_recordPtr, index));

                return new BroField(BroValue.CreateFromPtr(valuePtr, type), name);
            }
            set
            {
                if (m_recordPtr.IsInvalid)
                    throw new ObjectDisposedException("Cannot set field, Bro record is disposed.");

                if (index < 0 || index >= Count)
                    throw new ArgumentOutOfRangeException("index");

                if ((object)value == null)
                    throw new ArgumentNullException("value");

                if (value.ExecuteWithFixedPtr(ptr => BroApi.bro_record_set_nth_val(m_recordPtr, index, value.Type, value.TypeName, ptr) == 0))
                    throw new InvalidOperationException(string.Format("Failed to update field at index {0}.", index));
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="BroValue"/> for the specified field <paramref name="name"/>.
        /// </summary>
        /// <returns>
        /// The <see cref="BroField"/> with the specified field name, or <c>null</c> if there was an issue retrieving value.
        /// </returns>
        /// <param name="name">Then name of the <see cref="BroField"/> to get or set.</param>
        /// <exception cref="ObjectDisposedException">Cannot get or set <see cref="BroField"/>, Bro record is disposed.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="name"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentNullException">Cannot set a <c>null</c> <see cref="BroField"/>.</exception>
        /// <exception cref="InvalidOperationException">Failed to update <see cref="BroField"/> with <paramref name="name"/>.</exception>
        public BroValue this[string name]
        {
            get
            {
                if (m_recordPtr.IsInvalid)
                    throw new ObjectDisposedException("Cannot get field, Bro record is disposed.");

                if ((object)name == null)
                    throw new ArgumentNullException("name");

                BroType type = BroType.Unknown;
                IntPtr valuePtr = BroApi.bro_record_get_named_val(m_recordPtr, name, ref type);

                return new BroField(BroValue.CreateFromPtr(valuePtr, type), name);
            }
            set
            {
                if (m_recordPtr.IsInvalid)
                    throw new ObjectDisposedException("Cannot set field, Bro record is disposed.");

                if ((object)name == null)
                    throw new ArgumentNullException("name");

                if ((object)value == null)
                    throw new ArgumentNullException("value");

                if (value.ExecuteWithFixedPtr(ptr => BroApi.bro_record_set_named_val(m_recordPtr, name, value.Type, value.TypeName, ptr) == 0))
                    throw new InvalidOperationException(string.Format("Failed to update field with name \"{0}\".", name));
            }
        }

        /// <summary>
        /// Gets the number of fields contained in this <see cref="BroRecord"/>.
        /// </summary>
        /// <returns>
        /// The number of fields contained in this <see cref="BroRecord"/>.
        /// </returns>
        public int Count
        {
            get
            {
                if (!m_recordPtr.IsInvalid)
                    return BroApi.bro_record_get_length(m_recordPtr);

                return 0;
            }
        }

        /// <summary>
        /// Gets a value indicating whether this <see cref="BroRecord"/> is read-only.
        /// </summary>
        /// <returns>
        /// <c>true</c> if this <see cref="BroRecord"/> is read-only; otherwise, <c>false</c>.
        /// </returns>
        /// <remarks>
        /// This always returns <c>false</c> for a <see cref="BroRecord"/>.
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
        /// Releases all the resources used by this <see cref="BroRecord"/> object.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases the unmanaged resources used by this <see cref="BroRecord"/> object and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!m_disposed)
            {
                try
                {
                    if ((object)m_recordPtr != null && !m_recordPtr.IsInvalid)
                        m_recordPtr.Dispose();
                }
                finally
                {
                    m_disposed = true;  // Prevent duplicate dispose.
                }
            }
        }

        /// <summary>
        /// Adds new <paramref name="value"/> of <paramref name="type"/> to this <see cref="BroRecord"/> with specified <paramref name="fieldName"/>.
        /// </summary>
        /// <param name="value">The value to add to record as a field.</param>
        /// <param name="type">The <see cref="BroType"/> of the <paramref name="value"/>.</param>
        /// <param name="fieldName">Name of field to add to record, can be empty string for <see cref="BroType.List">BroType.List</see> source.</param>
        /// <param name="typeName">Optional name of specialized type of <paramref name="value"/>.</param>
        /// <returns><c>true</c> if successful; otherwise, <c>false</c>.</returns>
        /// <remarks>
        /// Field name is optional when using Bro record as a <see cref="BroType.List">BroType.List</see>.
        /// </remarks>
        /// <exception cref="ObjectDisposedException">Cannot add item, <see cref="BroRecord"/> is disposed.</exception>
        public bool Add(object value, BroType type, string fieldName = "", string typeName = null)
        {
            return Add(new BroField(value, type, fieldName, typeName));
        }

        /// <summary>
        /// Adds new <paramref name="value"/> to this <see cref="BroRecord"/> with specified <paramref name="fieldName"/>.
        /// </summary>
        /// <param name="value"><see cref="BroValue"/> to add to record as a field.</param>
        /// <param name="fieldName">Name of field to add to record, can be empty string for <see cref="BroType.List">BroType.List</see> source.</param>
        /// <returns><c>true</c> if successful; otherwise, <c>false</c>.</returns>
        /// <remarks>
        /// Field name is optional when using Bro record as a <see cref="BroType.List">BroType.List</see>.
        /// </remarks>
        /// <exception cref="ArgumentNullException">Cannot add a <c>null</c> <see cref="BroValue"/>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot add item, <see cref="BroRecord"/> is disposed.</exception>
        public bool Add(BroValue value, string fieldName = "")
        {
            if ((object)value == null)
                throw new ArgumentNullException("value");

            return Add(new BroField(value, fieldName));
        }

        /// <summary>
        /// Adds <paramref name="field"/> to this <see cref="BroRecord"/>.
        /// </summary>
        /// <param name="field">The <see cref="BroField"/> to add to this <see cref="BroRecord"/>.</param>
        /// <returns><c>true</c> if successful; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">Cannot add a <c>null</c> <see cref="BroField"/>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot add item, <see cref="BroRecord"/> is disposed.</exception>
        public bool Add(BroField field)
        {
            if ((object)field == null)
                throw new ArgumentNullException("field");

            if (m_recordPtr.IsInvalid)
                throw new ObjectDisposedException("Cannot add value, Bro record is disposed.");

            return field.ExecuteWithFixedPtr(ptr => BroApi.bro_record_add_val(m_recordPtr, field.Name == string.Empty ? null : field.Name, field.Type, field.TypeName, ptr) != 0);
        }

        // Interface for collection returns no value
        void ICollection<BroField>.Add(BroField item)
        {
            Add(item);
        }

        /// <summary>
        /// Gets a clone of this <see cref="BroRecord"/>.
        /// </summary>
        /// <returns>Clone of this <see cref="BroRecord"/>.</returns>
        /// <exception cref="ObjectDisposedException">Cannot clone, <see cref="BroRecord"/> is disposed.</exception>
        public BroRecord Clone()
        {
            if (m_recordPtr.IsInvalid)
                throw new ObjectDisposedException("Cannot clone, Bro record is disposed.");

            return new BroRecord(m_recordPtr);
        }

        /// <summary>
        /// Removes all fields from this <see cref="BroRecord"/>.
        /// </summary>
        /// <exception cref="ObjectDisposedException">Cannot clear, <see cref="BroRecord"/> is disposed.</exception>
        public void Clear()
        {
            if (m_recordPtr.IsInvalid)
                throw new ObjectDisposedException("Cannot clear items, Bro record is disposed.");

            m_recordPtr.Dispose();
            m_recordPtr = BroApi.bro_record_new();
        }

        /// <summary>
        /// Determines whether this <see cref="BroRecord"/> contains the specified <paramref name="fieldName"/>.
        /// </summary>
        /// <returns>
        /// <c>true</c> if <paramref name="fieldName"/> is found in this <see cref="BroRecord"/>; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="fieldName">The <see cref="BroField"/> to locate in this <see cref="BroRecord"/>.</param>
        /// <remarks>
        /// This method performs a linear search - an O(n) operation where n is <see cref="Count"/>.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="fieldName"/> is <c>null</c>.</exception>
        public bool Contains(string fieldName)
        {
            return IndexOf(fieldName) > -1;
        }

        /// <summary>
        /// Determines whether this <see cref="BroRecord"/> contains the specified <paramref name="field"/>.
        /// </summary>
        /// <returns>
        /// <c>true</c> if <paramref name="field"/> is found in this <see cref="BroRecord"/>; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="field">The <see cref="BroField"/> to locate in this <see cref="BroRecord"/>.</param>
        /// <remarks>
        /// This method performs a linear search - an O(n) operation where n is <see cref="Count"/>.
        /// </remarks>
        public bool Contains(BroField field)
        {
            return IndexOf(field) > -1;
        }

        /// <summary>
        /// Copies the fields of this <see cref="BroRecord"/> to an <see cref="Array"/>, starting at a particular <see cref="Array"/> index.
        /// </summary>
        /// <param name="array">The one-dimensional <see cref="Array"/> that is the destination of the fields copied from <see cref="BroRecord"/>. The <see cref="Array"/> must have zero-based indexing.</param>
        /// <param name="arrayIndex">The zero-based index in <paramref name="array"/> at which copying begins.</param>
        /// <exception cref="ArgumentNullException"><paramref name="array"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="arrayIndex"/> is less than 0.</exception>
        /// <exception cref="ArgumentException">The number of fields in the source <see cref="BroRecord"/> is greater than the available space from <paramref name="arrayIndex"/> to the end of the destination <paramref name="array"/>.</exception>
        public void CopyTo(BroField[] array, int arrayIndex)
        {
            if ((object)array == null)
                throw new ArgumentNullException("array");

            if (arrayIndex < 0)
                throw new ArgumentOutOfRangeException("arrayIndex");

            if (Count > array.Length - arrayIndex)
                throw new ArgumentException("Not enough available space in destination array starting from specified array index to hold all source fields.");

            for (int i = 0; i < Count; i++)
                array[arrayIndex + i] = this[i];
        }

        /// <summary>
        /// Returns an enumerator that iterates through the field collection.
        /// </summary>
        /// <returns>
        /// A <see cref="IEnumerator{T}"/> that can be used to iterate through the field collection.
        /// </returns>
        public IEnumerator<BroField> GetEnumerator()
        {
            for (int i = 0; i < Count; i++)
                yield return this[i];
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        /// <summary>
        /// Determines the index of the specified <paramref name="fieldName"/> in this <see cref="BroRecord"/>.
        /// </summary>
        /// <returns>
        /// The zero-based index of <paramref name="fieldName"/> if found in the record; otherwise, -1.
        /// </returns>
        /// <param name="fieldName">The <see cref="BroField"/> to locate in this <see cref="BroRecord"/>.</param>
        /// <remarks>
        /// This method performs a linear search - an O(n) operation where n is <see cref="Count"/>.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="fieldName"/> is <c>null</c>.</exception>
        public int IndexOf(string fieldName)
        {
            if ((object)fieldName == null)
                throw new ArgumentNullException("fieldName");

            for (int i = 0; i < Count; i++)
            {
                if (fieldName.Equals(this[i].Name, StringComparison.Ordinal))
                    return i;
            }

            return -1;
        }

        /// <summary>
        /// Determines the index of the specified <paramref name="field"/> in this <see cref="BroRecord"/>.
        /// </summary>
        /// <returns>
        /// The zero-based index of <paramref name="field"/> if found in the record; otherwise, -1.
        /// </returns>
        /// <param name="field">The <see cref="BroField"/> to locate in this <see cref="BroRecord"/>.</param>
        /// <remarks>
        /// This method performs a linear search - an O(n) operation where n is <see cref="Count"/>.
        /// </remarks>
        public int IndexOf(BroField field)
        {
            for (int i = 0; i < Count; i++)
            {
                if (this[i] == field)
                    return i;
            }

            return -1;
        }

        /// <summary>
        /// Inserts <paramref name="value"/> of <paramref name="type"/> in this <see cref="BroRecord"/> at the specified <paramref name="index"/> with specified <paramref name="fieldName"/>.
        /// </summary>
        /// <param name="index">The zero-based index at which <paramref name="value"/> should be inserted.</param>
        /// <param name="value">The value to insert into this <see cref="BroRecord"/> as a field.</param>
        /// <param name="type">The <see cref="BroType"/> of the <paramref name="value"/>.</param>
        /// <param name="fieldName">Name of field to add to record, can be empty string for <see cref="BroType.List">BroType.List</see> source.</param>
        /// <param name="typeName">Optional name of specialized type of <paramref name="value"/>.</param>
        /// <remarks>
        /// This is not a native Bro record operation. Function will perform expected task, but for large data sets operation may be expensive.
        /// </remarks>
        /// <exception cref="ObjectDisposedException">Cannot execute list operation, <see cref="BroRecord"/> is disposed.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="index"/> is not a valid index in this <see cref="BroRecord"/>.</exception>
        public void Insert(int index, object value, BroType type, string fieldName = "", string typeName = null)
        {
            Insert(index, new BroField(value, type, fieldName, typeName));
        }

        /// <summary>
        /// Inserts <paramref name="value"/> in this <see cref="BroRecord"/> at the specified <paramref name="index"/> with specified <paramref name="fieldName"/>.
        /// </summary>
        /// <param name="index">The zero-based index at which <paramref name="value"/> should be inserted.</param>
        /// <param name="value"><see cref="BroValue"/> to insert into this <see cref="BroRecord"/> as a field.</param>
        /// <param name="fieldName">Name of field to add to record, can be empty string for <see cref="BroType.List">BroType.List</see> source.</param>
        /// <remarks>
        /// This is not a native Bro record operation. Function will perform expected task, but for large data sets operation may be expensive.
        /// </remarks>
        /// <exception cref="ObjectDisposedException">Cannot execute list operation, <see cref="BroRecord"/> is disposed.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="index"/> is not a valid index in this <see cref="BroRecord"/>.</exception>
        public void Insert(int index, BroValue value, string fieldName = "")
        {
            Insert(index, new BroField(value, fieldName));
        }

        /// <summary>
        /// Inserts <paramref name="field"/> in this <see cref="BroRecord"/> at the specified <paramref name="index"/>.
        /// </summary>
        /// <param name="index">The zero-based index at which <paramref name="field"/> should be inserted.</param>
        /// <param name="field">The <see cref="BroField"/> to insert into this <see cref="BroRecord"/>.</param>
        /// <remarks>
        /// This is not a native Bro record operation. Function will perform expected task, but for large data sets operation may be expensive.
        /// </remarks>
        /// <exception cref="ObjectDisposedException">Cannot execute list operation, <see cref="BroRecord"/> is disposed.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="index"/> is not a valid index in this <see cref="BroRecord"/>.</exception>
        public void Insert(int index, BroField field)
        {
            ExecuteCloneOperation(list => list.Insert(index, field));
        }

        /// <summary>
        /// Removes the <see cref="BroField"/> item at the specified <paramref name="index"/>.
        /// </summary>
        /// <param name="index">The zero-based index of the item to remove.</param>
        /// <remarks>
        /// This is not a native Bro record operation. Function will perform expected task, but for large data sets operation may be expensive.
        /// </remarks>
        /// <exception cref="ObjectDisposedException">Cannot execute list operation, <see cref="BroRecord"/> is disposed.</exception>
        public void RemoveAt(int index)
        {
            ExecuteCloneOperation(list => list.RemoveAt(index));
        }

        /// <summary>
        /// Removes the first occurrence of the specified <paramref name="fieldName"/> from this <see cref="BroRecord"/>.
        /// </summary>
        /// <param name="fieldName">The <see cref="BroField"/> to remove from this <see cref="BroRecord"/>.</param>
        /// <returns>
        /// <c>true</c> if <paramref name="fieldName"/> was successfully removed from this <see cref="BroRecord"/>; otherwise, <c>false</c>.
        /// This method also returns <c>false</c> if <paramref name="fieldName"/> is not found in the original <see cref="BroRecord"/>.
        /// </returns>
        /// <remarks>
        /// This is not a native Bro record operation. Function will perform expected task, but for large data sets operation may be expensive.
        /// </remarks>
        /// <exception cref="ObjectDisposedException">Cannot execute list operation, <see cref="BroRecord"/> is disposed.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="fieldName"/> is <c>null</c>.</exception>
        public bool Remove(string fieldName)
        {
            int index = IndexOf(fieldName);

            if (index > -1)
            {
                RemoveAt(index);
                return true;
            }

            return false;
        }

        /// <summary>
        /// Removes the first occurrence of the specified <paramref name="field"/> from this <see cref="BroRecord"/>.
        /// </summary>
        /// <param name="field">The <see cref="BroField"/> to remove from this <see cref="BroRecord"/>.</param>
        /// <returns>
        /// <c>true</c> if <paramref name="field"/> was successfully removed from this <see cref="BroRecord"/>; otherwise, <c>false</c>.
        /// This method also returns <c>false</c> if <paramref name="field"/> is not found in the original <see cref="BroRecord"/>.
        /// </returns>
        /// <remarks>
        /// This is not a native Bro record operation. Function will perform expected task, but for large data sets operation may be expensive.
        /// </remarks>
        /// <exception cref="ObjectDisposedException">Cannot execute list operation, <see cref="BroRecord"/> is disposed.</exception>
        public bool Remove(BroField field)
        {
            int index = IndexOf(field);

            if (index > -1)
            {
                RemoveAt(index);
                return true;
            }

            return false;
        }

        /// <summary>
        /// Returns a string that represents this <see cref="BroRecord"/>.
        /// </summary>
        /// <returns>
        /// A string that represents this <see cref="BroRecord"/>.
        /// </returns>
        public override string ToString()
        {
            return string.Join(", ", this.Select(field => string.Format("[{0}]=\"{1}\"", string.IsNullOrEmpty(field.Name) ? field.Type.ToString() : field.Name, field.ToString())));
        }

        private void ExecuteCloneOperation(Action<List<BroField>> operation)
        {
            if (m_recordPtr.IsInvalid)
                throw new ObjectDisposedException("Cannot execute list operation, Bro table is disposed.");

            // Copy the Bro record fields into a new List<T> data structure
            List<BroField> list = new List<BroField>(this);

            // Execute operation on the list
            operation(list);

            // Clear the Bro record fields
            Clear();

            // Add the fields back to the Bro record
            foreach (BroField field in list)
                Add(field);
        }

        // Get pointer to Bro record
        internal BroRecordPtr GetValuePtr()
        {
            if (m_recordPtr.IsInvalid)
                throw new ObjectDisposedException("Cannot get value pointer, Bro record is disposed.");

            return m_recordPtr;
        }

        #endregion
    }
}
