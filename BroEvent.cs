//******************************************************************************************************
//  BroEvent.cs - Gbtc
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
    /// Represents a Bro event implemented as an <see cref="IEnumerable{T}">IEnumerable&lt;BroValue&gt;</see>.
    /// </summary>
    /// <include file='Documentation\BroEvent.xml' path='/doc/*'/>
    public class BroEvent : IEnumerable<BroValue>, IDisposable
    {
        #region [ Members ]

        // Fields
#if USE_SAFE_HANDLES
        private readonly BroEventPtr m_eventPtr;
#else
        private IntPtr m_eventPtr;
#endif
        private readonly string m_name;
        private readonly List<BroValue> m_parameters;
        private bool m_disposed;

        #endregion

        #region [ Constructors ]

        /// <summary>
        /// Creates a new <see cref="BroEvent"/> with the specified <paramref name="name"/>.
        /// </summary>
        /// <param name="name">Name of the <see cref="BroEvent"/>.</param>
        /// <exception cref="ArgumentNullException"><paramref name="name"/> is <c>null</c>.</exception>
        /// <exception cref="OutOfMemoryException">Failed to create Bro event.</exception>
        public BroEvent(string name)
        {
            if ((object)name == null)
                throw new ArgumentNullException("name");

            m_eventPtr = BroApi.bro_event_new(name);

            if (m_eventPtr.IsInvalid())
                throw new OutOfMemoryException("Failed to create Bro event.");

            m_name = name;
            m_parameters = new List<BroValue>();
        }

        /// <summary>
        /// Creates a new <see cref="BroEvent"/> with the specified <paramref name="name"/> and <paramref name="parameters"/>.
        /// </summary>
        /// <param name="name">Name of the <see cref="BroEvent"/>.</param>
        /// <param name="parameters">Parameters to add to event.</param>
        /// <exception cref="ArgumentNullException"><paramref name="name"/> or <paramref name="parameters"/> is <c>null</c>.</exception>
        /// <exception cref="OutOfMemoryException">Failed to create Bro event.</exception>
        public BroEvent(string name, IEnumerable<BroValue> parameters)
            : this(name)
        {
            if ((object)parameters == null)
                throw new ArgumentNullException("parameters");

            AddParameters(parameters);
        }

        /// <summary>
        /// Releases the unmanaged resources before this <see cref="BroEvent"/> object is reclaimed by <see cref="GC"/>.
        /// </summary>
        ~BroEvent()
        {
            Dispose(false);
        }

        #endregion

        #region [ Properties ]

        /// <summary>
        /// Gets name of this <see cref="BroEvent"/>.
        /// </summary>
        public string Name
        {
            get
            {
                return m_name;
            }
        }

        /// <summary>
        /// Gets the number of parameters added to this <see cref="BroEvent"/>.
        /// </summary>
        /// <remarks>
        /// <see cref="BroEvent"/> instance can be enumerated to access parameter values.
        /// </remarks>
        public int ParameterCount
        {
            get
            {
                return m_parameters.Count;
            }
        }

        #endregion

        #region [ Methods ]

        /// <summary>
        /// Releases all the resources used by this <see cref="BroEvent"/> object.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases the unmanaged resources used by this <see cref="BroEvent"/> object and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!m_disposed)
            {
                try
                {
#if USE_SAFE_HANDLES
                    if ((object)m_eventPtr != null && !m_eventPtr.IsInvalid())
                        m_eventPtr.Dispose();
#else
                    if (m_eventPtr != IntPtr.Zero)
                    {
                        BroApi.bro_event_free(m_eventPtr);
                        m_eventPtr = IntPtr.Zero;
                    }
#endif
                    if (disposing)
                        m_parameters.Clear();
                }
                finally
                {
                    m_disposed = true;  // Prevent duplicate dispose.
                }
            }
        }

        /// <summary>
        /// Adds a parameter with <paramref name="value"/> of <paramref name="type"/> to this <see cref="BroEvent"/>.
        /// </summary>
        /// <param name="value">The value to add to this <see cref="BroEvent"/>.</param>
        /// <param name="type">The <see cref="BroType"/> of the <paramref name="value"/>.</param>
        /// <param name="typeName">Optional name of specialized type of <paramref name="value"/>.</param>
        /// <returns><c>true</c> if operation was successful; otherwise, <c>false</c>.</returns>
        /// <exception cref="ObjectDisposedException">Cannot add parameter, <see cref="BroEvent"/> is disposed.</exception>
        public bool AddParameter(object value, BroType type, string typeName = null)
        {
            return AddParameter(new BroValue(value, type, typeName));
        }

        /// <summary>
        /// Adds a parameter to this <see cref="BroEvent"/>.
        /// </summary>
        /// <param name="value">The <see cref="BroValue"/> to add to this <see cref="BroEvent"/>.</param>
        /// <returns><c>true</c> if operation was successful; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">Cannot add a <c>null</c> <see cref="BroValue"/>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot add parameter, <see cref="BroEvent"/> is disposed.</exception>
        public bool AddParameter(BroValue value)
        {
            if ((object)value == null)
                throw new ArgumentNullException("value");

            if (m_eventPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot add value, Bro event is disposed.");

            if (value.ExecuteWithFixedPtr(ptr => BroApi.bro_event_add_val(m_eventPtr, value.Type, value.TypeName, ptr) == 0))
                return false;

            m_parameters.Add(value);
            return true;
        }

        /// <summary>
        /// Adds parameters to this <see cref="BroEvent"/>.
        /// </summary>
        /// <param name="values">Parameter values to add to event.</param>
        /// <returns><c>true</c> if all items were added; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="values"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot add parameter, <see cref="BroEvent"/> is disposed.</exception>
        public bool AddParameters(IEnumerable<BroValue> values)
        {
            if ((object)values == null)
                throw new ArgumentNullException("values");

            bool result = true;

            foreach (BroValue value in values)
            {
                if ((object)value == null)
                    continue;

                if (!AddParameter(value))
                    result = false;
            }

            return result;
        }

        /// <summary>
        /// Adds specified parameters to this <see cref="BroEvent"/>.
        /// </summary>
        /// <param name="args">Individual parameter values to add to the event.</param>
        /// <returns><c>true</c> if all items were added; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="args"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot add parameter, <see cref="BroEvent"/> is disposed.</exception>
        public bool AddParameters(params BroValue[] args)
        {
            return AddParameters(args as IEnumerable<BroValue>);
        }

        /// <summary>
        /// Replaces a parameter with <paramref name="value"/> of <paramref name="type"/> in this <see cref="BroEvent"/>.
        /// </summary>
        /// <param name="index">Parameter index.</param>
        /// <param name="value">The value to replace.</param>
        /// <param name="type">The <see cref="BroType"/> of the <paramref name="value"/>.</param>
        /// <param name="typeName">Optional name of specialized type of <paramref name="value"/>.</param>
        /// <returns><c>true</c> if operation was successful; otherwise, <c>false</c>.</returns>
        /// <exception cref="ObjectDisposedException">Cannot add parameter, <see cref="BroEvent"/> is disposed.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="index"/> is not a valid parameter index.</exception>
        public bool ReplaceParameter(int index, object value, BroType type, string typeName = null)
        {
            return ReplaceParameter(index, new BroValue(value, type, typeName));
        }

        /// <summary>
        /// Replaces a parameter in this <see cref="BroEvent"/>.
        /// </summary>
        /// <param name="index">Parameter index.</param>
        /// <param name="value">The <see cref="BroValue"/> to replace.</param>
        /// <returns><c>true</c> if operation was successful; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">Cannot add a <c>null</c> <see cref="BroValue"/>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot add parameter, <see cref="BroEvent"/> is disposed.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="index"/> is not a valid parameter index.</exception>
        public bool ReplaceParameter(int index, BroValue value)
        {
            if ((object)value == null)
                throw new ArgumentNullException("value");

            if (m_eventPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot replace value, Bro event is disposed.");

            if (index < 0 || index >= m_parameters.Count)
                throw new ArgumentOutOfRangeException("index");

            if (value.ExecuteWithFixedPtr(ptr => BroApi.bro_event_set_val(m_eventPtr, index, value.Type, value.TypeName, ptr) == 0))
                return false;

            m_parameters[index] = value;
            return true;
        }

        /// <summary>
        /// Returns an enumerator that iterates through the <see cref="BroEvent"/> parameters.
        /// </summary>
        /// <returns>
        /// A <see cref="IEnumerator{BroValue}"/> that can be used to iterate through the <see cref="BroEvent"/> parameters.
        /// </returns>
        public IEnumerator<BroValue> GetEnumerator()
        {
            foreach (BroValue value in m_parameters)
                yield return value;
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        // Get pointer to Bro event
#if USE_SAFE_HANDLES
        internal BroEventPtr GetValuePtr()
#else
        internal IntPtr GetValuePtr()
#endif
        {
            if (m_eventPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot get value pointer, Bro event is disposed.");

            return m_eventPtr;
        }

        #endregion
    }
}
