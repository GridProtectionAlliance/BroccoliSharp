//******************************************************************************************************
//  BroEventQueue.cs - Gbtc
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
//  10/26/2014 - J. Ritchie Carroll
//       Generated original version of source code.
//
//******************************************************************************************************

using System;
using BroccoliSharp.Internal;

namespace BroccoliSharp
{
    /// <summary>
    /// Represents functions related to the event queue for a <see cref="BroConnection"/>.
    /// </summary>
    public class BroEventQueue
    {
        #region [ Members ]

        // Fields
        private readonly Func<IntPtr> m_getValuePtr;

        #endregion

        #region [ Constructors ]

        // Creates a new event queue class for the Bro connection
        internal BroEventQueue(BroConnection parent)
        {
            m_getValuePtr = parent.GetValuePtr;
        }

        #endregion

        #region [ Properties ]

        /// <summary>
        /// Gets current event queue length for this <see cref="BroConnection"/>.
        /// </summary>
        /// <exception cref="ObjectDisposedException">Cannot get event queue length, <see cref="BroConnection"/> is disposed.</exception>
        public int Length
        {
            get
            {
                return BroApi.bro_event_queue_length(GetConnectionPtr());
            }
        }

        /// <summary>
        /// Gets maximum event queue length for this <see cref="BroConnection"/>.
        /// </summary>
        /// <exception cref="ObjectDisposedException">Cannot get maximum event queue length, <see cref="BroConnection"/> is disposed.</exception>
        public int MaxLength
        {
            get
            {
                return BroApi.bro_event_queue_length_max(GetConnectionPtr());
            }
        }

        #endregion

        #region [ Methods ]

        /// <summary>
        /// Attempts to flush the send queue of this <see cref="BroConnection"/>.
        /// </summary>
        /// <returns>Remaining queue length after flush.</returns>
        /// <exception cref="ObjectDisposedException">Cannot flush queue length, <see cref="BroConnection"/> is disposed.</exception>
        public int Flush()
        {
            return BroApi.bro_event_queue_flush(GetConnectionPtr());
        }

        // Get pointer to parent Bro connection
        private IntPtr GetConnectionPtr()
        {
            IntPtr connection = m_getValuePtr();

            if (connection == IntPtr.Zero)
                throw new ObjectDisposedException("Cannot flush event queue length, Bro connection is disposed.");

            return connection;
        }

        #endregion
    }
}
