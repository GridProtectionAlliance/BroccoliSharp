//******************************************************************************************************
//  BroConnectionData.cs - Gbtc
//
//  Copyright © 2014, Grid Protection Alliance.  All Rights Reserved.
//
//  Licensed to the Grid Protection Alliance (GPA) under one or more contributor license agreements. See
//  the NOTICE file distributed with this work for additional information regarding copyright ownership.
//  The GPA licenses this file to you under the Eclipse Public License -v 1.0 (the "License"); you may
//  not use this file except in compliance with the License. You may obtain a copy of the License at:
//
//      http://www.opensource.org/licenses/eclipse-1.0.php
//
//  Unless agreed to in writing, the subject software distributed under the License is distributed on an
//  "AS-IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. Refer to the
//  License for the specific language governing permissions and limitations.
//
//  Code Modification History:
//  ----------------------------------------------------------------------------------------------------
//  10/25/2014 - Admin
//       Generated original version of source code.
//
//******************************************************************************************************

using System;
using BroccoliSharp.Internal;

namespace BroccoliSharp
{
    // JRC: This class was dropped from the project in lieu of a managed Dictionary<string, object> that serves the same purpose

    /// <summary>
    /// Represents data storage facilities that can store arbitrary data associated with a <see cref="BroConnection"/>.
    /// </summary>
    public class BroConnectionData
    {
        #region [ Members ]

        // Fields
        private readonly BroConnection m_parent;

        #endregion

        #region [ Constructors ]

        // Creates a new connection data class for the Bro connection
        internal BroConnectionData(BroConnection parent)
        {
            m_parent = parent;
        }

        #endregion

        #region [ Properties ]

        /// <summary>
        /// Gets or sets arbitrary data associated with this <see cref="BroConnection"/>.
        /// </summary>
        /// <param name="key">Key identifier of data.</param>
        /// <returns>Data for given <paramref name="key"/>.</returns>
        /// <exception cref="ObjectDisposedException">Cannot get or set connection data, <see cref="BroConnection"/> is disposed.</exception>
        public IntPtr this[string key]
        {
            get
            {
                IntPtr connection = m_parent.GetValuePtr();

                if (connection == IntPtr.Zero)
                    throw new ObjectDisposedException("Cannot get connection data, Bro connection is disposed.");

                return BroApi.bro_conn_data_get(connection, key);
            }
            set
            {
                IntPtr connection = m_parent.GetValuePtr();

                if (connection == IntPtr.Zero)
                    throw new ObjectDisposedException("Cannot set connection data, Bro connection is disposed.");

                BroApi.bro_conn_data_set(connection, key, value);
            }
        }

        #endregion

        #region [ Methods ]

        /// <summary>
        /// Deletes data associated with specified <paramref name="key"/>.
        /// </summary>
        /// <param name="key">Key identifier of data.</param>
        /// <returns>The removed data if it exists, <see cref="IntPtr.Zero"/> otherwise.</returns>
        /// <exception cref="ObjectDisposedException">Cannot delete connection data, <see cref="BroConnection"/> is disposed.</exception>
        public IntPtr Delete(string key)
        {
            IntPtr connection = m_parent.GetValuePtr();

            if (connection == IntPtr.Zero)
                throw new ObjectDisposedException("Cannot delete connection data, Bro connection is disposed.");

            return BroApi.bro_conn_data_del(connection, key);
        }

        #endregion
    }
}
