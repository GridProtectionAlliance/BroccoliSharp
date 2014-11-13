//******************************************************************************************************
//  BroConnection.cs - Gbtc
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
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using BroccoliSharp.Internal;

namespace BroccoliSharp
{
#if BRO_PCAP_SUPPORT
    /// <summary>
    /// Represents a Bro connection. PCAP functionality is enabled for this build.
    /// </summary>
    /// <include file='Documentation\BroConnection.xml' path='/doc/*'/>
#else
    /// <summary>
    /// Represents a Bro connection. PCAP functionality is not enabled for this build.
    /// </summary>
    /// <include file='Documentation\BroConnection.xml' path='/doc/*'/>
#endif
    public class BroConnection : IDisposable
    {
        #region [ Members ]

        // Events

        /// <summary>
        /// Occurs when a Broccoli event call-back has been received.
        /// </summary>
        public event EventHandler<BroEventArgs> ReceivedEvent;

        // Fields
#if USE_SAFE_HANDLES
        private readonly BroConnectionPtr m_connectionPtr;
#else
        private IntPtr m_connectionPtr;
#endif
        private readonly string m_hostName;
        private readonly BroConnectionFlags m_flags;
        private readonly BroEventQueue m_eventQueue;
        private readonly Dictionary<string, object> m_data;
        private readonly Dictionary<string, object> m_userData;
        private readonly Dictionary<string, Action<BroEventArgs>> m_eventHandlers;
        private string m_class;
        private bool m_disposed;

        #endregion

        #region [ Constructors ]

        // Initialize members
        private BroConnection()
        {
            m_eventQueue = new BroEventQueue(this);
            m_data = new Dictionary<string, object>();
            m_userData = new Dictionary<string, object>();
            m_eventHandlers = new Dictionary<string, Action<BroEventArgs>>();
        }

        /// <summary>
        /// Creates a new <see cref="BroConnection"/> with specified connection parameters.
        /// </summary>
        /// <param name="hostName">Host name, formatted as host:port, to connect to.</param>
        /// <param name="flags">Connection flags for this <see cref="BroConnection"/>.</param>
        /// <exception cref="ArgumentNullException"><paramref name="hostName"/> is <c>null</c>.</exception>
        /// <exception cref="OutOfMemoryException">Failed to create Bro connection.</exception>
        public BroConnection(string hostName, BroConnectionFlags flags = BroConnectionFlags.None)
            : this()
        {
            if ((object)hostName == null)
                throw new ArgumentNullException("hostName");

            m_connectionPtr = BroApi.bro_conn_new_str(hostName, flags);

            if (m_connectionPtr.IsInvalid())
                throw new OutOfMemoryException("Failed to create Bro connection.");

            m_hostName = hostName;
            m_flags = flags;
        }

        /// <summary>
        /// Creates a new server-based <see cref="BroConnection"/> using the existing <paramref name="tcpListener"/>.
        /// </summary>
        /// <param name="tcpListener">Existing open TCP listener to use for <see cref="BroConnection"/>.</param>
        /// <param name="flags">Connection flags for this <see cref="BroConnection"/>.</param>
        /// <exception cref="ArgumentNullException"><paramref name="tcpListener"/> is <c>null</c>.</exception>
        /// <exception cref="OutOfMemoryException">Failed to create Bro connection.</exception>
        [SuppressMessage("Gendarme.Rules.Interoperability", "DoNotAssumeIntPtrSizeRule")]
        public BroConnection(TcpListener tcpListener, BroConnectionFlags flags = BroConnectionFlags.None)
            : this()
        {
            if ((object)tcpListener == null)
                throw new ArgumentNullException("tcpListener");

            Socket socket = tcpListener.Server;

            m_connectionPtr = BroApi.bro_conn_new_socket(socket.Handle.ToInt32(), flags);

            if (m_connectionPtr.IsInvalid())
                throw new OutOfMemoryException("Failed to create Bro connection.");

            m_hostName = DeriveHostName(socket);
            m_flags = flags;
        }

        /// <summary>
        /// Creates a new client-based <see cref="BroConnection"/> using the existing <paramref name="tcpClient"/>.
        /// </summary>
        /// <param name="tcpClient">Existing open TCP listener to use for <see cref="BroConnection"/>.</param>
        /// <param name="flags">Connection flags for this <see cref="BroConnection"/>.</param>
        /// <exception cref="ArgumentNullException"><paramref name="tcpClient"/> is <c>null</c>.</exception>
        /// <exception cref="OutOfMemoryException">Failed to create Bro connection.</exception>
        [SuppressMessage("Gendarme.Rules.Interoperability", "DoNotAssumeIntPtrSizeRule")]
        public BroConnection(TcpClient tcpClient, BroConnectionFlags flags = BroConnectionFlags.None)
            : this()
        {
            if ((object)tcpClient == null)
                throw new ArgumentNullException("tcpClient");

            Socket socket = tcpClient.Client;

            m_connectionPtr = BroApi.bro_conn_new_socket(socket.Handle.ToInt32(), flags);

            if (m_connectionPtr.IsInvalid())
                throw new OutOfMemoryException("Failed to create Bro connection.");

            m_hostName = DeriveHostName(socket);
            m_flags = flags;
        }

        /// <summary>
        /// Creates a new <see cref="BroConnection"/> using the existing <paramref name="socket"/>.
        /// </summary>
        /// <param name="socket">Existing open socket to use for <see cref="BroConnection"/>.</param>
        /// <param name="flags">Connection flags for this <see cref="BroConnection"/>.</param>
        /// <exception cref="ArgumentNullException"><paramref name="socket"/> is <c>null</c>.</exception>
        /// <exception cref="OutOfMemoryException">Failed to create Bro connection.</exception>
        [SuppressMessage("Gendarme.Rules.Interoperability", "DoNotAssumeIntPtrSizeRule")]
        public BroConnection(Socket socket, BroConnectionFlags flags = BroConnectionFlags.None)
            : this()
        {
            if ((object)socket == null)
                throw new ArgumentNullException("socket");

            m_connectionPtr = BroApi.bro_conn_new_socket(socket.Handle.ToInt32(), flags);

            if (m_connectionPtr.IsInvalid())
                throw new OutOfMemoryException("Failed to create Bro connection.");

            m_hostName = DeriveHostName(socket);
            m_flags = flags;
        }

        /// <summary>
        /// Creates a new <see cref="BroConnection"/> using the existing <paramref name="socket"/> handle.
        /// </summary>
        /// <param name="socket">Existing open socket to use for <see cref="BroConnection"/>.</param>
        /// <param name="flags">Connection flags for this <see cref="BroConnection"/>.</param>
        /// <exception cref="OutOfMemoryException">Failed to create Bro connection.</exception>
        public BroConnection(int socket, BroConnectionFlags flags = BroConnectionFlags.None)
            : this()
        {
            m_connectionPtr = BroApi.bro_conn_new_socket(socket, flags);

            if (m_connectionPtr.IsInvalid())
                throw new OutOfMemoryException("Failed to create Bro connection.");

            m_hostName = string.Format("@FD={0}", socket);
            m_flags = flags;
        }

        /// <summary>
        /// Releases the unmanaged resources before this <see cref="BroConnection"/> object is reclaimed by <see cref="GC"/>.
        /// </summary>
        ~BroConnection()
        {
            Dispose(false);
        }

        #endregion

        #region [ Properties ]

        /// <summary>
        /// Gets host name, formatted as host:port, associated with this <see cref="BroConnection"/>.
        /// </summary>
        public string HostName
        {
            get
            {
                return m_hostName;
            }
        }

        /// <summary>
        /// Gets <see cref="BroConnectionFlags"/> associated with this <see cref="BroConnection"/>.
        /// </summary>
        public BroConnectionFlags Flags
        {
            get
            {
                return m_flags;
            }
        }

        /// <summary>
        /// Gets data storage facility that can store arbitrary data associated with this <see cref="BroConnection"/>.
        /// </summary>
        public Dictionary<string, object> Data
        {
            get
            {
                return m_data;
            }
        }

        /// <summary>
        /// Gets event queue functions for this <see cref="BroConnection"/>.
        /// </summary>
        public BroEventQueue EventQueue
        {
            get
            {
                return m_eventQueue;
            }
        }

        /// <summary>
        /// Gets or sets class associated with this <see cref="BroConnection"/>.
        /// </summary>
        /// <exception cref="ObjectDisposedException">Cannot set property, Bro connection is disposed.</exception>
        /// <remarks>
        /// Broccoli connections can indicate that they belong to a certain class of connections, which is needed
        /// primarily if multiple Bro/Broccoli instances are running on the same node and connect to a single remote
        /// peer. Set the class before calling <see cref="Connect"/> since the connection class is determined upon
        /// connection establishment.
        /// </remarks>
        public string Class
        {
            get
            {
                return m_class;
            }
            set
            {
                m_class = value;

                if (m_connectionPtr.IsInvalid())
                    throw new ObjectDisposedException("Cannot set property, Bro connection is disposed.");

                BroApi.bro_conn_set_class(m_connectionPtr, m_class);
            }
        }

        /// <summary>
        /// Gets connection class indicated by peer.
        /// </summary>
        public string PeerClass
        {
            get
            {
                if (m_connectionPtr.IsInvalid())
                    return string.Empty;

                return Marshal.PtrToStringAnsi(BroApi.bro_conn_get_peer_class(m_connectionPtr));
            }
        }

        /// <summary>
        /// Gets flag that determines whether a connection is currently alive or has died.
        /// </summary>
        public bool IsAlive
        {
            get
            {
                if (m_connectionPtr.IsInvalid())
                    return false;

                return BroApi.bro_conn_alive(m_connectionPtr) != 0;
            }
        }

        /// <summary>
        /// Gets connection statistic for the number of bytes to process in input buffer.
        /// </summary>
        /// <remarks>
        /// Returns <c>rx_buflen</c> value from the <a href="https://www.bro.org/sphinx/broccoli-api/structbro__conn__stats.html">bro_conn_stats</a> structure.
        /// </remarks>
        public int InputBufferLength
        {
            get
            {
                return GetConnectionStats().rx_buflen;
            }
        }

        /// <summary>
        /// Gets connection statistic for the number of bytes to process in output buffer.
        /// </summary>
        /// <remarks>
        /// Returns <c>tx_buflen</c> value from the <a href="https://www.bro.org/sphinx/broccoli-api/structbro__conn__stats.html">bro_conn_stats</a> structure.
        /// </remarks>
        public int OutputBufferLength
        {
            get
            {
                return GetConnectionStats().tx_buflen;
            }
        }

        /// <summary>
        /// Gets file descriptor of this <see cref="BroConnection"/>.
        /// </summary>
        public int FileDescriptor
        {
            get
            {
                if (m_connectionPtr.IsInvalid())
                    return 0;

                return BroApi.bro_conn_get_fd(m_connectionPtr);
            }
        }

#if BRO_PCAP_SUPPORT
        /// <summary>
        /// Gets or sets current packet context, i.e., the libpcap DLT linklayer type, for this <see cref="BroConnection"/>.
        /// </summary>
        /// <exception cref="ObjectDisposedException">Cannot set property, Bro connection is disposed.</exception>
        public int PacketContext
        {
            get
            {
                int linkType = -1;

                if (!m_connectionPtr.IsInvalid())
                    BroApi.bro_conn_get_packet_ctxt(m_connectionPtr, ref linkType);

                return linkType;
            }
            set
            {
                if (m_connectionPtr.IsInvalid())
                    throw new ObjectDisposedException("Cannot set property, Bro connection is disposed.");

                BroApi.bro_conn_set_packet_ctxt(m_connectionPtr, value);
            }
        }
#endif

        #endregion

        #region [ Methods ]

        /// <summary>
        /// Releases all the resources used by this <see cref="BroConnection"/> object.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases the unmanaged resources used by this <see cref="BroConnection"/> object and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!m_disposed)
            {
                try
                {
#if USE_SAFE_HANDLES
                    if ((object)m_connectionPtr != null && !m_connectionPtr.IsInvalid())
                        m_connectionPtr.Dispose();
#else
                    if (m_connectionPtr != IntPtr.Zero)
                    {
                        BroApi.bro_conn_delete(m_connectionPtr);
                        m_connectionPtr = IntPtr.Zero;
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
        /// Attempts to establish connection to peer.
        /// </summary>
        /// <exception cref="ObjectDisposedException">Cannot connect, <see cref="BroConnection"/> is disposed.</exception>
        /// <exception cref="InvalidOperationException">Failed to connect to host.</exception>
        public void Connect()
        {
            if (m_connectionPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot connect, Bro connection is disposed.");

            // Attempt connection
            if (BroApi.bro_conn_connect(m_connectionPtr) == 0)
                throw new InvalidOperationException(string.Format("Failed to connect to \"{0}\".", m_hostName));
        }

        /// <summary>
        /// Drops the current connection and reconnects, reusing all settings.
        /// </summary>
        /// <exception cref="ObjectDisposedException">Cannot reconnect, <see cref="BroConnection"/> is disposed.</exception>
        /// <exception cref="InvalidOperationException">Failed to reconnect to host.</exception>
        public void Reconnect()
        {
            if (m_connectionPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot reconnect, Bro connection is disposed.");

            // Attempt reconnection
            if (BroApi.bro_conn_reconnect(m_connectionPtr) == 0)
                throw new InvalidOperationException(string.Format("Failed to reconnect to \"{0}\".", m_hostName));
        }

        /// <summary>
        /// Requests the same events as those in <paramref name="source"/> Bro connection.
        /// </summary>
        /// <param name="source">Source <see cref="BroConnection"/> to adopt events from.</param>
        /// <exception cref="ArgumentNullException"><paramref name="source"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot adopt events, <see cref="BroConnection"/> is disposed.</exception>
        public void AdoptEvents(BroConnection source)
        {
            if ((object)source == null)
                throw new ArgumentNullException("source");

            if (m_connectionPtr.IsInvalid() || source.m_connectionPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot adopt events, Bro connection is disposed.");

            BroApi.bro_conn_adopt_events(source.m_connectionPtr, m_connectionPtr);
        }

        /// <summary>
        /// Processes input sent to the sensor by Bro.
        /// </summary>
        /// <returns><c>true</c> if any input was processed; otherwise, <c>false</c>.</returns>
        /// <remarks>
        /// This function reads all input sent to the local sensor by the Bro peering at the current
        /// <see cref="BroConnection"/>. This function cannot block. <see cref="IsAlive"/> will
        /// report the actual state of the connection after a call to <see cref="ProcessInput"/>.
        /// </remarks>
        /// <exception cref="ObjectDisposedException">Cannot process input, <see cref="BroConnection"/> is disposed.</exception>
        public bool ProcessInput()
        {
            if (m_connectionPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot process input, Bro connection is disposed.");

            return BroApi.bro_conn_process_input(m_connectionPtr) != 0;
        }

        /// <summary>
        /// Attempts to send an event to a Bro agent with the specified <paramref name="name"/> and <paramref name="parameters"/>.
        /// </summary>
        /// <param name="name">Name of the event to send.</param>
        /// <param name="parameters">Parameters to add to event.</param>
        /// <returns><c>true</c> if the event was sent or queued for later transmission; otherwise <c>false</c> on error.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="name"/> is <c>null</c>.</exception>
        public bool SendEvent(string name, params BroValue[] parameters)
        {
            using (BroEvent @event = new BroEvent(name, parameters))
            {
                return SendEvent(@event);
            }
        }

        /// <summary>
        /// Attempts to send a <see cref="BroEvent"/> to a Bro agent.
        /// </summary>
        /// <param name="event"><see cref="BroEvent"/> to attempt to send.</param>
        /// <returns><c>true</c> if the event was sent or queued for later transmission; otherwise <c>false</c> on error.</returns>
        /// <remarks>
        /// There are no automatic repeated send attempts (to minimize the effect on the code that Broccoli is linked to).
        /// To verify all events were sent, attempt to empty the queue using <see cref="BroEventQueue.Flush"/>.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="event"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot send event, <see cref="BroConnection"/> or <see cref="BroEvent"/> is disposed.</exception>
        public bool SendEvent(BroEvent @event)
        {
            if ((object)@event == null)
                throw new ArgumentNullException("event");

            if (m_connectionPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot send event, Bro connection is disposed.");

            return BroApi.bro_event_send(m_connectionPtr, @event.GetValuePtr()) != 0;
        }

        /// <summary>
        /// Enqueues a serialized event directly into the send buffer for this <see cref="BroConnection"/>.
        /// </summary>
        /// <param name="data">Serialized event.</param>
        /// <param name="length">Length of serialized event.</param>
        /// <returns><c>true</c> if successful; otherwise, <c>false</c>.</returns>
        /// <remarks>
        /// Enqueues the given event data into the transmit buffer of this <see cref="BroConnection"/>.
        /// <paramref name="length"/> bytes of <paramref name="data"/> must correspond to a single event.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="data"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="length"/> is larger than <paramref name="data"/> length.</exception>
        /// <exception cref="ObjectDisposedException">Cannot send event, <see cref="BroConnection"/> is disposed.</exception>
        public bool SendEvent(byte[] data, int length)
        {
            if ((object)data == null)
                throw new ArgumentNullException("data");

            if (length > data.Length)
                throw new ArgumentOutOfRangeException("length");

            if (m_connectionPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot send event, Bro connection is disposed.");

            return BroApi.bro_event_send_raw(m_connectionPtr, data, length) != 0;
        }

        /// <summary>
        /// Registers for events that arrive with the name of <paramref name="eventName"/>.
        /// </summary>
        /// <param name="eventName">Event name to register for.</param>
        /// <param name="userData">Any user-data to be passed to event.</param>
        /// <exception cref="ArgumentNullException"><paramref name="eventName"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot register for event, <see cref="BroConnection"/> is disposed.</exception>
        public unsafe void RegisterForEvent(string eventName, object userData = null)
        {
            if ((object)eventName == null)
                throw new ArgumentNullException("eventName");

            if (m_connectionPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot register for event, Bro connection is disposed.");

            if (userData != null)
            {
                // Track user data in managed memory space associated with event name
                lock (m_userData)
                {
                    m_userData[eventName] = userData;
                }
            }

            BroApi.bro_event_registry_add_compact(m_connectionPtr, eventName, BroCompactEventCallBack, IntPtr.Zero);
        }

        /// <summary>
        /// Registers for events that arrive with the name of <paramref name="eventName"/> using specified <paramref name="eventHandler"/>.
        /// </summary>
        /// <param name="eventName">Event name to register for.</param>
        /// <param name="eventHandler">Event handler to use for the event.</param>
        /// <param name="userData">Any user-data to be passed to event.</param>
        /// <remarks>
        /// Users can use this event registration function to provide a direct handler for the event instead
        /// attaching to the <see cref="ReceivedEvent"/> and using one common handler for all events.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="eventName"/> or <paramref name="eventHandler"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot register for event, <see cref="BroConnection"/> is disposed.</exception>
        public void RegisterForEvent(string eventName, Action<BroEventArgs> eventHandler, object userData = null)
        {
            if ((object)eventHandler == null)
                throw new ArgumentNullException("eventHandler");

            RegisterForEvent(eventName, userData);

            // Attach to common event handler for direct event handlers
            lock (m_eventHandlers)
            {
                if (m_eventHandlers.Count == 0)
                    ReceivedEvent += CommonDirectEventHandler;

                m_eventHandlers[eventName] = eventHandler;
            }
        }

        /// <summary>
        /// Unregisters for events that arrive with the name of <paramref name="eventName"/>.
        /// </summary>
        /// <param name="eventName">Event name to unregister for.</param>
        /// <exception cref="ArgumentNullException"><paramref name="eventName"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot unregister for event, <see cref="BroConnection"/> is disposed.</exception>
        public void UnregisterForEvent(string eventName)
        {
            if ((object)eventName == null)
                throw new ArgumentNullException("eventName");

            if (m_connectionPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot unregister for event, Bro connection is disposed.");

            BroApi.bro_event_registry_remove(m_connectionPtr, eventName);

            // Remove any user data stored in managed memory space for specified event name
            lock (m_userData)
            {
                m_userData.Remove(eventName);
            }

            // Detach from common event handler for direct event handlers when no events are registered
            lock (m_eventHandlers)
            {
                if (m_eventHandlers.Remove(eventName) && m_eventHandlers.Count == 0)
                    ReceivedEvent -= CommonDirectEventHandler;
            }
        }

        /// <summary>
        /// Notifies peering Bro to send events.
        /// </summary>
        /// <exception cref="ObjectDisposedException">Cannot request events, <see cref="BroConnection"/> is disposed.</exception>
        public void RequestEvents()
        {
            if (m_connectionPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot request events, Bro connection is disposed.");

            BroApi.bro_event_registry_request(m_connectionPtr);
        }

#if BRO_PCAP_SUPPORT
        /// <summary>
        /// Sends Bro <paramref name="packet"/> from this <see cref="BroConnection"/>.
        /// </summary>
        /// <param name="packet"><see cref="BroPacket"/> to send.</param>
        /// <returns><c>true</c> if successful; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="packet"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot send packet, <see cref="BroConnection"/> is disposed.</exception>
        public bool SendPacket(BroPacket packet)
        {
            if ((object)packet == null)
                throw new ArgumentNullException("packet");

            if (m_connectionPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot send packet, Bro connection is disposed.");

            return BroApi.bro_packet_send(m_connectionPtr, packet.GetValuePtr()) != 0;
        }
#endif

        /// <summary>
        /// Raises the <see cref="ReceivedEvent"/> with the specified <paramref name="args"/>.
        /// </summary>
        /// <param name="args"><see cref="BroEventArgs"/> to pass to <see cref="ReceivedEvent"/>.</param>
        protected void OnReceivedEvent(BroEventArgs args)
        {
            // If any consumers are attached to event, raise it
            if ((object)ReceivedEvent != null)
                ReceivedEvent(this, args);
        }

        // Call-back handler for Bro compact event function
#if USE_SAFE_HANDLES
        private unsafe void BroCompactEventCallBack(BroConnectionPtr bc, IntPtr user_data, bro_ev_meta* meta)
#else
        private unsafe void BroCompactEventCallBack(IntPtr bc, IntPtr user_data, bro_ev_meta* meta)
#endif
        {
            // Bail out if we didn't get a meta structure or event name
            if (meta == null || meta->ev_name == IntPtr.Zero)
                return;

            // Create new BroEventArgs from call-back metadata
            BroEventArgs args = new BroEventArgs();
            bro_ev_arg arg;

            args.EventName = Marshal.PtrToStringAnsi(meta->ev_name);
            args.EventTime = new BroTime(meta->ev_ts);

            // Get any user data passed to the call-back for the specified event name
            lock (m_userData)
            {
                object userData;

                if (m_userData.TryGetValue(args.EventName, out userData))
                    args.UserData = userData;
            }

            args.Parameters = new BroValue[meta->ev_numargs];

            for (int i = 0; i < args.Parameters.Length; i++)
            {
                arg = meta->ev_args[i];
                args.Parameters[i] = BroValue.CreateFromPtr(arg.arg_data, arg.arg_type);
            }

            OnReceivedEvent(args);
        }

        private bro_conn_stats GetConnectionStats()
        {
            bro_conn_stats stats = new bro_conn_stats();

            if (!m_connectionPtr.IsInvalid())
                BroApi.bro_conn_get_connstats(m_connectionPtr, ref stats);

            return stats;
        }

        // Attempt to derive host name from provided socket
        private string DeriveHostName(Socket socket)
        {
            if ((object)socket == null)
                return "@FD=0";

            try
            {
                IPEndPoint endPoint = socket.RemoteEndPoint as IPEndPoint;

                if ((object)endPoint == null)
                    endPoint = socket.LocalEndPoint as IPEndPoint;

                if ((object)endPoint != null)
                    return Dns.GetHostEntry(endPoint.Address).HostName;
            }
            catch
            {
            }

            return string.Format("@FD={0}", socket.Handle.ToInt32());
        }

        // Common ReceivedEvent handler for direct event handler registrations
        private void CommonDirectEventHandler(object sender, BroEventArgs e)
        {
            Action<BroEventArgs> eventHandler;

            // Call delegates for direct event handler registrations
            if (m_eventHandlers.TryGetValue(e.EventName, out eventHandler))
                eventHandler(e);
        }

        // Get pointer to Bro connection
#if USE_SAFE_HANDLES
        internal BroConnectionPtr GetValuePtr()
#else
        internal IntPtr GetValuePtr()
#endif
        {
            if (m_connectionPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot get value pointer, Bro connection is disposed.");

            return m_connectionPtr;
        }

        #endregion

        #region [ Static ]

        // Static Methods

        /// <summary>
        /// Requests the same events for the <paramref name="destination"/> as those in <paramref name="source"/>.
        /// </summary>
        /// <param name="source">Source <see cref="BroConnection"/>  to adopt events from.</param>
        /// <param name="destination">Destination <see cref="BroConnection"/>  for adopted events.</param>
        /// <exception cref="ArgumentNullException"><paramref name="source"/> or <paramref name="destination"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">Cannot adopt events, <see cref="BroConnection"/> is disposed.</exception>
        public static void AdoptEvents(BroConnection source, BroConnection destination)
        {
            if ((object)source == null)
                throw new ArgumentNullException("source");

            if ((object)destination == null)
                throw new ArgumentNullException("destination");

            if (source.m_connectionPtr.IsInvalid() || destination.m_connectionPtr.IsInvalid())
                throw new ObjectDisposedException("Cannot adopt events, Bro connection is disposed.");

            BroApi.bro_conn_adopt_events(source.m_connectionPtr, destination.m_connectionPtr);
        }

        #endregion
    }
}
