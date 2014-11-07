//******************************************************************************************************
//  BroPacket.cs - Gbtc
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
//  10/24/2014 - J. Ritchie Carroll
//       Generated original version of source code.
//
//******************************************************************************************************

#if BRO_PCAP_SUPPORT
using System;
using BroccoliSharp.Internal;

namespace BroccoliSharp
{
    /// <summary>
    /// Represents a Bro packet used for working with libpcap packets.
    /// </summary>
    /// <remarks>
    /// Managed wrapper class for <a href="https://www.bro.org/sphinx/broccoli-api/structbro__packet.html">bro_packet</a> structure.
    /// </remarks>
    public class BroPacket : IDisposable
    {
        #region [ Members ]

        // Fields
        private IntPtr m_packet;
        private bool m_disposed;

        #endregion

        #region [ Constructors ]

        /// <summary>
        /// Creates a new <see cref="BroPacket"/> from libpcap packet header information with .NET <see cref="DateTime"/> and packet data.
        /// </summary>
        /// <param name="timestamp">Timestamp.</param>
        /// <param name="captureLength">Capture length - portion present.</param>
        /// <param name="packetData">Packet data.</param>
        /// <param name="tag">Optional tag.</param>
        /// <exception cref="ArgumentNullException"><paramref name="packetData"/> is <c>null</c>.</exception>
        /// <exception cref="OutOfMemoryException">Failed to create Bro packet.</exception>
        public BroPacket(DateTime timestamp, uint captureLength, byte[] packetData, string tag = null)
            : this(((BroTime)timestamp).ToTimeVal(), captureLength, packetData, tag)
        {
        }

        /// <summary>
        /// Creates a new <see cref="BroPacket"/> from libpcap packet header information with 64-bit timestamp and packet data.
        /// </summary>
        /// <param name="timestamp">64-bit timestamp (high-dword = Epoch seconds, low-dword = microseconds).</param>
        /// <param name="captureLength">Capture length - portion present.</param>
        /// <param name="packetData">Packet data.</param>
        /// <param name="tag">Optional tag.</param>
        /// <exception cref="ArgumentNullException"><paramref name="packetData"/> is <c>null</c>.</exception>
        /// <exception cref="OutOfMemoryException">Failed to create Bro packet.</exception>
        public BroPacket(ulong timestamp, uint captureLength, byte[] packetData, string tag = null)
            : this((uint)((timestamp & 0xFFFFFFFF00000000UL) >> 32), (uint)(timestamp & 0x00000000FFFFFFFFUL), captureLength, packetData, tag)
        {
        }

        /// <summary>
        /// Creates a new <see cref="BroPacket"/> from libpcap packet header information with seconds, microseconds and packet data.
        /// </summary>
        /// <param name="seconds">Epoch seconds of timestamp (e.g., timeval.tv_sec).</param>
        /// <param name="microseconds">Microseconds of timestamp (e.g., timeval.tv_usec).</param>
        /// <param name="captureLength">Capture length - portion present.</param>
        /// <param name="packetData">Packet data.</param>
        /// <param name="tag">Optional tag.</param>
        /// <exception cref="ArgumentNullException"><paramref name="packetData"/> is <c>null</c>.</exception>
        /// <exception cref="OutOfMemoryException">Failed to create Bro packet.</exception>
        public BroPacket(uint seconds, uint microseconds, uint captureLength, byte[] packetData, string tag = null)
            : this(new timeval
            {
                tv_sec = seconds,
                tv_usec = microseconds
            }, captureLength, packetData, tag)
        {
        }

        // Creates a new Bro packet from libpcap packet header information and packet data.
        internal BroPacket(timeval timestamp, uint captureLength, byte[] packetData, string tag = null)
        {
            if ((object)packetData == null)
                throw new ArgumentNullException("packetData");

            pcap_pkthdr header = new pcap_pkthdr();

            header.ts = timestamp;
            header.caplen = captureLength;
            header.len = (uint)packetData.Length;

            m_packet = BroApi.bro_packet_new(ref header, packetData, tag);

            if (m_packet == IntPtr.Zero)
                throw new OutOfMemoryException("Failed to create Bro packet.");
        }

        // Create new BroPacket from an existing source packet - have to clone source packet since we don't own it
        internal BroPacket(IntPtr sourcePacket)
        {
            if (sourcePacket != IntPtr.Zero)
                m_packet = BroApi.bro_packet_clone(sourcePacket);
        }

        /// <summary>
        /// Releases the unmanaged resources before this <see cref="BroPacket"/> object is reclaimed by <see cref="GC"/>.
        /// </summary>
        ~BroPacket()
        {
            Dispose(false);
        }

        #endregion

        #region [ Methods ]

        /// <summary>
        /// Releases all the resources used by this <see cref="BroPacket"/> object.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases the unmanaged resources used by this <see cref="BroPacket"/> object and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!m_disposed)
            {
                try
                {
                    if (m_packet != IntPtr.Zero)
                    {
                        BroApi.bro_packet_free(m_packet);
                        m_packet = IntPtr.Zero;
                    }
                }
                finally
                {
                    m_disposed = true;  // Prevent duplicate dispose.
                }
            }
        }

        /// <summary>
        /// Gets a clone of this <see cref="BroPacket"/>.
        /// </summary>
        /// <returns>Clone of this <see cref="BroPacket"/>.</returns>
        /// <exception cref="ObjectDisposedException">Cannot clone, <see cref="BroPacket"/> is disposed.</exception>
        public BroPacket Clone()
        {
            if (m_packet == IntPtr.Zero)
                throw new ObjectDisposedException("Cannot clone, Bro packet is disposed.");

            return new BroPacket(m_packet);
        }

        // Get pointer to Bro packet
        internal IntPtr GetValuePtr()
        {
            if (m_packet == IntPtr.Zero)
                throw new ObjectDisposedException("Cannot get value pointer, Bro packet is disposed.");

            return m_packet;
        }

        #endregion
    }
}
#endif