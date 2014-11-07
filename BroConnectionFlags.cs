//******************************************************************************************************
//  BroConnectionFlags.cs - Gbtc
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

namespace BroccoliSharp
{
    /// <summary>
    /// Bro connection flags enumeration.
    /// </summary>
    /// <remarks>
    /// See <a href="https://www.bro.org/sphinx/broccoli-api/broccoli_8h.html">Macros</a> in <c>broccoli.h</c> file.
    /// </remarks>
    [Flags]
    public enum BroConnectionFlags
    {
        /// <summary>
        /// No flags. <c>BRO_CFLAG_NONE</c>
        /// </summary>
        None = 0,
        /// <summary>
        /// Attempt transparent reconnects. <c>BRO_CFLAG_RECONNECT</c>
        /// </summary>
        Reconnect = (1 << 0),
        /// <summary>
        /// Queue events sent while disconnected. <c>BRO_CFLAG_ALWAYS_QUEUE</c>
        /// </summary>
        AlwaysQueue = (1 << 1),

        //Shareable = (1 << 2), // DO NOT USE -- no longer supported

        /// <summary>
        /// Ask peer not to use I/O cache (default). <c>BRO_CFLAG_DONTCACHE</c>
        /// </summary>
        DontCache = (1 << 3),
        /// <summary>
        /// Process just one event at a time. <c>BRO_CFLAG_YIELD</c>
        /// </summary>
        Yield = (1 << 4),
        /// <summary>
        /// Ask peer to use I/O cache. <c>BRO_CFLAG_CACHE</c>
        /// </summary>
        Cache = (1 << 5)
    }
}
