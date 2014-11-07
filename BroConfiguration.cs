//******************************************************************************************************
//  BroConfiguration.cs - Gbtc
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
//  10/27/2014 - J. Ritchie Carroll
//       Generated original version of source code.
//
//******************************************************************************************************

using System.Runtime.InteropServices;
using BroccoliSharp.Internal;

namespace BroccoliSharp
{
    /// <summary>
    /// Defines configuration file access functions for Broccoli.
    /// </summary>
    /// <remarks>
    /// See <a href="https://www.bro.org/sphinx/components/broccoli/broccoli-manual.html#configuration-files">
    /// Configuration Files</a> topic in Broccoli documentation for more details.
    /// </remarks>
    public static class BroConfiguration
    {
        private static string s_domain;

        /// <summary>
        /// Gets or sets current domain for use in a configuration file.
        /// </summary>
        /// <remarks>
        /// Broccoli's configuration files are divided into sections. The beginning of each config
        /// can have an unnamed section that will be used by default. Case is irrelevant. By setting
        /// <see cref="Domain"/> to <c>null</c>, the default domain will be selected.
        /// </remarks>
        public static string Domain
        {
            get
            {
                return s_domain;
            }
            set
            {
                s_domain = value;
                BroApi.bro_conf_set_domain(s_domain);
            }
        }

        /// <summary>
        /// Attempts to retrieve <see cref="int"/> based value from the configuration. 
        /// </summary>
        /// <param name="valueName">Key name for the value to retrieve.</param>
        /// <param name="value">The retrieved value.</param>
        /// <returns><c>true</c> if <paramref name="valueName"/> was found; otherwise, <c>false</c>.</returns>
        public static bool TryGetValue(string valueName, out int value)
        {
            return BroApi.bro_conf_get_int(valueName, out value) != 0;
        }

        /// <summary>
        /// Attempts to retrieve <see cref="double"/> based value from the configuration. 
        /// </summary>
        /// <param name="valueName">Key name for the value to retrieve.</param>
        /// <param name="value">The retrieved value.</param>
        /// <returns><c>true</c> if <paramref name="valueName"/> was found; otherwise, <c>false</c>.</returns>
        public static bool TryGetValue(string valueName, out double value)
        {
            return BroApi.bro_conf_get_dbl(valueName, out value) != 0;
        }

        /// <summary>
        /// Attempts to retrieve <see cref="string"/> based value from the configuration. 
        /// </summary>
        /// <param name="valueName">Key name for the value to retrieve.</param>
        /// <param name="value">The retrieved value.</param>
        /// <returns><c>true</c> if <paramref name="valueName"/> was found; otherwise, <c>false</c>.</returns>
        public static bool TryGetValue(string valueName, out string value)
        {
            value = Marshal.PtrToStringAnsi(BroApi.bro_conf_get_str(valueName));
            return ((object)value != null);
        }
    }
}
