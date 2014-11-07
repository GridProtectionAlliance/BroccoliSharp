//******************************************************************************************************
//  BroApi.cs - Gbtc
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
//  10/14/2014 - J. Ritchie Carroll
//       Generated original version of source code.
//
//******************************************************************************************************

using System;
using System.Runtime.InteropServices;
using System.Security;

namespace BroccoliSharp.Internal
{
    /// <summary>
    /// Broccoli API interop function declarations based on "broccoli.h.in".
    /// </summary>
    [SuppressUnmanagedCodeSecurity]
    internal static class BroApi
    {
        // Mono will suffix library filename with .so or .dylib based on operating system
        private const string BroccoliLibrary = "libbroccoli";

        #region [ Callback Signatures ]

        // /**
        // * BroEventFunc - The signature of expanded event callbacks.
        // * @param bc Bro connection handle.
        // * @param user_data user data provided to bro_event_registry_add().
        // * @param ... varargs.
        // *
        // * This is the signature of callbacks for handling received
        // * Bro events, called in the argument-expanded style.  For details
        // * see bro_event_registry_add().
        // */
        //public delegate void BroEventFunc(IntPtr bc, IntPtr user_data, __arglist);

        /**
         * BroCompactEventFunc - The signature of compact event callbacks.
         * @param bc Bro connection handle.
         * @param user_data user data provided to bro_event_registry_add_compact().
         * @param meta metadata for the event.
         *
         * This is the signature of callbacks for handling received
         * Bro events, called in the compact-argument style. For details
         * see bro_event_registry_add_compact().
         */
        public delegate void BroCompactEventFunc(IntPtr bc, IntPtr user_data, ref bro_ev_meta meta);

        /**
         * BroTableCallback - The signature of callbacks for iterating over tables.
         * @param key a pointer to the key of a key-value pair.
         * @param val a pointer to @p key's corresponding value.
         * @param user_data user data passed through.
         *
         * This is the signature of callbacks used when iterating over all
         * elements stored in a BroTable.
         *
         * @returns TRUE if iteration should continue, FALSE if done.
         */
        public delegate int BroTableCallback(IntPtr key, IntPtr val, IntPtr user_data);

        /**
         * BroSetCallback - The signature of callbacks for iterating over sets.
         * @param val a pointer to an element in the set.
         * @param user_data user data passed through.
         *
         * This is the signature of callbacks used when iterating over all
         * elements stored in a BroSet.
         *
         * @returns TRUE if iteration should continue, FALSE if done.
         */
        public delegate int BroSetCallback(IntPtr val, IntPtr user_data);

        #endregion

        #region [ Initialization ]

        // Exception here is desired since this will indicate that Broccoli API is not installed or having trouble
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1065")]
        static BroApi()
        {
            // Calling bro_init from static constructor so it is only called once - we won't be using
            // OpenSSL from a .NET application so we will always pass in null into the initializer.
            if (bro_init(IntPtr.Zero) == 0)
                throw new TypeInitializationException("BroccoliSharp.Internal.BroApi", new Exception("Failed to initialize Broccoli library - bro_init() function reported failure."));
        }

        /**
         * bro_init - Initializes the library.
         * @param ctx pointer to a BroCtx structure.
         *
         * The function initializes the library. It MUST be called before
         * anything else in Broccoli. Specific initialization context may be
         * provided using a BroCtx structure pointed to by ctx. It may be
         * omitted by passing %NULL, for default values. See bro_init_ctx() for
         * initialization of the context structure to default values.
         *
         * @returns %TRUE if initialization succeeded, %FALSE otherwise.
         */
        [DllImport(BroccoliLibrary)]
        private static extern int bro_init(IntPtr ctx);

        #endregion

        #region [ Connection Handling ]

        /**
         * bro_conn_new - Creates and returns a handle for a connection to a remote Bro.
         * @param ip_addr 4-byte IP address of Bro to contact, in network byte order.
         * @param port of machine at @p ip_addr to contact, in network byte order.
         * @param flags an or-combination of the %BRO_CONN_xxx flags.
         *
         * The function creates a new Bro connection handle for communication with
         * Bro through a network. Depending on the flags passed in, the connection
         * and its setup process can be adjusted. If you don't want to pass any
         * flags, use %BRO_CFLAG_NONE.
         *
         * @returns pointer to a newly allocated and initialized
         * Bro connection structure. You need this structure for all
         * other calls in order to identify the connection to Bro.
         */
        [DllImport(BroccoliLibrary)]
        public static extern IntPtr bro_conn_new(uint ip_addr, ushort port, BroConnectionFlags flags);

        /**
         * bro_conn_new_str - Same as bro_conn_new(), but accepts strings for hostname and port.
         * @param hostname string describing the host and port to connect to.
         * @param flags an or-combination of the %BRO_CONN_xxx flags.
         *
         * The function is identical to bro_conn_new(), but allows you to specify the
         * host and port to connect to in a string as "&lt;hostname&gt;:&lt;port&gt;". @p flags can
         * be used to adjust the connection features and the setup process. If you don't
         * want to pass any flags, use %BRO_CFLAG_NONE.
         *
         * @returns pointer to a newly allocated and initialized
         * Bro connection structure. You need this structure for all
         * other calls in order to identify the connection to Bro.
         */
        [DllImport(BroccoliLibrary, BestFitMapping = false)]
        public static extern IntPtr bro_conn_new_str([MarshalAs(UnmanagedType.LPStr)] string hostname, BroConnectionFlags flags);

        /**
         * bro_conn_new_socket - Same as bro_conn_new(), but uses existing socket.
         * @param socket open socket.
         * @param flags an or-combination of the %BRO_CONN_xxx flags.
         *
         * The function is identical to bro_conn_new(), but allows you to pass in an
         * open socket to use for the communication. @p flags can be used to
         * adjust the connection features and the setup process. If you don't want to
         * pass any flags, use %BRO_CFLAG_NONE.
         *
         * @returns pointer to a newly allocated and initialized
         * Bro connection structure. You need this structure for all
         * other calls in order to identify the connection to Bro.
         */
        [DllImport(BroccoliLibrary)]
        public static extern IntPtr bro_conn_new_socket(int socket, BroConnectionFlags flags);

        /**
         * bro_conn_set_class - Sets a connection's class identifier.
         * @param bc connection handle.
         * @param classname class identifier.
         *
         * Broccoli connections can indicate that they belong to a certain class
         * of connections, which is needed primarily if multiple Bro/Broccoli
         * instances are running on the same node and connect to a single remote
         * peer. You can set this class with this function, and you have to do so
         * before calling bro_connect() since the connection class is determined
         * upon connection establishment. You remain responsible for the memory
         * pointed to by @p classname.
         */
        [DllImport(BroccoliLibrary, BestFitMapping = false)]
        public static extern void bro_conn_set_class(IntPtr bc, [MarshalAs(UnmanagedType.LPStr)] string classname);

        /**
         * bro_conn_get_peer_class - Reports connection class indicated by peer.	
         * @param bc connection handle.
         *
         * @returns a string containing the connection class indicated by the peer,
         * if any, otherwise %NULL.
         */
        [DllImport(BroccoliLibrary)]
        public static extern IntPtr bro_conn_get_peer_class(IntPtr bc);

        /**
         * bro_conn_get_connstats - Reports connection properties.
         * @param bc connection handle.
         * @param cs BroConnStats handle.
         * 
         * The function fills the BroConnStats structure provided via @p cs with
         * information about the given connection.
         */
        [DllImport(BroccoliLibrary)]
        public static extern void bro_conn_get_connstats(IntPtr bc, ref bro_conn_stats cs);

        /**
         * bro_conn_connect - Establish connection to peer.
         * @param bc connection handle.
         *
         * The function attempts to set up and configure a connection to
         * the peer configured when the connection handle was obtained.
         *
         * @returns %TRUE on success, %FALSE on failure.
         */
        [DllImport(BroccoliLibrary)]
        public static extern int bro_conn_connect(IntPtr bc);

        /**
         * bro_conn_reconnect - Drop the current connection and reconnect, reusing all settings.
         * @param bc Bro connection handle.
         *
         * The functions drops the current connection identified by @p bc and attempts
         * to establish a new one with all the settings associated with @p bc,
         * including full handshake completion.
         *
         * @returns %TRUE if successful, %FALSE otherwise. No matter what the outcome,
         * you can continue to use @p bc as normal (e.g. you have to release it using
         * bro_conn_delete()).
         */
        [DllImport(BroccoliLibrary)]
        public static extern int bro_conn_reconnect(IntPtr bc);

        /**
         * bro_conn_delete - terminates and releases connection.
         * @param bc Bro connection handle.
         *
         * This function will terminate the given connection if necessary
         * and release all resources associated with the connection handle.
         * 
         *
         * @returns %FALSE on error, %TRUE otherwise.
         */
        [DllImport(BroccoliLibrary)]
        public static extern int bro_conn_delete(IntPtr bc);

        /**
         * bro_conn_alive - Reports whether a connection is currently alive or has died.
         * @param bc Bro connection handle.
 
         * This predicate reports whether the connection handle is currently
         * usable for sending/receiving data or not, e.g. because the peer
         * died. The function does not actively check and update the
         * connection's state, it only reports the value of flags indicating
         * its status. In particular, this means that when calling
         * bro_conn_alive() directly after a select() on the connection's
         * descriptor, bro_conn_alive() may return an incorrent value. It will
         * however return the correct value after a subsequent call to
         * bro_conn_process_input(). Also note that the connection is also
         * dead after the connection handle is obtained and before
         * bro_conn_connect() is called.
         * 
         * @returns %TRUE if the connection is alive, %FALSE otherwise.
         */
        [DllImport(BroccoliLibrary)]
        public static extern int bro_conn_alive(IntPtr bc);

        /**
         * bro_conn_adopt_events - Makes one connection send out the same events as another.
         * @param src Bro connection handle for connection whose event list to adopt.
         * @param dst Bro connection handle for connection whose event list to change.
         *
         * The function makes the connection identified by @p dst use the same event
         * mask as the one identified by @p src.
         */
        [DllImport(BroccoliLibrary)]
        public static extern void bro_conn_adopt_events(IntPtr src, IntPtr dst);

        /**
         * bro_conn_get_fd - Returns file descriptor of a Bro connection.
         * @param bc Bro connection handle.
         *
         * If you need to know the file descriptor of the connection
         * (such as when select()ing it, etc.), use this accessor function.
         *
         * @returns file descriptor for connection @p bc, or negative value
         * on error.
         */
        [DllImport(BroccoliLibrary)]
        public static extern int bro_conn_get_fd(IntPtr bc);

        /**
         * bro_conn_process_input - Processes input sent to the sensor by Bro.
         * @param bc Bro connection handle.
         *
         * The function reads all input sent to the local sensor by the
         * Bro peering at the connection identified by @p bc. It is up
         * to you to find a spot in the application you're instrumenting
         * to make sure this is called. This function cannot block.
         * bro_conn_alive() will report the actual state of the connection
         * after a call to bro_conn_process_input().
         *
         * @returns %TRUE if any input was processed, %FALSE otherwise.
         */
        [DllImport(BroccoliLibrary)]
        public static extern int bro_conn_process_input(IntPtr bc);

        #endregion

        #region [ Bro Events ]

        /**
         * bro_event_new - Creates a new empty event with a given name.
         * @param event_name name of the Bro event.
         *
         * The function creates a new empty event with the given
         * name and returns it.
         *
         * @returns new event, or %NULL if allocation failed.
         */
        [DllImport(BroccoliLibrary, BestFitMapping = false)]
        public static extern IntPtr bro_event_new([MarshalAs(UnmanagedType.LPStr)] string event_name);

        /**
         * bro_event_free - Releases all memory associated with an event.
         * @param be event to release.
         *
         * The function releases all memory associated with @p be. Note 
         * that you do NOT have to call this after sending an event.
         */
        [DllImport(BroccoliLibrary)]
        public static extern void bro_event_free(IntPtr be);

        /**
         * bro_event_add_val - Adds a parameter to an event.
         * @param be event to add to.
         * @param type numerical type identifier (a %BRO_TYPE_xxx constant).
         * @param type_name optional name of specialized type.
         * @param val value to add to event.
         *
         * The function adds the given @p val to the argument list of
         * event @p be. The type of @p val is derived from @p type, and may be
         * specialized to the type named @p type_name. If @p type_name is not
         * desired, use %NULL.
         *
         * @p val remains the caller's responsibility and is copied internally.
         *
         * @returns %TRUE if the operation was successful, %FALSE otherwise.
         */
        [DllImport(BroccoliLibrary, BestFitMapping = false)]
        public static extern int bro_event_add_val(IntPtr be, BroType type, [MarshalAs(UnmanagedType.LPStr)] string type_name, IntPtr val);

        /**
         * bro_event_set_val - Replace a value in an event.
         * @param be event handle.
         * @param val_num number of the value to replace, starting at 0.
         * @param type numerical type identifier (a %BRO_TYPE_xxx constant).
         * @param type_name optional name of specialized type.
         * @param val value to put in.
         *
         * The function replaces whatever value is currently stored in the
         * event pointed to by @p be with the value specified through the @p type and
         * @p val arguments. If the event does not currently hold enough
         * values to replace one in position @p val_num, the function does
         * nothing. If you want to indicate a type specialized from @p type,
         * use @p type_name to give its name, otherwise pass %NULL for @p type_name.
         *
         * @returns %TRUE if successful, %FALSE on error.
         */
        [DllImport(BroccoliLibrary, BestFitMapping = false)]
        public static extern int bro_event_set_val(IntPtr be, int val_num, BroType type, [MarshalAs(UnmanagedType.LPStr)] string type_name, IntPtr val);

        /**
         * bro_event_send - Tries to send an event to a Bro agent.
         * @param bc Bro connection handle.
         * @param be event to send.
         *
         * The function tries to send @p be to the Bro agent connected
         * through @p bc. Regardless of the outcome, you do NOT have
         * to release the event afterwards using bro_event_free().
         * 
         * @returns %TRUE if the event got sent or queued for later transmission,
         * %FALSE on error. There are no automatic repeated send attempts
         * (to minimize the effect on the code that Broccoli is linked to).
         * If you have to make sure that everything got sent, you have
         * to try to empty the queue using bro_event_queue_flush(), and
         * also look at bro_event_queue_empty().
         */
        [DllImport(BroccoliLibrary)]
        public static extern int bro_event_send(/*BroConn*/ IntPtr bc, /*BroEvent*/ IntPtr be);

        /**
         * bro_event_send_raw - Enqueues a serialized event directly into a connection's send buffer.
         * @param bc Bro connection handle.
         * @param data pointer to serialized event data.
         * @param data_len length of buffer pointed to by @p data.
         *
         * The function enqueues the given event data into @p bc's transmit buffer.
         * @p data_len bytes at @p data must correspond to a single event.
         *
         * @returns %TRUE if successful, %FALSE on error.
         */
        [DllImport(BroccoliLibrary)]
        public static extern int bro_event_send_raw(IntPtr bc, byte[] data, int data_len);

        /**
         * bro_event_queue_length - Returns current queue length.
         * @param bc Bro connection handle.
         *
         * Use this function to find out how many events are currently queued
         * on the client side.
         *
         * @returns number of items currently queued.
         */
        [DllImport(BroccoliLibrary)]
        public static extern int bro_event_queue_length(IntPtr bc);

        /**
         * bro_event_queue_length_max - Returns maximum queue length.
         * @param bc Bro connection handle.
         *
         * Use this function to find out how many events can be queued before
         * events start to get dropped.
         *
         * @returns maximum possible queue size.
         */
        [DllImport(BroccoliLibrary)]
        public static extern int bro_event_queue_length_max(IntPtr bc);

        /**
         * bro_event_queue_flush - Tries to flush the send queue of a connection.
         * @param bc Bro connection handle.
         *
         * The function tries to send as many queued events to the Bro
         * agent as possible.
         *
         * @returns remaining queue length after flush.
         */
        [DllImport(BroccoliLibrary)]
        public static extern int bro_event_queue_flush(IntPtr bc);

        #endregion

        #region [ Bro Event Callbacks ]

        // /**
        // * bro_event_registry_add - Adds an expanded-argument event callback to the event registry.
        // * @param bc Bro connection handle.
        // * @param event_name Name of events that trigger callback.
        // * @param func callback to invoke.
        // * @param user_data user data passed through to the callback.
        // *
        // * This function registers the callback @p func to be invoked when events
        // * of name @p event_name arrive on connection @p bc. @p user_data is passed
        // * along to the callback, which will receive it as the second parameter. You
        // * need to ensure that the memory @p user_data points to is valid during the
        // * time the callback might be invoked.
        // *
        // * Note that this function only registers the callback in the state
        // * associated with @p bc. If you use bro_event_registry_add() and @p bc
        // * has not yet been connected via bro_conn_connect(), then no further
        // * action is required. bro_conn_connect() requests any registered event types.
        // * If however you are requesting additional event types after the connection has
        // * been established, then you also need to call bro_event_registry_request()
        // * in order to signal to the peering Bro that you want to receive those events.
        // */
        //[DllImport(BroccoliLibrary)]
        //public static extern void bro_event_registry_add(IntPtr bc, string event_name, BroEventFunc func, IntPtr user_data);

        /**
         * bro_event_registry_add_compact - Adds a compact-argument event callback to the event registry.
         * @param bc Bro connection handle.
         * @param event_name Name of events that trigger callback.
         * @param func callback to invoke.
         * @param user_data user data passed through to the callback.
         *
         * This function registers the callback @p func to be invoked when events
         * of name @p event_name arrive on connection @p bc. @p user_data is passed
         * along to the callback, which will receive it as the second parameter. You
         * need to ensure that the memory @p user_data points to is valid during the
         * time the callback might be invoked. See bro_event_registry_add() for
         * details.
         */
        [DllImport(BroccoliLibrary, BestFitMapping = false)]
        public static extern void bro_event_registry_add_compact(IntPtr bc, [MarshalAs(UnmanagedType.LPStr)] string event_name, BroCompactEventFunc func, IntPtr user_data);

        /**
         * bro_event_registry_remove - Removes an event handler.
         * @param bc Bro connection handle.
         * @param event_name event to ignore from now on.
         *
         * The function removes all callbacks for event @p event_name from the
         * event registry for connection @p bc.
         */
        [DllImport(BroccoliLibrary, BestFitMapping = false)]
        public static extern void bro_event_registry_remove(IntPtr bc, [MarshalAs(UnmanagedType.LPStr)] string event_name);

        /**
         * bro_event_registry_request - Notifies peering Bro to send events.
         * @param bc Bro connection handle.
         *
         * The function requests the events you have previously requested using
         * bro_event_registry_add() from the Bro listening on @p bc.
         */
        [DllImport(BroccoliLibrary)]
        public static extern void bro_event_registry_request(IntPtr bc);

        #endregion

        #region [ Configuration Access ]

        /**
         * bro_conf_set_domain - Sets the current domain to use in a config file.
         * @param domain name of the domain, or %NULL.
         *
         * Broccoli's config files are divided into sections. At the beginning of
         * each config file you can have an unnamed section that will be used by
         * default. Case is irrelevant. By passing %NULL for @p domain, you select
         * the default domain, otherwise the one that matches @p domain. @p domain is
         * copied internally.
         */
        [DllImport(BroccoliLibrary, BestFitMapping = false)]
        public static extern void bro_conf_set_domain([MarshalAs(UnmanagedType.LPStr)] string domain);

        /**
         * bro_conf_get_int - Retrieves an integer from the configuration.
         * @param val_name key name for the value.
         * @param val result pointer for the value.
         *
         * The function tries to find an integer item named @p val_name in the
         * configuration. If it is found, its value is placed into the
         * int pointed to by @p val.
         *
         * @returns %TRUE if @p val_name was found, %FALSE otherwise.
         */
        [DllImport(BroccoliLibrary, BestFitMapping = false)]
        public static extern int bro_conf_get_int([MarshalAs(UnmanagedType.LPStr)] string val_name, out int val);

        /**
         * bro_conf_get_dbl - Retrieves a double float from the configuration.
         * @param val_name key name for the value.
         * @param val result pointer for the value.
         *
         * The function tries to find a double float item named @p val_name 
         * in the configuration. If it is found, its value is placed into the
         * double pointed to by @p val.
         *
         * @returns %TRUE if @p val_name was found, %FALSE otherwise.
         */
        [DllImport(BroccoliLibrary, BestFitMapping = false)]
        public static extern int bro_conf_get_dbl([MarshalAs(UnmanagedType.LPStr)] string val_name, out double val);

        /**
         * bro_conf_get_str - Retrieves an integer from the configuration.
         * @param val_name key name for the value.
         *
         * The function tries to find a string item named @p val_name in the
         * configuration.
         *
         * @returns the config item if @p val_name was found, %NULL otherwise.
         * A returned string is stored internally and not to be modified. If
         * you need to keep it around, strdup() it.
         */
        [DllImport(BroccoliLibrary, BestFitMapping = false)]
        public static extern IntPtr bro_conf_get_str([MarshalAs(UnmanagedType.LPStr)] string val_name);

        #endregion

        #region [ Strings ]

        /**
         * bro_string_init - Initializes an existing string structure.
         * @param bs string pointer.
         *
         * The function initializes the BroString pointed to by @p bs. Use this
         * function before using the members of a BroString you're using on the
         * stack.
         */
        [DllImport(BroccoliLibrary)]
        public static extern void bro_string_init(ref bro_string bs);

        /**
         * bro_string_set - Sets a BroString's contents.
         * @param bs string pointer.
         * @param s C ASCII string.
         *
         * The function initializes the BroString pointed to by @p bs to the string
         * given in @p s. @p s's content is copied, so you can modify or free @p s
         * after calling this, and you need to call bro_string_cleanup() on the
         * BroString pointed to by @p bs.
         *
         * @returns %TRUE if successful, %FALSE otherwise.
         */
        [DllImport(BroccoliLibrary, BestFitMapping = false)]
        public static extern int bro_string_set(ref bro_string bs, [MarshalAs(UnmanagedType.LPStr)] string s);

        /**
         * bro_string_set_data - Sets a BroString's contents.
         * @param bs string pointer.
         * @param data arbitrary data.
         * @param data_len length of @p data.
         *
         * The function initializes the BroString pointed to by @p bs to @p data_len
         * bytes starting at @p data. @p data's content is copied, so you can modify
         * or free @p data after calling this.
         *
         * @returns %TRUE if successful, %FALSE otherwise.
         */
        [DllImport(BroccoliLibrary)]
        public static extern int bro_string_set_data(ref bro_string bs, byte[] data, int data_len);

        /**
         * bro_string_get_data - Returns pointer to the string data.
         * @param bs string pointer.
         *
         * The function returns a pointer to the string's internal data. You
         * can copy out the string using this function in combination with
         * bro_string_get_length(), for obtaining the string's length.
         *
         * @returns pointer to string, or %NULL on error.
         */
        [DllImport(BroccoliLibrary)]
        public static unsafe extern sbyte* bro_string_get_data(ref bro_string bs);

        /**
         * bro_string_get_length - Returns string's length.
         * @param bs string pointer.
         *
         * @returns the string's length.
         */
        [DllImport(BroccoliLibrary)]
        public static extern int bro_string_get_length(ref bro_string bs);

        /**
         * bro_string_copy - Duplicates a BroString.
         * @param bs string pointer.
         *
         * @returns a deep copy of the BroString pointed to by @p bs, or %NULL on
         * error.
         */
        // NOTE: User owns and must now bro_string_free returned calloc allocated structure
        [DllImport(BroccoliLibrary)]
        public static unsafe extern bro_string* bro_string_copy(ref bro_string bs);

        /**
         * bro_string_assign - Duplicates a BroString's content, assigning it to an existing one.
         * @param src source string.
         * @param dst target string.
         *
         * Copies the string content pointed to by @p src into the existing
         * BroString pointed to by @p dst. bro_string_cleanup() is called on
         * @p dst before the assignment.
         */
        [DllImport(BroccoliLibrary)]
        public static extern void bro_string_assign(ref bro_string src, ref bro_string dst);

        /**
         * bro_string_cleanup - Cleans up existing BroString.
         * @param bs string pointer.
         *
         * This function releases all contents claimed by the BroString pointed
         * to by @p bs, without releasing that BroString structure itself. Use
         * this when manipulating a BroString on the stack, paired with
         * bro_string_init().
         */
        [DllImport(BroccoliLibrary)]
        public static extern void bro_string_cleanup(ref bro_string bs);

        /**
         * bro_string_free - Cleans up dynamically allocated BroString.
         * @param bs string pointer.
         * 
         * This function releases the entire BroString pointed to by @p bs, including
         * the BroString structure itself.
         */
        [DllImport(BroccoliLibrary)]
        public static extern void bro_string_free(ref bro_string bs);

        #endregion

        #region [ Record Handling ]

        /**
         * bro_record_new - Creates a new record.
         *
         * The function allocates and initializes a new empty record. BroRecords
         * are used for adding and retrieving record values to/from events. You
         * do not have to specify a record type separately when you create a
         * record. The type is defined implicitly by the sequence of types formed
         * by the sequence of values added to the record, along with the names for
         * each value. See the manual for details.
         *
         * @returns a new record, or %NULL on error.
         */
        [DllImport(BroccoliLibrary)]
        public static extern IntPtr bro_record_new();

        /**
         * bro_record_free - Releases a record.
         * @param rec record handle.
         *
         * The function releases all memory consumed by the record pointed to
         * by @p rec.
         */
        [DllImport(BroccoliLibrary)]
        public static extern void bro_record_free(IntPtr rec);

        /**
         * bro_record_get_length - Returns number of fields in record.
         * @param rec record handle.
         *
         * @returns the number of fields in the record.
         */
        [DllImport(BroccoliLibrary)]
        public static extern int bro_record_get_length(IntPtr rec);

        /**
         * bro_record_add_val - Adds a value to a record.
         * @param rec record handle.
         * @param name field name of the added val.
         * @param type numerical type tag of the new val.
         * @param type_name optional name of specialized type.
         * @param val pointer to the new val.
         *
         * The function adds a new field to the record pointed to by @p rec and
         * assigns the value passed in to that field. The field name is given
         * in @p name, the type of the value is given in @p type and must be one of
         * the %BRO_TYPE_xxx constants defined in broccoli.h. The type you give
         * implies what data type @p val must be pointing to; see the manual for
         * details. If you want to indicate a type specialized from @p type,
         * use @p type_name to give its name, otherwise pass %NULL for @p type_name.
         * It is possible to leave fields unassigned, in that case, pass in
         * %NULL for @p val.
         *
         * @p val remains the caller's responsibility and is copied internally.
         *
         * @returns %TRUE on success, %FALSE on error.
         */
        [DllImport(BroccoliLibrary, BestFitMapping = false)]
        public static extern int bro_record_add_val(IntPtr rec, [MarshalAs(UnmanagedType.LPStr)] string name, BroType type, [MarshalAs(UnmanagedType.LPStr)] string type_name, IntPtr val);

        /**
         * bro_record_get_nth_val - Retrieves a value from a record by field index.
         * @param rec record handle.
         * @param num field index, starting from 0.
         * @param type value-result argument for the expected/actual type of the value.
         *
         * The function returns the @p num'th value of the record pointed to
         * by @p rec, expected to be of @p type. The returned value is internal
         * and needs to be duplicated if you want to keep it around. Upon
         * return, the int pointed to by @p type tells you the type of the returned
         * value, as a BRO_TYPE_xxx type tag. If the int pointed to upon calling
         * the function has the value BRO_TYPE_UNKNOWN, no type checking is
         * performed and the value is returned. If it is any other type tag,
         * its value is compared to that of the value, and if they match, the
         * value is returned. Otherwise, the return value is %NULL. If you don't
         * care about type enforcement and don't want to know the value's type,
         * you may pass %NULL for @p type.
         *
         * @returns pointer to queried value on success, %NULL on error.
         */
        [DllImport(BroccoliLibrary)]
        public static extern IntPtr bro_record_get_nth_val(IntPtr rec, int num, ref BroType type);

        /**
         * bro_record_get_nth_name - Retrieves a name from a record by field index.
         * @param rec record handle.
         * @param num field index, starting from 0.
         *
         * The function returns the @p num'th name of the record pointed to by @p rec. 
         *
         * @returns field name on success, %NULL on error.
         */
        [DllImport(BroccoliLibrary)]
        public static extern IntPtr bro_record_get_nth_name(IntPtr rec, int num);

        /**
         * bro_record_get_named_val - Retrieves a value from a record by field name.
         * @param rec record handle.
         * @param name field name.
         * @param type value-result argument for the expected/actual type of the value.
         *
         * The function returns the value of the field named @p name in the
         * record pointed to by @p rec. The returned value is internal and needs
         * to be duplicated if you want to keep it around. @p type works as with
         * bro_record_get_nth_val(), see there for more details.
         *
         * @returns pointer to queried value on success, %NULL on error.
         */
        [DllImport(BroccoliLibrary, BestFitMapping = false)]
        public static extern IntPtr bro_record_get_named_val(IntPtr rec, [MarshalAs(UnmanagedType.LPStr)] string name, ref BroType type);

        /**
         * bro_record_set_nth_val - Replaces a value in a record, identified by field index.
         * @param rec record handle.
         * @param num field index, starting from 0.
         * @param type expected type of the value.
         * @param type_name optional name of specialized type.
         * @param val pointer to new val.
         *
         * The function replaces the @p num'th value of the record pointed to
         * by @p rec, expected to be of @p type. All values are copied internally
         * so what @p val points to stays unmodified. The value of @p type implies
         * what @p result must be pointing to. See the manual for details.
         * If you want to indicate a type specialized from @p type, use
         * @p type_name to give its name, otherwise pass %NULL for @p type_name.
         *
         * @returns %TRUE on success, %FALSE on error.
         */
        [DllImport(BroccoliLibrary, BestFitMapping = false)]
        public static extern int bro_record_set_nth_val(IntPtr rec, int num, BroType type, [MarshalAs(UnmanagedType.LPStr)] string type_name, IntPtr val);

        /**
         * bro_record_set_named_val - Replaces a value in a record, identified by name.
         * @param rec record handle.
         * @param name field name.
         * @param type expected type of the value.
         * @param type_name optional name of specialized type.
         * @param val pointer to new val.
         *
         * The function replaces the value named @p name in the record pointed to
         * by @p rec, expected to be of @p type. All values are copied internally
         * so what @p val points to stays unmodified. The value of @p type implies
         * what @p result must be pointing to. See the manual for details.
         * If you want to indicate a type specialized from @p type,
         * use @p type_name to give its name, otherwise pass %NULL for @p type_name.
         *
         * @returns %TRUE on success, %FALSE on error.
         */
        [DllImport(BroccoliLibrary, BestFitMapping = false)]
        public static extern int bro_record_set_named_val(IntPtr rec, [MarshalAs(UnmanagedType.LPStr)] string name, BroType type, [MarshalAs(UnmanagedType.LPStr)] string type_name, IntPtr val);

        #endregion

        #region [ Tables & Sets ]

        // TODO: When comments are added to broccoli.h.in for these functions, copy them here

        [DllImport(BroccoliLibrary)]
        public static extern IntPtr bro_table_new();

        [DllImport(BroccoliLibrary)]
        public static extern void bro_table_free(IntPtr tbl);

        [DllImport(BroccoliLibrary)]
        public static extern int bro_table_insert(IntPtr tbl, BroType key_type, IntPtr key, BroType val_type, IntPtr val);

        [DllImport(BroccoliLibrary)]
        public static extern IntPtr bro_table_find(IntPtr tbl, IntPtr key);

        [DllImport(BroccoliLibrary)]
        public static extern int bro_table_get_size(IntPtr tbl);

        [DllImport(BroccoliLibrary)]
        public static extern void bro_table_foreach(IntPtr tbl, BroTableCallback cb, IntPtr user_data);

        [DllImport(BroccoliLibrary)]
        public static extern void bro_table_get_types(IntPtr tbl, ref BroType key_type, ref BroType val_type);

        [DllImport(BroccoliLibrary)]
        public static extern IntPtr bro_set_new();

        [DllImport(BroccoliLibrary)]
        public static extern void bro_set_free(IntPtr set);

        [DllImport(BroccoliLibrary)]
        public static extern int bro_set_insert(IntPtr set, BroType type, IntPtr val);

        [DllImport(BroccoliLibrary)]
        public static extern int bro_set_find(IntPtr set, IntPtr key);

        [DllImport(BroccoliLibrary)]
        public static extern int bro_set_get_size(IntPtr set);

        [DllImport(BroccoliLibrary)]
        public static extern void bro_set_foreach(IntPtr set, BroSetCallback cb, IntPtr user_data);

        [DllImport(BroccoliLibrary)]
        public static extern void bro_set_get_type(IntPtr set, ref BroType type);

        #endregion

        #region [ Vectors ]

        /**
         * bro_vector_new - Creates a new vector.
         *
         * The function allocates and initializes a new empty vector.
         *
         * @returns a new vector, or %NULL on error.
         */
        [DllImport(BroccoliLibrary)]
        public static extern IntPtr bro_vector_new();

        /**
         * bro_vector_free - Releases a vector.
         * @param vec vector handle.
         *
         * The function releases all memory consumed by the vector pointed to
         * by @p vec.
         */
        [DllImport(BroccoliLibrary)]
        public static extern void bro_vector_free(IntPtr vec);

        /**
         * bro_vector_get_length - Returns number of elements in vector.
         * @param vec vector handle.
         *
         * @returns the number of elements in the vector.
         */
        [DllImport(BroccoliLibrary)]
        public static extern int bro_vector_get_length(IntPtr vec);

        /**
         * bro_vector_add_val - Adds a value to a vector.
         * @param vec vector handle.
         * @param type numerical type tag of the new val.
         * @param type_name optional name of specialized type.
         * @param val pointer to the new val.
         *
         * The function adds a new element to the vector pointed to by @p vec and
         * assigns the value passed in to that field. The type of the value is given
         * in @p type and must be one of
         * the %BRO_TYPE_xxx constants defined in broccoli.h. The type you give
         * implies what data type @p val must be pointing to; see the manual for
         * details. If you want to indicate a type specialized from @p type,
         * use @p type_name to give its name, otherwise pass %NULL for @p type_name.
         * It is possible to leave fields unassigned, in that case, pass in
         * %NULL for @p val.
         *
         * @p val remains the caller's responsibility and is copied internally.
         *
         * @returns %TRUE on success, %FALSE on error.
         */
        [DllImport(BroccoliLibrary, BestFitMapping = false)]
        public static extern int bro_vector_add_val(IntPtr vec, BroType type, [MarshalAs(UnmanagedType.LPStr)] string type_name, IntPtr val);

        /**
         * bro_vector_get_nth_val - Retrieves a value from a vector by index.
         * @param vec vector handle.
         * @param num index, starting from 0.
         * @param type value-result argument for the expected/actual type of the value.
         *
         * The function returns the @p num'th value of the vector pointed to
         * by @p vec, expected to be of @p type. The returned value is internal
         * and needs to be duplicated if you want to keep it around. Upon
         * return, the int pointed to by @p type tells you the type of the returned
         * value, as a BRO_TYPE_xxx type tag. If the int pointed to upon calling
         * the function has the value BRO_TYPE_UNKNOWN, no type checking is
         * performed and the value is returned. If it is any other type tag,
         * its value is compared to that of the value, and if they match, the
         * value is returned. Otherwise, the return value is %NULL. If you don't
         * care about type enforcement and don't want to know the value's type,
         * you may pass %NULL for @p type.
         *
         * @returns pointer to queried value on success, %NULL on error.
         */
        [DllImport(BroccoliLibrary)]
        public static extern IntPtr bro_vector_get_nth_val(IntPtr vec, int num, ref BroType type);

        /**
         * bro_vector_set_nth_val - Replaces a value in a vector, identified by index.
         * @param vec vector handle.
         * @param num index, starting from 0.
         * @param type expected type of the value.
         * @param type_name optional name of specialized type.
         * @param val pointer to new val.
         *
         * The function replaces the @p num'th value of the vector pointed to
         * by @p vec, expected to be of @p type. All values are copied internally
         * so what @p val points to stays unmodified. The value of @p type implies
         * what @p result must be pointing to. See the manual for details.
         * If you want to indicate a type specialized from @p type, use
         * @p type_name to give its name, otherwise pass %NULL for @p type_name.
         *
         * @returns %TRUE on success, %FALSE on error.
         */
        [DllImport(BroccoliLibrary, BestFitMapping = false)]
        public static extern int bro_vector_set_nth_val(IntPtr vec, int num, BroType type, [MarshalAs(UnmanagedType.LPStr)] string type_name, IntPtr val);

        #endregion

#if BRO_PCAP_SUPPORT
        #region [ Pcap Packet Handling ]

        /**
         * bro_conn_set_packet_ctxt - Sets current packet context for connection.
         * @param bc connection handle.
         * @param link_type libpcap DLT linklayer type.
         * 
         * The function sets the packet context for @p bc for future BroPackets
         * handled by this connection.
         */
        [DllImport(BroccoliLibrary)]
        public static extern void bro_conn_set_packet_ctxt(IntPtr bc, int link_type);

        /**
         * bro_conn_get_packet_ctxt - Gets current packet context for connection.
         * @param bc connection handle.
         * @param link_type result pointer for libpcap DLT linklayer type.
         * 
         * The function returns @p bc's current packet context through @p link_type.
         */
        [DllImport(BroccoliLibrary)]
        public static extern void bro_conn_get_packet_ctxt(IntPtr bc, ref int link_type);

        /** 
         * bro_packet_new - Creates a new packet.
         * @param hdr pointer to libpcap packet header.
         * @param data pointer to libpcap packet data.
         * @param tag pointer to ASCII tag (0 for no tag).
         * 
         * @returns a new BroPacket by copying @p hdr and @p data
         * internally.
         * Release the resulting packet using bro_packet_free().
         */
        [DllImport(BroccoliLibrary, BestFitMapping = false)]
        public static extern IntPtr bro_packet_new(ref pcap_pkthdr hdr, byte[] data, [MarshalAs(UnmanagedType.LPStr)] string tag);

        /**
         * bro_packet_clone - Clones a packet.
         * @param packet packet to clone.
         *
         * @returns a copy of @p packet, or %NULL on error.
         */
        [DllImport(BroccoliLibrary)]
        public static extern IntPtr bro_packet_clone(IntPtr packet);

        /**
         * bro_packet_free - Releases a packet.
         * @param packet packet to release.
         * 
         * The function releases all memory occupied by a packet previously allocated
         * using bro_packet_new().
         */
        [DllImport(BroccoliLibrary)]
        public static extern void bro_packet_free(IntPtr packet);

        /**
         * bro_packet_send - Sends a packet over a given connection.
         * @param bc connection on which to send packet.
         * @param packet packet to send.
         *
         * The function sends @p packet to the Bro peer connected via @p bc.
         *
         * @returns %TRUE if successful, %FALSE otherwise.
         */
        [DllImport(BroccoliLibrary)]
        public static extern int bro_packet_send(IntPtr bc, IntPtr packet);

        #endregion
#endif

        #region [ Unused API Functions ]

        #region [ Connection Data Storage ]

        // Equivalent connection data storage functionality associated with the managed BroConnection implemented
        // in managed memory space using a Dictionary<string, object>:

        /* Connection handles come with a facility to store and retrieve
         * arbitrary data items. Use the following functions to store,
         * query, and remove items from a connection handle.
         */

        // /**
        // * bro_conn_data_set - Puts a data item into the registry.
        // * @param bc Bro connection handle.
        // * @param key name of the data item.
        // * @param val data item.
        // *
        // * The function stores @p val under name @p key in the connection handle @p bc.
        // * @p key is copied internally so you do not need to duplicate it before
        // * passing.
        // */
        //[DllImport(BroccoliLibrary, BestFitMapping = false)]
        //public static extern void bro_conn_data_set(IntPtr bc, [MarshalAs(UnmanagedType.LPStr)] string key, IntPtr val);

        // /**
        // * bro_conn_data_get - Looks up a data item.
        // * @param bc Bro connection handle.
        // * @param key name of the data item.
        // *
        // * The function tries to look up the data item with name @p key and
        // * if found, returns it.
        // * 
        // * @returns data item if lookup was successful, %NULL otherwise.
        // */
        //[DllImport(BroccoliLibrary, BestFitMapping = false)]
        //public static extern IntPtr bro_conn_data_get(IntPtr bc, [MarshalAs(UnmanagedType.LPStr)] string key);

        // /**
        // * bro_conn_data_del - Removes a data item.
        // * @param bc Bro connection handle.
        // * @param key name of the data item.
        // *
        // * The function tries to remove the data item with name @p key.
        // * 
        // * @returns the removed data item if it exists, %NULL otherwise.
        // */
        //[DllImport(BroccoliLibrary, BestFitMapping = false)]
        //public static extern IntPtr bro_conn_data_del(IntPtr bc, [MarshalAs(UnmanagedType.LPStr)] string key);

        #endregion

        #region [ Dynamic-size Buffers ]

        // Broccoli provides the BroBuf API for dynamically allocatable, growable, shrinkable and consumable buffers.
        // However, this feature is not required to use Broccoli - it is provided simply because the buffers are
        // used internally anyway and might otherwise be useful. Since these functions are optional and .NET already
        // provides equivalent managed functionality through various common data structures, these are not implemented
        // in the BroccoliSharp library:

        // /**
        // * bro_buf_new - Creates a new buffer object.
        // *
        // * @returns a new buffer object, or %NULL on error. Use paired with
        // * bro_buf_free().
        // */
        //[DllImport(BroccoliLibrary)]
        //public static extern IntPtr bro_buf_new();

        // /**
        // * bro_buf_free - Releases a dynamically allocated buffer object.
        // * @param buf buffer pointer.
        // *
        // * The function releases all memory held by the buffer pointed
        // * to by @p buf. Use paired with bro_buf_new().
        // */
        //[DllImport(BroccoliLibrary)]
        //public static extern void bro_buf_free(IntPtr buf);

        // /**
        // * bro_buf_append - appends data to the end of the buffer.
        // * @param buf buffer pointer.
        // * @param data new data to append to buffer.
        // * @param data_len size of @p data.
        // *
        // * The function appends data to the end of the buffer,
        // * enlarging it if necessary to hold the @p len new bytes.
        // * NOTE: it does not modify the buffer pointer. It only
        // * appends new data where buf_off is currently pointing
        // * and updates it accordingly. If you DO want the buffer
        // * pointer to be updated, have a look at bro_buf_ptr_write()
        // * instead.
        // *
        // * @returns %TRUE if successful, %FALSE otherwise.
        // */
        //[DllImport(BroccoliLibrary)]
        //public static extern int bro_buf_append(IntPtr buf, byte[] data, int data_len);

        // /**
        // * bro_buf_consume - shrinks the buffer.
        // * @param buf buffer pointer.
        // *
        // * The function removes the buffer contents between the start
        // * of the buffer and the point where the buffer pointer
        // * currently points to. The idea is that you call bro_buf_ptr_read()
        // * a few times to extract data from the buffer, and then
        // * call bro_buf_consume() to signal to the buffer that the
        // * extracted data are no longer needed inside the buffer.
        // */
        //[DllImport(BroccoliLibrary)]
        //public static extern void bro_buf_consume(IntPtr buf);

        // /**
        // * bro_buf_reset - resets the buffer.
        // * @param buf buffer pointer.
        // *
        // * The function resets the buffer pointers to the beginning of the
        // * currently allocated buffer, i.e., it marks the buffer as empty.
        // */
        //[DllImport(BroccoliLibrary)]
        //public static extern void bro_buf_reset(IntPtr buf);

        // /**
        // * bro_buf_get - Returns pointer to actual start of buffer.
        // * @param buf buffer pointer.
        // *
        // * @returns the entire buffer's contents.
        // */
        //[DllImport(BroccoliLibrary)]
        //public static unsafe extern byte* bro_buf_get(IntPtr buf);

        // /**
        // * bro_buf_get_end - Returns pointer to the end of the buffer.
        // * @param buf buffer pointer.
        // *
        // * @returns a pointer to the first byte in the
        // * buffer that is not currently used.
        // */
        //[DllImport(BroccoliLibrary)]
        //public static unsafe extern byte* bro_buf_get_end(IntPtr buf);

        // /**
        // * bro_buf_get_size - Returns number of bytes allocated for buffer.
        // * @param buf buffer pointer.
        // *
        // * @returns the number of actual bytes allocated for the
        // * buffer.
        // */
        //[DllImport(BroccoliLibrary)]
        //public static extern uint bro_buf_get_size(IntPtr buf);

        // /**
        // * bro_buf_get_used_size - Returns number of bytes currently used.
        // * @param buf buffer pointer.
        // *
        // * @returns number of bytes currently used.
        // */
        //[DllImport(BroccoliLibrary)]
        //public static extern uint bro_buf_get_used_size(IntPtr buf);

        // /**
        // * bro_buf_ptr_get - Returns current buffer content pointer.
        // * @param buf buffer pointer.
        // *
        // * @returns current buffer content pointer.
        // */
        //[DllImport(BroccoliLibrary)]
        //public static unsafe extern byte* bro_buf_ptr_get(IntPtr buf);

        // /**
        // * bro_buf_ptr_tell - Returns current offset of buffer content pointer.
        // * @param buf buffer pointer.
        // *
        // * @returns current offset of buffer content pointer.
        // */
        //[DllImport(BroccoliLibrary)]
        //public static extern uint bro_buf_ptr_tell(IntPtr buf);

        // /**
        // * bro_buf_ptr_seek - Adjusts buffer content pointer.
        // * @param buf buffer pointer.
        // * @param offset number of bytes by which to adjust pointer, positive or negative.
        // * @param whence location relative to which to adjust.
        // *
        // * The function adjusts the position of @p buf's content
        // * pointer. Call semantics are identical to fseek(), thus
        // * use @p offset to indicate the offset by which to jump and
        // * use %SEEK_SET, %SEEK_CUR, or %SEEK_END to specify the
        // * position relative to which to adjust.
        // *
        // * @returns %TRUE if adjustment could be made, %FALSE
        // * if not (e.g. because the offset requested is not within
        // * legal bounds).
        // */
        //[DllImport(BroccoliLibrary)]
        //public static extern int bro_buf_ptr_seek(IntPtr buf, int offset, int whence);

        // /** 
        // * bro_buf_ptr_check - Checks whether a number of bytes can be read.
        // * @param buf buffer pointer.
        // * @param size number of bytes to check for availability.
        // *
        // * The function checks whether @p size bytes could be read from the
        // * buffer using bro_buf_ptr_read().
        // *
        // * @returns %TRUE if @p size bytes can be read, %FALSE if not.
        // */
        //[DllImport(BroccoliLibrary)]
        //public static extern int bro_buf_ptr_check(IntPtr buf, int size);

        // /**
        // * bro_buf_ptr_read - Extracts a number of bytes from buffer.
        // * @param buf buffer pointer.
        // * @param data destination area.
        // * @param size number of bytes to copy into @p data.
        // *
        // * The function copies @p size bytes into @p data if the buffer
        // * has @p size bytes available from the current location of
        // * the buffer content pointer onward, incrementing the content
        // * pointer accordingly. If not, the function doesn't do anything.
        // * It behaves thus different from the normal read() in that
        // * it either copies the amount requested or nothing.
        // * 
        // * @returns %TRUE if @p size bytes were copied, %FALSE if not.
        // */
        //[DllImport(BroccoliLibrary)]
        //public static extern int bro_buf_ptr_read(IntPtr buf, byte[] data, int size);

        // /**
        // * bro_buf_ptr_write - Writes a number of bytes into buffer.
        // * @param buf buffer pointer.
        // * @param data data to write.
        // * @param size number of bytes to copy into @p data.
        // *
        // * The function writes @p size bytes of the area pointed to by @p data
        // * into the buffer @p buf at the current location of its content pointer,
        // * adjusting the content pointer accordingly. If the buffer doesn't have
        // * enough space to receive @p size bytes, more space is allocated.
        // *
        // * @returns %TRUE if @p size bytes were copied, %FALSE if an error
        // * occurred and the bytes could not be copied.
        // */
        //[DllImport(BroccoliLibrary)]
        //public static extern int bro_buf_ptr_write(IntPtr buf, byte[] data, int size);

        #endregion

        #endregion
    }
}
