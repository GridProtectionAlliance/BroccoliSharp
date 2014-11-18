<table>
    <tr>
        <td>
            <img src="http://gridprotectionalliance.github.io/BroccoliSharp/icons/BroccoliSharp.png"/>
        </td>
        <td>
            <h2>BroccoliSharp: A .NET implementation of the Bro Client Communications Library.</h2>
        </td>
    </tr>
</table>

<p>
    BroccoliSharp is a set of managed C# based .NET classes and structures that wrap
    Broccoli, the "Bro client communications library". This library fully implements
    the Broccoli API and will allow you to create client sensors for the Bro intrusion
    detection system, receive Bro IDs, send and receive Bro events, as well as send
    and receive event requests to and from peering Bros. As in the native C Broccoli
    API, this .NET library can be used to create and receive values of pure types like
    integers, counters, timestamps, IP addresses, port numbers, booleans, and strings.
</p>

<p>
    BroccoliSharp is free software under terms of the BSD license as provided in the LICENSE file
    distributed with the source code. This source code library was developed and is maintained by
    the <a href="https://www.gridprotectionalliance.org">Grid Protection Alliance</a> who provides
    production grade open source software to electric utilities.  This library was developed as
    part of a <a href="http://energy.gov/oe/services/technology-development/energy-delivery-systems-cybersecurity">DOE CEDS</a>
    project called <a href="https://www.controlsystemsroadmap.net/ieRoadmap%20Documents/GPA-ARMORE-CEDS_Peer_Review_2014.pdf">"ARMORE"</a>
    which is incorporating Bro within a security appliance for use in substations.
</p>

<p>
    More details on BroccoliSharp usage can be found in the documentation related to
    the primary data structures. It is expected that the developer is already familiar
    with basic Bro concepts before using the BroccoliSharp library.
</p>

[![Build status](https://ci.appveyor.com/api/projects/status/8jhnn7jjh3qv7qs4?svg=true)](https://ci.appveyor.com/project/ritchiecarroll/broccolisharp)

<h2>Installation</h2>

<p>
    The BroccoliSharp library has only been tested on Linux so far.
</p>

<h3>Prerequisites</h3>

<p>
    BroccoliSharp requires the following libraries which need to be installed before you begin:
</p>

<p style='text-indent: .5in'>
    <span style='font-family: Symbol'>·&#160;</span>&#160;
    <a href="https://www.bro.org/download/">The Broccoli library</a>
    (of course!), Broccoli has its own requirements, see
    <a href="https://www.bro.org/sphinx/components/broccoli/README.html">docs</a>.
</p>

<p style='text-indent: .5in'>
    <span style='font-family: Symbol'>·&#160;</span>&#160;
    <a href="http://www.mono-project.com/download/#download-lin">Mono</a> –
    version supporting .NET 4.5 is preferred, but not required.
</p>

<h3>Building BroccoliSharp</h3>

<p>
    To build the BroccoliSharp library using Mono you can use <code>xbuild</code>:
</p>

<p style='text-indent: .5in'>
    <ul>
    <li>
        <code>xbuild /p:Configuration=Release BroccoliSharp.sln</code>
    </li>
    </ul>          
</p>

<p>
    To build a debug library, use:
</p>

<p style='text-indent: .5in'>
    <ul>
    <li>
        <code>xbuild /p:Configuration=Debug BroccoliSharp.sln</code>
    </li>
    </ul>          
</p>
        
<p>
    To build BroccoliSharp to work with a Broccoli release that has disabled PCAP support, use:
</p>

<p style='text-indent: .5in'>
    <ul>
    <li>
        <code>xbuild /p:Configuration=ReleaseNoPCAP BroccoliSharp.sln</code>
    </li>
    </ul>          
</p>

<p>
    To create builds that use SafeHandle implementations for opaque pointers use:
</p>

<p style='text-indent: .5in'>
    <ul>
    <li>
        <code>xbuild /p:Configuration=DebugWithSafeHandles BroccoliSharp.sln</code>
    </li>
    <li>
        <code>xbuild /p:Configuration=ReleaseWithSafeHandles BroccoliSharp.sln</code>
    </li>
    <li>
        <code>xbuild /p:Configuration=ReleaseNoPCAPWithSafeHandles BroccoliSharp.sln</code>
    </li>
    </ul>
</p>

<p>
    To build BroccoliSharp to target older versions of Mono use one of the following:
</p>

<p style='text-indent: .5in'>
    <ul>
    <li>
        <code>xbuild /p:Configuration=Debug BroccoliSharp-NET4.0.sln</code>
    </li>
    <li>
        <code>xbuild /p:Configuration=Release BroccoliSharp-NET4.0.sln</code>
    </li>
    <li>
        <code>xbuild /p:Configuration=ReleaseNoPCAP BroccoliSharp-NET4.0.sln</code>
    </li>
    <li>
        <code>xbuild /p:Configuration=DebugWithSafeHandles BroccoliSharp-NET4.0.sln</code>
    </li>
    <li>
        <code>xbuild /p:Configuration=ReleaseWithSafeHandles BroccoliSharp-NET4.0.sln</code>
    </li>
    <li>
        <code>xbuild /p:Configuration=ReleaseNoPCAPWithSafeHandles BroccoliSharp-NET4.0.sln</code>
    </li>
    </ul>
</p>

<p>
    You can also build the library on Windows using Visual Studio and the binaries
    should still work on Linux depending on the corresponding installed version of
    Mono.
</p>

<p>
    Once the BroccoliSharp.dll exists (found in the output folder associated with
    the build configuration, e.g., "/Main/Build/Output/Release" relative to source),
    you can add a reference to the library in your .NET projects and begin using
    BroccoliSharp.
</p>

<p>
    In order for your .NET application to be able to find the Broccoli API shared library (i.e.,
    <code>libbroccoli.so</code>), you will need to add the location of this library to your
    Linux library path (e.g., add path to <code>LD_LIBRARY_PATH</code> environmental variable).
    See <a href="http://www.mono-project.com/docs/advanced/pinvoke/">Mono Interop documentation</a> on
    "Library Handling" for more detail.
</p>

<h2>About the Code</h2>

<p>
    The source code has been defined with precompiler directives to allow for compiling the code to
    either use direct pointers or use safe handles for opaque Bro types. Generally, as their name
    implies, safe handles are the ideal choice when using managed code with unmanaged code. See the
    <a href="http://msdn.microsoft.com/en-us/library/fh21e17c(v=vs.110).aspx">Safe Handles</a>
    documentation for more detail. In general, multi-threaded race conditions between garbage collection
    and pointer usage can be avoided and the unmanaged memory allocations the pointer references will
    be disposed of properly even if the program abnormally terminates. That being said, depending on the
    version of Mono you are targeting, the safe handle implementation may not be fully cooked. Also, if
    you are trying to debug your .NET application and get Mono to report verbose information, there is a
    lot less noise to filter through when you are just using pointers. As a result, you can choose which
    mode of operation you want to use depending on your task. For any production level deployments, it is
    recommended to use the <code>ReleaseWithSafeHandles</code> build configuration with a
    later build of Mono.
</p>
        
<p>
    When building inside Visual Studio code analysis is enabled for this project. A rule set is included
    with the source code (i.e., BroccoliSharp.ruleset) that defines the analysis rules that are enabled for
    the project. Note that this rule set is basically just the "Microsoft Managed Recommended Rules" with
    one rule turned off: CA1060: Move P/Invokes to NativeMethods class. This rule wants to force the name
    of the imported Bro API functions class to be "NativeMethods", but "BroAPI" was preferred for this project.
</p>
<p>
    The code has also been through extensive analysis using the
    <a href="http://www.mono-project.com/docs/tools+libraries/tools/gendarme/">Gendarme</a> tool. All reported
    items of concern have been corrected and the remaining items have been reviewed thoroughly. A future to-do
    could be to create an exclusion list with justifications.
</p>
