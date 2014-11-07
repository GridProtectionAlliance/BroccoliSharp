using System;
using System.Reflection;
using System.Runtime.InteropServices;

// General Information about an assembly is controlled through the following 
// set of attributes. Change these attribute values to modify the information
// associated with an assembly.
[assembly: AssemblyTitle("BroccoliSharp")]
[assembly: AssemblyDescription("C# Wrapper Implementation of Broccoli API")]
#if DEBUG
[assembly: AssemblyConfiguration("Debug Build")]
#else
#if BRO_PCAP_SUPPORT
[assembly: AssemblyConfiguration("Release Build (PCAP Support Enabled)")]
#else
[assembly: AssemblyConfiguration("Release Build (No PCAP Support)")]
#endif
#endif
[assembly: AssemblyCompany("Grid Protection Alliance")]
[assembly: AssemblyProduct("BroccoliSharp")]
[assembly: AssemblyCopyright("Copyright © GPA, 2014.  All Rights Reserved.")]

// Setting ComVisible to false makes the types in this assembly not visible 
// to COM components.  If you need to access a type in this assembly from 
// COM, set the ComVisible attribute to true on that type.
[assembly: ComVisible(false)]
[assembly: CLSCompliant(false)]

// The following GUID is for the ID of the typelib if this project is exposed to COM
[assembly: Guid("0f5cdac3-a699-4b56-808b-4cb3764ab7fe")]

// Version information for an assembly consists of the following four values:
//
//      Major Version
//      Minor Version 
//      Build Number
//      Revision
//
// You can specify all the values or you can default the Build and Revision Numbers 
// by using the '*' as shown below:
// [assembly: AssemblyVersion("1.0.*")]
[assembly: AssemblyVersion("1.0.*")]