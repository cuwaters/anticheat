/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_Protector,
    0x8b9b0358,0x62f1,0x4245,0x99,0xa5,0xf0,0x67,0x11,0xa3,0x9d,0x1b);
// {8b9b0358-62f1-4245-99a5-f06711a39d1b}
