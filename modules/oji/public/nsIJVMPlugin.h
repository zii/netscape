/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 *
 * The contents of this file are subject to the Netscape Public License
 * Version 1.0 (the "NPL"); you may not use this file except in
 * compliance with the NPL.  You may obtain a copy of the NPL at
 * http://www.mozilla.org/NPL/
 *
 * Software distributed under the NPL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the NPL
 * for the specific language governing rights and limitations under the
 * NPL.
 *
 * The Initial Developer of this code under the NPL is Netscape
 * Communications Corporation.  Portions created by Netscape are
 * Copyright (C) 1998 Netscape Communications Corporation.  All Rights
 * Reserved.
 */

////////////////////////////////////////////////////////////////////////////////
// NETSCAPE JAVA VM PLUGIN EXTENSIONS
// 
// This interface allows a Java virtual machine to be plugged into
// Communicator to implement the APPLET tag and host applets.
// 
// Note that this is the C++ interface that the plugin sees. The browser
// uses a specific implementation of this, nsJVMPlugin, found in jvmmgr.h.
////////////////////////////////////////////////////////////////////////////////

#ifndef nsIJVMPlugin_h___
#define nsIJVMPlugin_h___

#include "nsIPlugin.h"
#include "jni.h"

////////////////////////////////////////////////////////////////////////////////
// Java VM Plugin Interface
// This interface defines additional entry points that a plugin developer needs
// to implement in order to implement a Java virtual machine plugin. 

struct nsJVMInitArgs {
    jint version;
    const char* classpathAdditions;     // appended to the JVM's classpath
};

#define nsJVMInitArgs_Version   0x00010000 

class nsIJVMPlugin : public nsIPlugin {
public:

    // This method us used to start the Java virtual machine.
    // It sets up any global state necessary to host Java programs.
    // Note that calling this method is distinctly separate from 
    // initializing the nsIJVMPlugin object (done by the Initialize
    // method).
    NS_IMETHOD_(nsJVMError)
    StartupJVM(nsJVMInitArgs* initargs) = 0;

    // This method us used to stop the Java virtual machine.
    // It tears down any global state necessary to host Java programs.
    // The fullShutdown flag specifies whether the browser is quitting
    // (PR_TRUE) or simply whether the JVM is being shut down (PR_FALSE).
    NS_IMETHOD_(nsJVMError)
    ShutdownJVM(PRBool fullShutdown) = 0;

    // Causes the JVM to append a new directory to its classpath.
    // If the JVM doesn't support this operation, an error is returned.
    NS_IMETHOD_(nsJVMError)
    AddToClassPath(const char* dirPath) = 0;

    // Causes the JVM to remove a directory from its classpath.
    // If the JVM doesn't support this operation, an error is returned.
    NS_IMETHOD_(nsJVMError)
    RemoveFromClassPath(const char* dirPath) = 0;

    // Returns the current classpath in use by the JVM.
    NS_IMETHOD_(const char*)
    GetClassPath(void) = 0;
    
    NS_IMETHOD_(nsIPluginInstance*)
    GetPluginInstance(jobject javaObject) = 0;

    NS_IMETHOD_(nsIPluginInstance*)
    GetPluginInstance(JNIEnv* jenv) = 0;

    NS_IMETHOD_(JavaVM *)
    GetJavaVM(void) = 0;

    // Find or create a JNIEnv for the current thread.
    // Returns NULL if an error occurs.
    NS_IMETHOD_(JNIEnv*)
    GetJNIEnv(void) = 0;

    // This method must be called when the caller is done using the JNIEnv.
    // This decrements a refcount associated with it may free it.
    NS_IMETHOD_(nsrefcnt)
    ReleaseJNIEnv(JNIEnv* env) = 0;

};

#define NS_IJVMPLUGIN_IID                            \
{ /* da6f3bc0-a1bc-11d1-85b1-00805f0e4dfe */         \
    0xda6f3bc0,                                      \
    0xa1bc,                                          \
    0x11d1,                                          \
    {0x85, 0xb1, 0x00, 0x80, 0x5f, 0x0e, 0x4d, 0xfe} \
}

////////////////////////////////////////////////////////////////////////////////

#endif /* nsIJVMPlugin_h___ */
