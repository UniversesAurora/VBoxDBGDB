/* $Id: MachineDebuggerImpl.cpp $ */
/** @file
 * VBox IMachineDebugger COM class implementation (VBoxC).
 */

/*
 * Copyright (C) 2006-2020 Oracle Corporation
 *
 * This file is part of VirtualBox Open Source Edition (OSE), as
 * available from http://www.virtualbox.org. This file is free software;
 * you can redistribute it and/or modify it under the terms of the GNU
 * General Public License (GPL) as published by the Free Software
 * Foundation, in version 2 as it comes in the "COPYING" file of the
 * VirtualBox OSE distribution. VirtualBox OSE is distributed in the
 * hope that it will be useful, but WITHOUT ANY WARRANTY of any kind.
 */


/*********************************************************************************************************************************
*   Header Files                                                                                                                 *
*********************************************************************************************************************************/
#define LOG_GROUP LOG_GROUP_MAIN_MACHINEDEBUGGER

#include "LoggingNew.h"

#include "MachineDebuggerImpl.h"

#include "Global.h"
#include "ConsoleImpl.h"

#include "AutoCaller.h"

#include <VBox/vmm/em.h>
#include <VBox/vmm/uvm.h>
#include <VBox/vmm/tm.h>
#include <VBox/vmm/hm.h>
#include <VBox/err.h>
#include <iprt/cpp/utils.h>
#include <iprt/ctype.h>
#include <iprt/errcore.h>

#include <VBox/vmm/vmapi.h>

#define DEBUG_LEVEL 1

#if DEBUG_LEVEL > 0
// #define Log1(fmt,...) printf(fmt, ##__VA_ARGS__)
#define Log1(...) _LogRelItLikely(RTLOGGRPFLAGS_LEVEL_1, LOG_GROUP, __VA_ARGS__)
#else
#define Log1(x)
#endif



// constructor / destructor
/////////////////////////////////////////////////////////////////////////////

MachineDebugger::MachineDebugger()
    : mParent(NULL)
{
}

MachineDebugger::~MachineDebugger()
{
}

HRESULT MachineDebugger::FinalConstruct()
{
    unconst(mParent) = NULL;
    return BaseFinalConstruct();
}

void MachineDebugger::FinalRelease()
{
    uninit();
    BaseFinalRelease();
}

// public initializer/uninitializer for internal purposes only
/////////////////////////////////////////////////////////////////////////////

/**
 * Initializes the machine debugger object.
 *
 * @returns COM result indicator
 * @param aParent handle of our parent object
 */
HRESULT MachineDebugger::init(Console *aParent)
{
    LogFlowThisFunc(("aParent=%p\n", aParent));

    ComAssertRet(aParent, E_INVALIDARG);

    /* Enclose the state transition NotReady->InInit->Ready */
    AutoInitSpan autoInitSpan(this);
    AssertReturn(autoInitSpan.isOk(), E_FAIL);

    unconst(mParent) = aParent;

    for (unsigned i = 0; i < RT_ELEMENTS(maiQueuedEmExecPolicyParams); i++)
        maiQueuedEmExecPolicyParams[i] = UINT8_MAX;
    mSingleStepQueued = -1;
    mRecompileUserQueued = -1;
    mRecompileSupervisorQueued = -1;
    mPatmEnabledQueued = -1;
    mCsamEnabledQueued = -1;
    mLogEnabledQueued = -1;
    mVirtualTimeRateQueued = UINT32_MAX;
    mFlushMode = false;

    /* Confirm a successful initialization */
    autoInitSpan.setSucceeded();

    return S_OK;
}

/**
 *  Uninitializes the instance and sets the ready flag to FALSE.
 *  Called either from FinalRelease() or by the parent when it gets destroyed.
 */
void MachineDebugger::uninit()
{
    LogFlowThisFunc(("\n"));

    /* Enclose the state transition Ready->InUninit->NotReady */
    AutoUninitSpan autoUninitSpan(this);
    if (autoUninitSpan.uninitDone())
        return;

    unconst(mParent) = NULL;
    mFlushMode = false;
}

// IMachineDebugger properties
/////////////////////////////////////////////////////////////////////////////

VMMR3DECL(int) test_attach(PUVM pUVM)
{
    if (VMR3GetAttached(pUVM))
        return VINF_SUCCESS;

    return DBGFR3Attach(pUVM);
}

VMMR3DECL(int) test_detach(PUVM pUVM)
{
    if (!VMR3GetAttached(pUVM))
        return VINF_SUCCESS;

    return DBGFR3Detach(pUVM);
}


/**
 * Returns the current singlestepping flag.
 *
 * @returns COM status code
 * @param   aSingleStep     Where to store the result.
 */
HRESULT MachineDebugger::getSingleStep(BOOL *aSingleStep)
{
    AutoReadLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    if (SUCCEEDED(hrc))
    {
        *aSingleStep = DBGFR3IsHalted(ptrVM.rawUVM());
    }
    return hrc;
}

/**
 * Sets the singlestepping flag.
 *
 * @returns COM status code
 * @param   aSingleStep     The new state.
 */
HRESULT MachineDebugger::setSingleStep(BOOL aSingleStep)
{
    AutoWriteLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    if (SUCCEEDED(hrc))
    {
        bool is_halted = DBGFR3IsHalted(ptrVM.rawUVM());
        if (is_halted && !aSingleStep)
        {
            DBGFR3Resume(ptrVM.rawUVM());
        }
        else if (!is_halted && aSingleStep)
        {
            DBGFR3Halt(ptrVM.rawUVM());
        }
    }
    return hrc;
}

/**
 * Internal worker for getting an EM executable policy setting.
 *
 * @returns COM status code.
 * @param   enmPolicy           Which EM policy.
 * @param   pfEnforced          Where to return the policy setting.
 */
HRESULT MachineDebugger::i_getEmExecPolicyProperty(EMEXECPOLICY enmPolicy, BOOL *pfEnforced)
{
    CheckComArgOutPointerValid(pfEnforced);

    AutoCaller autoCaller(this);
    HRESULT hrc = autoCaller.rc();
    if (SUCCEEDED(hrc))
    {
        AutoReadLock alock(this COMMA_LOCKVAL_SRC_POS);
        if (i_queueSettings())
            *pfEnforced = maiQueuedEmExecPolicyParams[enmPolicy] == 1;
        else
        {
            bool fEnforced = false;
            Console::SafeVMPtrQuiet ptrVM(mParent);
            hrc = ptrVM.rc();
            if (SUCCEEDED(hrc))
                EMR3QueryExecutionPolicy(ptrVM.rawUVM(), enmPolicy, &fEnforced);
            *pfEnforced = fEnforced;
        }
    }
    return hrc;
}

/**
 * Internal worker for setting an EM executable policy.
 *
 * @returns COM status code.
 * @param   enmPolicy           Which policy to change.
 * @param   fEnforce            Whether to enforce the policy or not.
 */
HRESULT MachineDebugger::i_setEmExecPolicyProperty(EMEXECPOLICY enmPolicy, BOOL fEnforce)
{
    AutoCaller autoCaller(this);
    HRESULT hrc = autoCaller.rc();
    if (SUCCEEDED(hrc))
    {
        AutoReadLock alock(this COMMA_LOCKVAL_SRC_POS);
        if (i_queueSettings())
            maiQueuedEmExecPolicyParams[enmPolicy] = fEnforce ? 1 : 0;
        else
        {
            Console::SafeVMPtrQuiet ptrVM(mParent);
            hrc = ptrVM.rc();
            if (SUCCEEDED(hrc))
            {
                int vrc = EMR3SetExecutionPolicy(ptrVM.rawUVM(), enmPolicy, fEnforce != FALSE);
                if (RT_FAILURE(vrc))
                    hrc = setErrorBoth(VBOX_E_VM_ERROR, vrc, tr("EMR3SetExecutionPolicy failed with %Rrc"), vrc);
            }
        }
    }
    return hrc;
}

/**
 * Returns the current recompile user mode code flag.
 *
 * @returns COM status code
 * @param   aRecompileUser  address of result variable
 */
HRESULT MachineDebugger::getRecompileUser(BOOL *aRecompileUser)
{
    return i_getEmExecPolicyProperty(EMEXECPOLICY_RECOMPILE_RING3, aRecompileUser);
}

/**
 * Sets the recompile user mode code flag.
 *
 * @returns COM status
 * @param   aRecompileUser  new user mode code recompile flag.
 */
HRESULT MachineDebugger::setRecompileUser(BOOL aRecompileUser)
{
    LogFlowThisFunc(("enable=%d\n", aRecompileUser));
    return i_setEmExecPolicyProperty(EMEXECPOLICY_RECOMPILE_RING3, aRecompileUser);
}

/**
 * Returns the current recompile supervisor code flag.
 *
 * @returns COM status code
 * @param   aRecompileSupervisor    address of result variable
 */
HRESULT MachineDebugger::getRecompileSupervisor(BOOL *aRecompileSupervisor)
{
    return i_getEmExecPolicyProperty(EMEXECPOLICY_RECOMPILE_RING0, aRecompileSupervisor);
}

/**
 * Sets the new recompile supervisor code flag.
 *
 * @returns COM status code
 * @param   aRecompileSupervisor    new recompile supervisor code flag
 */
HRESULT MachineDebugger::setRecompileSupervisor(BOOL aRecompileSupervisor)
{
    LogFlowThisFunc(("enable=%d\n", aRecompileSupervisor));
    return i_setEmExecPolicyProperty(EMEXECPOLICY_RECOMPILE_RING0, aRecompileSupervisor);
}

/**
 * Returns the current execute-all-in-IEM setting.
 *
 * @returns COM status code
 * @param   aExecuteAllInIEM    Address of result variable.
 */
HRESULT MachineDebugger::getExecuteAllInIEM(BOOL *aExecuteAllInIEM)
{
    return i_getEmExecPolicyProperty(EMEXECPOLICY_IEM_ALL, aExecuteAllInIEM);
}

/**
 * Changes the execute-all-in-IEM setting.
 *
 * @returns COM status code
 * @param   aExecuteAllInIEM    New setting.
 */
HRESULT MachineDebugger::setExecuteAllInIEM(BOOL aExecuteAllInIEM)
{
    LogFlowThisFunc(("enable=%d\n", aExecuteAllInIEM));
    return i_setEmExecPolicyProperty(EMEXECPOLICY_IEM_ALL, aExecuteAllInIEM);
}

/**
 * Returns the current patch manager enabled flag.
 *
 * @returns COM status code
 * @param   aPATMEnabled    address of result variable
 */
HRESULT MachineDebugger::getPATMEnabled(BOOL *aPATMEnabled)
{
    *aPATMEnabled = false;
    return S_OK;
}

/**
 * Set the new patch manager enabled flag.
 *
 * @returns COM status code
 * @param   aPATMEnabled    new patch manager enabled flag
 */
HRESULT MachineDebugger::setPATMEnabled(BOOL aPATMEnabled)
{
    LogFlowThisFunc(("enable=%d\n", aPATMEnabled));

    if (aPATMEnabled)
        return setErrorBoth(VBOX_E_VM_ERROR, VERR_RAW_MODE_NOT_SUPPORTED, tr("PATM not present"), VERR_NOT_SUPPORTED);
    return S_OK;
}

/**
 * Returns the current code scanner enabled flag.
 *
 * @returns COM status code
 * @param   aCSAMEnabled    address of result variable
 */
HRESULT MachineDebugger::getCSAMEnabled(BOOL *aCSAMEnabled)
{
    *aCSAMEnabled = false;
    return S_OK;
}

/**
 * Sets the new code scanner enabled flag.
 *
 * @returns COM status code
 * @param   aCSAMEnabled    new code scanner enabled flag
 */
HRESULT MachineDebugger::setCSAMEnabled(BOOL aCSAMEnabled)
{
    LogFlowThisFunc(("enable=%d\n", aCSAMEnabled));

    if (aCSAMEnabled)
        return setErrorBoth(VBOX_E_VM_ERROR, VERR_RAW_MODE_NOT_SUPPORTED, tr("CASM not present"));
    return S_OK;
}

/**
 * Returns the log enabled / disabled status.
 *
 * @returns COM status code
 * @param   aLogEnabled     address of result variable
 */
HRESULT MachineDebugger::getLogEnabled(BOOL *aLogEnabled)
{
#ifdef LOG_ENABLED
    AutoReadLock alock(this COMMA_LOCKVAL_SRC_POS);

    const PRTLOGGER pLogInstance = RTLogDefaultInstance();
    *aLogEnabled = pLogInstance && !(pLogInstance->fFlags & RTLOGFLAGS_DISABLED);
#else
    *aLogEnabled = false;
#endif

    return S_OK;
}

/**
 * Enables or disables logging.
 *
 * @returns COM status code
 * @param   aLogEnabled    The new code log state.
 */
HRESULT MachineDebugger::setLogEnabled(BOOL aLogEnabled)
{
    LogFlowThisFunc(("aLogEnabled=%d\n", aLogEnabled));

    AutoWriteLock alock(this COMMA_LOCKVAL_SRC_POS);

    if (i_queueSettings())
    {
        // queue the request
        mLogEnabledQueued = aLogEnabled;
        return S_OK;
    }

    Console::SafeVMPtr ptrVM(mParent);
    if (FAILED(ptrVM.rc())) return ptrVM.rc();

#ifdef LOG_ENABLED
    int vrc = DBGFR3LogModifyFlags(ptrVM.rawUVM(), aLogEnabled ? "enabled" : "disabled");
    if (RT_FAILURE(vrc))
    {
        /** @todo handle error code. */
    }
#endif

    return S_OK;
}

HRESULT MachineDebugger::i_logStringProps(PRTLOGGER pLogger, PFNLOGGETSTR pfnLogGetStr,
                                          const char *pszLogGetStr, Utf8Str *pstrSettings)
{
    /* Make sure the VM is powered up. */
    AutoWriteLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    if (FAILED(hrc))
        return hrc;

    /* Make sure we've got a logger. */
    if (!pLogger)
    {
        *pstrSettings = "";
        return S_OK;
    }

    /* Do the job. */
    size_t cbBuf = _1K;
    for (;;)
    {
        char *pszBuf = (char *)RTMemTmpAlloc(cbBuf);
        AssertReturn(pszBuf, E_OUTOFMEMORY);
        int vrc = pstrSettings->reserveNoThrow(cbBuf);
        if (RT_SUCCESS(vrc))
        {
            vrc = pfnLogGetStr(pLogger, pstrSettings->mutableRaw(), cbBuf);
            if (RT_SUCCESS(vrc))
            {
                pstrSettings->jolt();
                return S_OK;
            }
            *pstrSettings = "";
            AssertReturn(vrc == VERR_BUFFER_OVERFLOW,
                         setErrorBoth(VBOX_E_IPRT_ERROR, vrc, tr("%s returned %Rrc"), pszLogGetStr, vrc));
        }
        else
            return E_OUTOFMEMORY;

        /* try again with a bigger buffer. */
        cbBuf *= 2;
        AssertReturn(cbBuf <= _256K, setError(E_FAIL, tr("%s returns too much data"), pszLogGetStr));
    }
}

HRESULT MachineDebugger::getLogDbgFlags(com::Utf8Str &aLogDbgFlags)
{
    return i_logStringProps(RTLogGetDefaultInstance(), RTLogGetFlags, "RTGetFlags", &aLogDbgFlags);
}

HRESULT MachineDebugger::getLogDbgGroups(com::Utf8Str &aLogDbgGroups)
{
    return i_logStringProps(RTLogGetDefaultInstance(), RTLogGetGroupSettings, "RTLogGetGroupSettings", &aLogDbgGroups);
}

HRESULT MachineDebugger::getLogDbgDestinations(com::Utf8Str &aLogDbgDestinations)
{
    return i_logStringProps(RTLogGetDefaultInstance(), RTLogGetDestinations, "RTLogGetDestinations", &aLogDbgDestinations);
}

HRESULT MachineDebugger::getLogRelFlags(com::Utf8Str &aLogRelFlags)
{
    return i_logStringProps(RTLogRelGetDefaultInstance(), RTLogGetFlags, "RTGetFlags", &aLogRelFlags);
}

HRESULT MachineDebugger::getLogRelGroups(com::Utf8Str &aLogRelGroups)
{
    return i_logStringProps(RTLogRelGetDefaultInstance(), RTLogGetGroupSettings, "RTLogGetGroupSettings", &aLogRelGroups);
}

HRESULT MachineDebugger::getLogRelDestinations(com::Utf8Str &aLogRelDestinations)
{
    return i_logStringProps(RTLogRelGetDefaultInstance(), RTLogGetDestinations, "RTLogGetDestinations", &aLogRelDestinations);
}

/**
 * Return the main execution engine of the VM.
 *
 * @returns COM status code
 * @param   apenmEngine     Address of the result variable.
 */
HRESULT MachineDebugger::getExecutionEngine(VMExecutionEngine_T *apenmEngine)
{
    *apenmEngine = VMExecutionEngine_NotSet;

    AutoReadLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtrQuiet ptrVM(mParent);
    if (ptrVM.isOk())
    {
        uint8_t bEngine = UINT8_MAX;
        int rc = EMR3QueryMainExecutionEngine(ptrVM.rawUVM(), &bEngine);
        if (RT_SUCCESS(rc))
            switch (bEngine)
            {
                case VM_EXEC_ENGINE_NOT_SET:    *apenmEngine = VMExecutionEngine_NotSet; break;
                case VM_EXEC_ENGINE_RAW_MODE:   *apenmEngine = VMExecutionEngine_RawMode; break;
                case VM_EXEC_ENGINE_HW_VIRT:    *apenmEngine = VMExecutionEngine_HwVirt; break;
                case VM_EXEC_ENGINE_NATIVE_API: *apenmEngine = VMExecutionEngine_NativeApi; break;
                default: AssertMsgFailed(("bEngine=%d\n", bEngine));
            }
    }

    return S_OK;
}

/**
 * Returns the current hardware virtualization flag.
 *
 * @returns COM status code
 * @param   aHWVirtExEnabled    address of result variable
 */
HRESULT MachineDebugger::getHWVirtExEnabled(BOOL *aHWVirtExEnabled)
{
    *aHWVirtExEnabled = false;

    AutoReadLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtrQuiet ptrVM(mParent);
    if (ptrVM.isOk())
    {
        uint8_t bEngine = UINT8_MAX;
        int rc = EMR3QueryMainExecutionEngine(ptrVM.rawUVM(), &bEngine);
        *aHWVirtExEnabled = RT_SUCCESS(rc) && bEngine == VM_EXEC_ENGINE_HW_VIRT;
    }

    return S_OK;
}

/**
 * Returns the current nested paging flag.
 *
 * @returns COM status code
 * @param   aHWVirtExNestedPagingEnabled    address of result variable
 */
HRESULT MachineDebugger::getHWVirtExNestedPagingEnabled(BOOL *aHWVirtExNestedPagingEnabled)
{
    AutoReadLock alock(this COMMA_LOCKVAL_SRC_POS);

    Console::SafeVMPtrQuiet ptrVM(mParent);

    if (ptrVM.isOk())
        *aHWVirtExNestedPagingEnabled = HMR3IsNestedPagingActive(ptrVM.rawUVM());
    else
        *aHWVirtExNestedPagingEnabled = false;

    return S_OK;
}

/**
 * Returns the current VPID flag.
 *
 * @returns COM status code
 * @param   aHWVirtExVPIDEnabled address of result variable
 */
HRESULT MachineDebugger::getHWVirtExVPIDEnabled(BOOL *aHWVirtExVPIDEnabled)
{
    AutoReadLock alock(this COMMA_LOCKVAL_SRC_POS);

    Console::SafeVMPtrQuiet ptrVM(mParent);

    if (ptrVM.isOk())
        *aHWVirtExVPIDEnabled = HMR3IsVpidActive(ptrVM.rawUVM());
    else
        *aHWVirtExVPIDEnabled = false;

    return S_OK;
}

/**
 * Returns the current unrestricted execution setting.
 *
 * @returns COM status code
 * @param   aHWVirtExUXEnabled  address of result variable
 */
HRESULT MachineDebugger::getHWVirtExUXEnabled(BOOL *aHWVirtExUXEnabled)
{
    AutoReadLock alock(this COMMA_LOCKVAL_SRC_POS);

    Console::SafeVMPtrQuiet ptrVM(mParent);

    if (ptrVM.isOk())
        *aHWVirtExUXEnabled = HMR3IsUXActive(ptrVM.rawUVM());
    else
        *aHWVirtExUXEnabled = false;

    return S_OK;
}

HRESULT MachineDebugger::getOSName(com::Utf8Str &aOSName)
{
    LogFlowThisFunc(("\n"));
    AutoReadLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    if (SUCCEEDED(hrc))
    {
        /*
         * Do the job and try convert the name.
         */
        char szName[64];
        int vrc = DBGFR3OSQueryNameAndVersion(ptrVM.rawUVM(), szName, sizeof(szName), NULL, 0);
        if (RT_SUCCESS(vrc))
        {
            try
            {
                Bstr bstrName(szName);
                aOSName = Utf8Str(bstrName);
            }
            catch (std::bad_alloc &)
            {
                hrc = E_OUTOFMEMORY;
            }
        }
        else
            hrc = setErrorBoth(VBOX_E_VM_ERROR, vrc, tr("DBGFR3OSQueryNameAndVersion failed with %Rrc"), vrc);
    }
    return hrc;
}

HRESULT MachineDebugger::getOSVersion(com::Utf8Str &aOSVersion)
{
    LogFlowThisFunc(("\n"));
    AutoReadLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    if (SUCCEEDED(hrc))
    {
        /*
         * Do the job and try convert the name.
         */
        char szVersion[256];
        int vrc = DBGFR3OSQueryNameAndVersion(ptrVM.rawUVM(), NULL, 0, szVersion, sizeof(szVersion));
        if (RT_SUCCESS(vrc))
        {
            try
            {
                Bstr bstrVersion(szVersion);
                aOSVersion = Utf8Str(bstrVersion);
            }
            catch (std::bad_alloc &)
            {
                hrc = E_OUTOFMEMORY;
            }
        }
        else
            hrc = setErrorBoth(VBOX_E_VM_ERROR, vrc, tr("DBGFR3OSQueryNameAndVersion failed with %Rrc"), vrc);
    }
    return hrc;
}

/**
 * Returns the current PAE flag.
 *
 * @returns COM status code
 * @param   aPAEEnabled     address of result variable.
 */
HRESULT MachineDebugger::getPAEEnabled(BOOL *aPAEEnabled)
{
    AutoReadLock alock(this COMMA_LOCKVAL_SRC_POS);

    Console::SafeVMPtrQuiet ptrVM(mParent);

    if (ptrVM.isOk())
    {
        uint32_t cr4;
        int rc = DBGFR3RegCpuQueryU32(ptrVM.rawUVM(), 0 /*idCpu*/,  DBGFREG_CR4, &cr4); AssertRC(rc);
        *aPAEEnabled = RT_BOOL(cr4 & X86_CR4_PAE);
    }
    else
        *aPAEEnabled = false;

    return S_OK;
}

/**
 * Returns the current virtual time rate.
 *
 * @returns COM status code.
 * @param   aVirtualTimeRate    Where to store the rate.
 */
HRESULT MachineDebugger::getVirtualTimeRate(ULONG *aVirtualTimeRate)
{
    AutoReadLock alock(this COMMA_LOCKVAL_SRC_POS);

    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    if (SUCCEEDED(hrc))
        *aVirtualTimeRate = TMR3GetWarpDrive(ptrVM.rawUVM());

    return hrc;
}

/**
 * Set the virtual time rate.
 *
 * @returns COM status code.
 * @param   aVirtualTimeRate    The new rate.
 */
HRESULT MachineDebugger::setVirtualTimeRate(ULONG aVirtualTimeRate)
{
    HRESULT hrc = S_OK;

    if (aVirtualTimeRate < 2 || aVirtualTimeRate > 20000)
        return setError(E_INVALIDARG, tr("%u is out of range [2..20000]"), aVirtualTimeRate);

    AutoWriteLock alock(this COMMA_LOCKVAL_SRC_POS);
    if (i_queueSettings())
        mVirtualTimeRateQueued = aVirtualTimeRate;
    else
    {
        Console::SafeVMPtr ptrVM(mParent);
        hrc = ptrVM.rc();
        if (SUCCEEDED(hrc))
        {
            int vrc = TMR3SetWarpDrive(ptrVM.rawUVM(), aVirtualTimeRate);
            if (RT_FAILURE(vrc))
                hrc = setErrorBoth(VBOX_E_VM_ERROR, vrc, tr("TMR3SetWarpDrive(, %u) failed with rc=%Rrc"), aVirtualTimeRate, vrc);
        }
    }

    return hrc;
}

/**
 * Hack for getting the user mode VM handle (UVM).
 *
 * This is only temporary (promise) while prototyping the debugger.
 *
 * @returns COM status code
 * @param   aVM         Where to store the vm handle. Since there is no
 *                      uintptr_t in COM, we're using the max integer.
 *                      (No, ULONG is not pointer sized!)
 * @remarks The returned handle must be passed to VMR3ReleaseUVM()!
 * @remarks Prior to 4.3 this returned PVM.
 */
HRESULT MachineDebugger::getVM(LONG64 *aVM)
{
    AutoReadLock alock(this COMMA_LOCKVAL_SRC_POS);

    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    if (SUCCEEDED(hrc))
    {
        VMR3RetainUVM(ptrVM.rawUVM());
        *aVM = (intptr_t)ptrVM.rawUVM();
    }

    /*
     * Note! ptrVM protection provided by SafeVMPtr is no long effective
     *       after we return from this method.
     */
    return hrc;
}

/**
 * Get the VM uptime in milliseconds.
 *
 * @returns COM status code
 * @param   aUptime     Where to store the uptime.
 */
HRESULT MachineDebugger::getUptime(LONG64 *aUptime)
{
    AutoReadLock alock(this COMMA_LOCKVAL_SRC_POS);

    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    if (SUCCEEDED(hrc))
        *aUptime = (int64_t)TMR3TimeVirtGetMilli(ptrVM.rawUVM());

    return hrc;
}

// IMachineDebugger methods
/////////////////////////////////////////////////////////////////////////////

HRESULT MachineDebugger::dumpGuestCore(const com::Utf8Str &aFilename, const com::Utf8Str &aCompression)
{
    if (aCompression.length())
        return setError(E_INVALIDARG, tr("The compression parameter must be empty"));

    AutoWriteLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    if (SUCCEEDED(hrc))
    {
        int vrc = DBGFR3CoreWrite(ptrVM.rawUVM(), aFilename.c_str(), false /*fReplaceFile*/);
        if (RT_SUCCESS(vrc))
            hrc = S_OK;
        else
            hrc = setErrorBoth(E_FAIL, vrc, tr("DBGFR3CoreWrite failed with %Rrc"), vrc);
    }

    return hrc;
}

HRESULT MachineDebugger::dumpHostProcessCore(const com::Utf8Str &aFilename, const com::Utf8Str &aCompression)
{
    RT_NOREF(aFilename, aCompression);
    ReturnComNotImplemented();
}

/**
 * Debug info string buffer formatter.
 */
typedef struct MACHINEDEBUGGERINOFHLP
{
    /** The core info helper structure. */
    DBGFINFOHLP Core;
    /** Pointer to the buffer. */
    char       *pszBuf;
    /** The size of the buffer. */
    size_t      cbBuf;
    /** The offset into the buffer */
    size_t      offBuf;
    /** Indicates an out-of-memory condition. */
    bool        fOutOfMemory;
} MACHINEDEBUGGERINOFHLP;
/** Pointer to a Debug info string buffer formatter. */
typedef MACHINEDEBUGGERINOFHLP *PMACHINEDEBUGGERINOFHLP;


/**
 * @callback_method_impl{FNRTSTROUTPUT}
 */
static DECLCALLBACK(size_t) MachineDebuggerInfoOutput(void *pvArg, const char *pachChars, size_t cbChars)
{
    PMACHINEDEBUGGERINOFHLP pHlp = (PMACHINEDEBUGGERINOFHLP)pvArg;

    /*
     * Grow the buffer if required.
     */
    size_t const cbRequired  = cbChars + pHlp->offBuf + 1;
    if (cbRequired > pHlp->cbBuf)
    {
        if (RT_UNLIKELY(pHlp->fOutOfMemory))
            return 0;

        size_t cbBufNew = pHlp->cbBuf * 2;
        if (cbRequired > cbBufNew)
            cbBufNew = RT_ALIGN_Z(cbRequired, 256);
        void *pvBufNew = RTMemRealloc(pHlp->pszBuf, cbBufNew);
        if (RT_UNLIKELY(!pvBufNew))
        {
            pHlp->fOutOfMemory = true;
            RTMemFree(pHlp->pszBuf);
            pHlp->pszBuf = NULL;
            pHlp->cbBuf  = 0;
            pHlp->offBuf = 0;
            return 0;
        }

        pHlp->pszBuf = (char *)pvBufNew;
        pHlp->cbBuf  = cbBufNew;
    }

    /*
     * Copy the bytes into the buffer and terminate it.
     */
    if (cbChars)
    {
        memcpy(&pHlp->pszBuf[pHlp->offBuf], pachChars, cbChars);
        pHlp->offBuf += cbChars;
    }
    pHlp->pszBuf[pHlp->offBuf] = '\0';
    Assert(pHlp->offBuf < pHlp->cbBuf);
    return cbChars;
}

/**
 * @interface_method_impl{DBGFINFOHLP,pfnPrintfV}
 */
static DECLCALLBACK(void) MachineDebuggerInfoPrintfV(PCDBGFINFOHLP pHlp, const char *pszFormat, va_list args)
{
    RTStrFormatV(MachineDebuggerInfoOutput, (void *)pHlp, NULL,  NULL, pszFormat, args);
}

/**
 * @interface_method_impl{DBGFINFOHLP,pfnPrintf}
 */
static DECLCALLBACK(void) MachineDebuggerInfoPrintf(PCDBGFINFOHLP pHlp, const char *pszFormat, ...)
{
    va_list va;
    va_start(va, pszFormat);
    MachineDebuggerInfoPrintfV(pHlp, pszFormat, va);
    va_end(va);
}

/**
 * Initializes the debug info string buffer formatter
 *
 * @param   pHlp                The help structure to init.
 */
static void MachineDebuggerInfoInit(PMACHINEDEBUGGERINOFHLP pHlp)
{
    pHlp->Core.pfnPrintf        = MachineDebuggerInfoPrintf;
    pHlp->Core.pfnPrintfV       = MachineDebuggerInfoPrintfV;
    pHlp->Core.pfnGetOptError   = DBGFR3InfoGenricGetOptError;
    pHlp->pszBuf                = NULL;
    pHlp->cbBuf                 = 0;
    pHlp->offBuf                = 0;
    pHlp->fOutOfMemory          = false;
}

/**
 * Deletes the debug info string buffer formatter.
 * @param   pHlp                The helper structure to delete.
 */
static void MachineDebuggerInfoDelete(PMACHINEDEBUGGERINOFHLP pHlp)
{
    RTMemFree(pHlp->pszBuf);
    pHlp->pszBuf = NULL;
}

HRESULT MachineDebugger::info(const com::Utf8Str &aName, const com::Utf8Str &aArgs, com::Utf8Str &aInfo)
{
    LogFlowThisFunc(("\n"));

    /*
     * Do the autocaller and lock bits.
     */
    AutoCaller autoCaller(this);
    HRESULT hrc = autoCaller.rc();
    if (SUCCEEDED(hrc))
    {
        AutoWriteLock alock(this COMMA_LOCKVAL_SRC_POS);
        Console::SafeVMPtr ptrVM(mParent);
        hrc = ptrVM.rc();
        if (SUCCEEDED(hrc))
        {
            /*
             * Create a helper and call DBGFR3Info.
             */
            MACHINEDEBUGGERINOFHLP Hlp;
            MachineDebuggerInfoInit(&Hlp);
            int vrc = DBGFR3Info(ptrVM.rawUVM(),  aName.c_str(),  aArgs.c_str(), &Hlp.Core);
            if (RT_SUCCESS(vrc))
            {
                if (!Hlp.fOutOfMemory)
                {
                    /*
                     * Convert the info string, watching out for allocation errors.
                     */
                    try
                    {
                        Bstr bstrInfo(Hlp.pszBuf);
                        aInfo = bstrInfo;
                    }
                    catch (std::bad_alloc &)
                    {
                        hrc = E_OUTOFMEMORY;
                    }
                }
                else
                    hrc = E_OUTOFMEMORY;
            }
            else
                hrc = setErrorBoth(VBOX_E_VM_ERROR, vrc, tr("DBGFR3Info failed with %Rrc"), vrc);
            MachineDebuggerInfoDelete(&Hlp);
        }
    }
    return hrc;
}

HRESULT MachineDebugger::injectNMI()
{
    LogFlowThisFunc(("\n"));

    AutoWriteLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    if (SUCCEEDED(hrc))
    {
        int vrc = DBGFR3InjectNMI(ptrVM.rawUVM(), 0);
        if (RT_SUCCESS(vrc))
            hrc = S_OK;
        else
            hrc = setErrorBoth(E_FAIL, vrc, tr("DBGFR3InjectNMI failed with %Rrc"), vrc);
    }
    return hrc;
}

HRESULT MachineDebugger::modifyLogFlags(const com::Utf8Str &aSettings)
{
    LogFlowThisFunc(("aSettings=%s\n", aSettings.c_str()));
    AutoWriteLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    if (SUCCEEDED(hrc))
    {
        int vrc = DBGFR3LogModifyFlags(ptrVM.rawUVM(), aSettings.c_str());
        if (RT_SUCCESS(vrc))
            hrc = S_OK;
        else
            hrc = setErrorBoth(E_FAIL, vrc, tr("DBGFR3LogModifyFlags failed with %Rrc"), vrc);
    }
    return hrc;
}

HRESULT MachineDebugger::modifyLogGroups(const com::Utf8Str &aSettings)
{
    LogFlowThisFunc(("aSettings=%s\n", aSettings.c_str()));
    AutoWriteLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    if (SUCCEEDED(hrc))
    {
        int vrc = DBGFR3LogModifyGroups(ptrVM.rawUVM(), aSettings.c_str());
        if (RT_SUCCESS(vrc))
            hrc = S_OK;
        else
            hrc = setErrorBoth(E_FAIL, vrc, tr("DBGFR3LogModifyGroups failed with %Rrc"), vrc);
    }
    return hrc;
}

HRESULT MachineDebugger::modifyLogDestinations(const com::Utf8Str &aSettings)
{
    LogFlowThisFunc(("aSettings=%s\n", aSettings.c_str()));
    AutoWriteLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    if (SUCCEEDED(hrc))
    {
        int vrc = DBGFR3LogModifyDestinations(ptrVM.rawUVM(), aSettings.c_str());
        if (RT_SUCCESS(vrc))
            hrc = S_OK;
        else
            hrc = setErrorBoth(E_FAIL, vrc, tr("DBGFR3LogModifyDestinations failed with %Rrc"), vrc);
    }
    return hrc;
}



VMMDECL(int) FDPVBOX_readPhysicalMemory(PUVM pUVM, uint8_t *pDstBuffer, uint64_t PhysicalAddress, uint32_t ReadSize)
{
    Log1("[DBGC] READ_PHYSICAL %p %d %s ... \n", PhysicalAddress, ReadSize, pDstBuffer ? "OK" : "NULL");
    return VMR3PhysSimpleReadGCPhysU(pUVM, pDstBuffer, PhysicalAddress, ReadSize);
}

VMMDECL(int) FDPVBOX_writePhysicalMemory(PUVM pUVM, uint8_t *pSrcBuffer, uint64_t PhysicalAddress, uint32_t WriteSize)
{
    Log1("[DBGC] WRITE_PHYSICAL %p %d...\n", PhysicalAddress, WriteSize);
    void* TempBuffer = RTMemAlloc(WriteSize);
    int ret = FDPVBOX_readPhysicalMemory(pUVM, (uint8_t*)TempBuffer, PhysicalAddress, WriteSize);
    RTMemFree(TempBuffer);
    //Check Read access
    if (RT_FAILURE(ret))
        return ret;
    //Effective Write
    return VMR3PhysSimpleWriteGCPhysU(pUVM, pSrcBuffer, PhysicalAddress, WriteSize);
}

std::vector<BYTE> duplex_array;

HRESULT MachineDebugger::readPhysicalMemory(LONG64 aAddress, ULONG aSize, std::vector<BYTE> &aBytes)
{
    HRESULT hrc;
    int rc;
    uint16_t* addr_rd_ptr = (uint16_t *)&aAddress;

    Log1("[readPhysicalMemory] Reading physical memory...\n");
    AutoReadLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtr ptrVM(mParent);
    hrc = ptrVM.rc();
    if (SUCCEEDED(hrc))
    {
        if (addr_rd_ptr[3] == 0xbe01)
        {
            aBytes = duplex_array;
            hrc = VINF_SUCCESS;
        }
        else if (addr_rd_ptr[3] == 0xbe02)
        {
            aBytes = std::vector<BYTE>(8);
            uint64_t* event_type = (uint64_t *)&aBytes[0];
            *event_type = 0;

            while (1)
            {
                rc = DBGFR3QueryWaitable(ptrVM.rawUVM());

                if (RT_SUCCESS(rc))
                {
                    /*
                     * Wait for a debug event.
                     */
                    PCDBGFEVENT pEvent;
                    rc = DBGFR3EventWait(ptrVM.rawUVM(), 32, &pEvent);
                    if (RT_FAILURE(rc))
                    {
                        break;
                    }

                    switch (pEvent->enmType)
                    {
                    case DBGFEVENT_BREAKPOINT:
                        if (DBGFR3IsHalted(ptrVM.rawUVM()))
                        {
                            *event_type = 0x1;
                        }
                        break;
                    case DBGFEVENT_BREAKPOINT_IO:
                        *event_type = 0x2;
                        break;
                    case DBGFEVENT_BREAKPOINT_MMIO:
                        *event_type = 0x3;
                        break;
                    case DBGFEVENT_BREAKPOINT_HYPER:
                        *event_type = 0x4;
                        break;
                    case DBGFEVENT_STEPPED:
                        *event_type = 0x5;
                        break;
                    case DBGFEVENT_STEPPED_HYPER:
                        *event_type = 0x6;
                        break;
                    case DBGFEVENT_HALT_DONE:
                        *event_type = 0x7;
                        break;
                    case DBGFEVENT_FATAL_ERROR:
                        *event_type = 0x8;
                        break;
                    case DBGFEVENT_ASSERTION_HYPER:
                        *event_type = 0x9;
                        break;
                    case DBGFEVENT_DEV_STOP:
                        *event_type = 0xa;
                        break;
                    case DBGFEVENT_INVALID_COMMAND:
                        *event_type = 0xb;
                        break;
                    case DBGFEVENT_POWERING_OFF:
                        *event_type = 0xc;
                        break;
                    default:
                        break;
                    }
                }
                else
                {
                    break;
                }
            }

            hrc = VINF_SUCCESS;
        }
        else
        {
            void* rd_buff = RTMemAlloc(aSize);
            rc = FDPVBOX_readPhysicalMemory(ptrVM.rawUVM(), (uint8_t*)rd_buff, aAddress, aSize);
            if (RT_FAILURE(rc))
            {
                PCRTSTATUSMSG pMsg = RTErrGet(rc);
                hrc = setError(E_FAIL, pMsg->pszMsgFull);
            }
            aBytes = std::vector<BYTE>((BYTE*)(rd_buff), (BYTE*)(rd_buff)+aSize);

            RTMemFree(rd_buff);
        }
    }

    return hrc;
}

HRESULT MachineDebugger::writePhysicalMemory(LONG64 aAddress, ULONG aSize, const std::vector<BYTE> &aBytes)
{
    AutoWriteLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtr ptrVM(mParent);
    uint16_t* addr_rd_ptr = (uint16_t *)&aAddress;
    uint64_t* param_array = (uint64_t *)&aBytes[0];
    HRESULT hrc = ptrVM.rc();
    int rc;
    if (SUCCEEDED(hrc))
    {
        if (addr_rd_ptr[3] == 0xbe03)
        {
            uint64_t is_hard_brkp = param_array[0];
            uint64_t hard_type = param_array[1];
            uint64_t cpu_id = param_array[2];
            uint64_t address = param_array[3];
            uint64_t hit_trigger = param_array[4];
            uint64_t has_hit_disable = param_array[5];
            uint64_t hit_disable = param_array[6];
            uint64_t access_sz = param_array[7];
            duplex_array = std::vector<BYTE>(4);
            uint32_t* ibp = (uint32_t *)&duplex_array[0];

            DBGFADDRESS dbg_address;
            DBGFR3AddrFromFlat(ptrVM.rawUVM(), &dbg_address, address);
            if (!has_hit_disable)
            {
                hit_disable = UINT64_MAX;
            }

            if (is_hard_brkp)
            {
                if (hard_type > 3)
                {
                    return setError(E_FAIL, tr("Invalid hard_type %lu"), hard_type);
                }

                uint8_t fType = 0;
                switch (hard_type)
                {
                    case 0:  fType = X86_DR7_RW_EO; break;
                    case 1:  fType = X86_DR7_RW_RW; break;
                    case 2:  fType = X86_DR7_RW_WO; break;
                    case 3:  fType = X86_DR7_RW_IO; break;
                }

                if (fType == X86_DR7_RW_EO)
                {
                    access_sz = 1;
                }
                switch (access_sz)
                {
                    case 1:
                    case 2:
                    case 4:
                        break;
                    /*case 8: - later*/
                    default:
                        return setError(E_FAIL, tr("Invalid access size %lu"), access_sz);
                }

                rc = DBGFR3BpSetReg(ptrVM.rawUVM(), &dbg_address, hit_trigger, hit_disable, fType, (uint8_t)access_sz, ibp);
                if (RT_FAILURE(rc))
                {
                    return setError(E_FAIL, tr("Failed to set access point"));
                }
            }
            else
            {
                rc = DBGFR3BpSetInt3(ptrVM.rawUVM(), (uint32_t)cpu_id, &dbg_address, hit_trigger, hit_disable, ibp);
                if (RT_FAILURE(rc))
                {
                    return setError(E_FAIL, tr("Failed to set software breakpoint"));
                }
            }

            hrc = VINF_SUCCESS;
        }
        else if (addr_rd_ptr[3] == 0xbe04)
        {
            uint32_t ibp = (uint32_t)param_array[0];
            rc = DBGFR3BpClear(ptrVM.rawUVM(), ibp);
            if (RT_FAILURE(rc))
            {
                return setError(E_FAIL, tr("Failed to delete breakpoint"));
            }
        }
        else if (addr_rd_ptr[3] == 0xbe05 || addr_rd_ptr[3] == 0xbe06)
        {
            uint32_t cpu_id = (uint32_t)param_array[0];
            PDBGFADDRESS pStackPop  = NULL;
            RTGCPTR      cbStackPop = 0;
            uint32_t     cMaxSteps  = addr_rd_ptr[3] == 0xbe05 ? _512K : _64K;
            uint32_t     fFlags     = addr_rd_ptr[3] == 0xbe05 ? DBGF_STEP_F_OVER : DBGF_STEP_F_INTO;

            if (addr_rd_ptr[3] != 0xbe05)
                cMaxSteps = 1;
            else
            {
                /** @todo consider passing RSP + 1 in for 'p' and something else sensible for
                 *        the 'pt' command. */
            }

            rc = DBGFR3StepEx(ptrVM.rawUVM(), cpu_id, fFlags, NULL, pStackPop, cbStackPop, cMaxSteps);
            if (RT_SUCCESS(rc))
            {
                hrc = VINF_SUCCESS;
            }
            else
            {
                hrc = setError(E_FAIL, tr("DBGFR3StepEx failed"));
            }
        }
        else if (addr_rd_ptr[3] == 0xbe07)
        {
            uint32_t cpu_id = (uint32_t)param_array[0];
            uint64_t vir_addr = param_array[1];
            duplex_array = std::vector<BYTE>(8);
            uint64_t* phy_addr = (uint64_t *)&duplex_array[0];

            if(cpu_id >= VMR3GetCPUCount(ptrVM.rawUVM())){
                return VERR_GENERAL_FAILURE;
            }
            PVMCPU pVCpu = VMMR3GetCpuByIdU(ptrVM.rawUVM(), cpu_id);

            rc = VMR3PhysGCPtr2GCPhys(pVCpu, vir_addr, phy_addr);
            if (RT_FAILURE(rc))
            {
                PCRTSTATUSMSG pMsg = RTErrGet(rc);
                hrc = setError(E_FAIL, pMsg->pszMsgFull);
            }
        }
        else
        {
            rc = FDPVBOX_writePhysicalMemory(ptrVM.rawUVM(), (uint8_t *)&aBytes[0], aAddress, aSize);
            if (RT_FAILURE(rc))
            {
                PCRTSTATUSMSG pMsg = RTErrGet(rc);
                hrc = setError(E_FAIL, pMsg->pszMsgFull);
            }
        }
    }
    return hrc;
}

VMMDECL(int) FDPVBOX_readVirtualMemory(PUVM pUVM, uint32_t CpuId, uint64_t VirtualAddress, uint32_t ReadSize, uint8_t *pDstBuffer)
{
    if(CpuId >= VMR3GetCPUCount(pUVM)){
        return VERR_GENERAL_FAILURE;
    }
    PVMCPU pVCpu = VMMR3GetCpuByIdU(pUVM, CpuId);

    return VMR3PhysSimpleReadGCPtr(pVCpu, pDstBuffer, VirtualAddress, ReadSize);
}

VMMDECL(int) FDPVBOX_writeVirtualMemory(PUVM pUVM, uint32_t CpuId, uint8_t *pSrcBuffer, uint64_t VirtualAddress, uint32_t WriteSize)
{
    Log1("[DBGC] writeVirtualMemory %p %d ...\n", VirtualAddress, WriteSize);
    if(CpuId >= VMR3GetCPUCount(pUVM)){
        return VERR_GENERAL_FAILURE;
    }
    PVMCPU pVCpu = VMMR3GetCpuByIdU(pUVM, CpuId);
    return VMR3PhysSimpleWriteGCPtr(pVCpu, VirtualAddress, pSrcBuffer, WriteSize);
}

HRESULT MachineDebugger::readVirtualMemory(ULONG aCpuId, LONG64 aAddress, ULONG aSize, std::vector<BYTE> &aBytes)
{
    AutoReadLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    if (SUCCEEDED(hrc))
    {
        void* rd_buff = RTMemAlloc(aSize);
        int rc = FDPVBOX_readVirtualMemory(ptrVM.rawUVM(), aCpuId, aAddress, aSize, (uint8_t*)rd_buff);
        if (RT_FAILURE(rc))
        {
            PCRTSTATUSMSG pMsg = RTErrGet(rc);
            hrc = setError(E_FAIL, pMsg->pszMsgFull);
        }

        aBytes = std::vector<BYTE>((BYTE*)(rd_buff), (BYTE*)(rd_buff)+aSize);

        RTMemFree(rd_buff);
    }
    return hrc;
}

HRESULT MachineDebugger::writeVirtualMemory(ULONG aCpuId, LONG64 aAddress, ULONG aSize, const std::vector<BYTE> &aBytes)
{
    AutoWriteLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    if (SUCCEEDED(hrc))
    {
        int rc = FDPVBOX_writeVirtualMemory(ptrVM.rawUVM(), aCpuId, (uint8_t *)&aBytes[0], aAddress, aSize);
        if (RT_FAILURE(rc))
        {
            PCRTSTATUSMSG pMsg = RTErrGet(rc);
            hrc = setError(E_FAIL, pMsg->pszMsgFull);
        }
    }
    return hrc;
}

HRESULT MachineDebugger::loadPlugIn(const com::Utf8Str &aName, com::Utf8Str &aPlugInName)
{
    /*
     * Lock the debugger and get the VM pointer
     */
    AutoWriteLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    if (SUCCEEDED(hrc))
    {
        int vrc;
        /*
         * Do the job and try convert the name.
         */
        vrc = test_attach(ptrVM.rawUVM());
        if (RT_FAILURE(vrc))
        {
            hrc = setErrorVrc(vrc, "test_attach() failed in loadPlugIn()");
        }



        if (aName.equals("all"))
        {
            DBGFR3PlugInLoadAll(ptrVM.rawUVM());
            try
            {
                aPlugInName = "all";
                hrc = S_OK;
            }
            catch (std::bad_alloc &)
            {
                hrc = E_OUTOFMEMORY;
            }
        }
        else
        {
            RTERRINFOSTATIC ErrInfo;
            char            szName[80];
            vrc = DBGFR3PlugInLoad(ptrVM.rawUVM(), aName.c_str(), szName, sizeof(szName), RTErrInfoInitStatic(&ErrInfo));
            if (RT_SUCCESS(vrc))
            {
                try
                {
                    aPlugInName = szName;
                    hrc = S_OK;
                }
                catch (std::bad_alloc &)
                {
                    hrc = E_OUTOFMEMORY;
                }
            }
            else
                hrc = setErrorVrc(vrc, "%s", ErrInfo.szMsg);
        }
    }
    return hrc;

}

HRESULT MachineDebugger::unloadPlugIn(const com::Utf8Str &aName)
{
    /*
     * Lock the debugger and get the VM pointer
     */
    AutoWriteLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    if (SUCCEEDED(hrc))
    {
        int vrc;

        /*
         * Do the job and try convert the name.
         */
        if (aName.equals("all"))
        {
            DBGFR3PlugInUnloadAll(ptrVM.rawUVM());
            hrc = S_OK;
        }
        else
        {
            vrc = DBGFR3PlugInUnload(ptrVM.rawUVM(), aName.c_str());
            if (RT_SUCCESS(vrc))
                hrc = S_OK;
            else if (vrc == VERR_NOT_FOUND)
                hrc = setErrorBoth(E_FAIL, vrc, "Plug-in '%s' was not found", aName.c_str());
            else
                hrc = setErrorVrc(vrc, "Error unloading '%s': %Rrc", aName.c_str(), vrc);
        }

        vrc = test_detach(ptrVM.rawUVM());
        if (RT_FAILURE(vrc))
        {
            hrc = setErrorVrc(vrc, "test_detach() failed in unloadPlugIn()");
        }
    }
    return hrc;

}

HRESULT MachineDebugger::detectOS(com::Utf8Str &aOs)
{
    LogFlowThisFunc(("\n"));

    /*
     * Lock the debugger and get the VM pointer
     */
    AutoWriteLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    if (SUCCEEDED(hrc))
    {
        /*
         * Do the job.
         */
        char szName[64];
        int vrc = DBGFR3OSDetect(ptrVM.rawUVM(), szName, sizeof(szName));
        if (RT_SUCCESS(vrc) && vrc != VINF_DBGF_OS_NOT_DETCTED)
        {
            try
            {
                aOs = szName;
            }
            catch (std::bad_alloc &)
            {
                hrc = E_OUTOFMEMORY;
            }
        }
        else
            hrc = setErrorBoth(VBOX_E_VM_ERROR, vrc, tr("DBGFR3OSDetect failed with %Rrc"), vrc);
    }
    return hrc;
}

HRESULT MachineDebugger::queryOSKernelLog(ULONG aMaxMessages, com::Utf8Str &aDmesg)
{
    /*
     * Lock the debugger and get the VM pointer
     */
    AutoWriteLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    if (SUCCEEDED(hrc))
    {
        PDBGFOSIDMESG pDmesg = (PDBGFOSIDMESG)DBGFR3OSQueryInterface(ptrVM.rawUVM(), DBGFOSINTERFACE_DMESG);
        if (pDmesg)
        {
            size_t   cbActual;
            size_t   cbBuf  = _512K;
            int vrc = aDmesg.reserveNoThrow(cbBuf);
            if (RT_SUCCESS(vrc))
            {
                uint32_t cMessages = aMaxMessages == 0 ? UINT32_MAX : aMaxMessages;
                vrc = pDmesg->pfnQueryKernelLog(pDmesg, ptrVM.rawUVM(), 0 /*fFlags*/, cMessages,
                                                aDmesg.mutableRaw(), cbBuf, &cbActual);

                uint32_t cTries = 10;
                while (vrc == VERR_BUFFER_OVERFLOW && cbBuf < 16*_1M && cTries-- > 0)
                {
                    cbBuf = RT_ALIGN_Z(cbActual + _4K, _4K);
                    vrc = aDmesg.reserveNoThrow(cbBuf);
                    if (RT_SUCCESS(vrc))
                        vrc = pDmesg->pfnQueryKernelLog(pDmesg, ptrVM.rawUVM(), 0 /*fFlags*/, cMessages,
                                                        aDmesg.mutableRaw(), cbBuf, &cbActual);
                }
                if (RT_SUCCESS(vrc))
                    aDmesg.jolt();
                else if (vrc == VERR_BUFFER_OVERFLOW)
                    hrc = setError(E_FAIL, "Too much log available, must use the maxMessages parameter to restrict.");
                else
                    hrc = setErrorVrc(vrc);
            }
            else
                hrc = setErrorBoth(E_OUTOFMEMORY, vrc);
        }
        else
            hrc = setError(E_FAIL, "The dmesg interface isn't implemented by guest OS digger, or detectOS() has not been called.");
    }
    return hrc;
}

/**
 * Formats a register value.
 *
 * This is used by both register getter methods.
 *
 * @returns
 * @param   a_pbstr             The output Bstr variable.
 * @param   a_pValue            The value to format.
 * @param   a_enmType           The type of the value.
 */
DECLINLINE(HRESULT) formatRegisterValue(Bstr *a_pbstr, PCDBGFREGVAL a_pValue, DBGFREGVALTYPE a_enmType)
{
    char szHex[160];
    ssize_t cch = DBGFR3RegFormatValue(szHex, sizeof(szHex), a_pValue, a_enmType, true /*fSpecial*/);
    if (RT_UNLIKELY(cch <= 0))
        return E_UNEXPECTED;
    *a_pbstr = szHex;
    return S_OK;
}

HRESULT MachineDebugger::getRegister(ULONG aCpuId, const com::Utf8Str &aName, com::Utf8Str &aValue)
{
    /*
     * The prologue.
     */
    LogFlowThisFunc(("\n"));
    AutoWriteLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    if (SUCCEEDED(hrc))
    {
        /*
         * Real work.
         */
        DBGFREGVAL      Value;
        DBGFREGVALTYPE  enmType;
        int vrc = DBGFR3RegNmQuery(ptrVM.rawUVM(), aCpuId, aName.c_str(), &Value, &enmType);
        if (RT_SUCCESS(vrc))
        {
            try
            {
                Bstr bstrValue;
                hrc = formatRegisterValue(&bstrValue, &Value, enmType);
                if (SUCCEEDED(hrc))
                    aValue = Utf8Str(bstrValue);
            }
            catch (std::bad_alloc &)
            {
                hrc = E_OUTOFMEMORY;
            }
        }
        else if (vrc == VERR_DBGF_REGISTER_NOT_FOUND)
            hrc = setErrorBoth(E_FAIL, vrc, tr("Register '%s' was not found"), aName.c_str());
        else if (vrc == VERR_INVALID_CPU_ID)
            hrc = setErrorBoth(E_FAIL, vrc, tr("Invalid CPU ID: %u"), aCpuId);
        else
            hrc = setErrorBoth(VBOX_E_VM_ERROR, vrc,
                               tr("DBGFR3RegNmQuery failed with rc=%Rrc querying register '%s' with default cpu set to %u"),
                               vrc, aName.c_str(), aCpuId);
    }

    return hrc;
}

HRESULT MachineDebugger::getRegisters(ULONG aCpuId, std::vector<com::Utf8Str> &aNames, std::vector<com::Utf8Str> &aValues)
{
    RT_NOREF(aCpuId); /** @todo fix missing aCpuId usage! */

    /*
     * The prologue.
     */
    LogFlowThisFunc(("\n"));
    AutoWriteLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    if (SUCCEEDED(hrc))
    {
        /*
         * Real work.
         */
        size_t cRegs;
        int vrc = DBGFR3RegNmQueryAllCount(ptrVM.rawUVM(), &cRegs);
        if (RT_SUCCESS(vrc))
        {
            PDBGFREGENTRYNM paRegs = (PDBGFREGENTRYNM)RTMemAllocZ(sizeof(paRegs[0]) * cRegs);
            if (paRegs)
            {
                vrc = DBGFR3RegNmQueryAll(ptrVM.rawUVM(), paRegs, cRegs);
                if (RT_SUCCESS(vrc))
                {
                    try
                    {
                        aValues.resize(cRegs);
                        aNames.resize(cRegs);
                        for (uint32_t iReg = 0; iReg < cRegs; iReg++)
                        {
                            char szHex[160];
                            szHex[159] = szHex[0] = '\0';
                            ssize_t cch = DBGFR3RegFormatValue(szHex, sizeof(szHex), &paRegs[iReg].Val,
                                                               paRegs[iReg].enmType, true /*fSpecial*/);
                            //Assert(cch > 0); NOREF(cch);
                            aNames[iReg] = Utf8Str(paRegs[iReg].pszName);
                            aValues[iReg] = Utf8Str(szHex);
                        }
                    }
                    catch (std::bad_alloc &)
                    {
                        hrc = E_OUTOFMEMORY;
                    }
                }
                else
                    hrc = setErrorBoth(E_FAIL, vrc, tr("DBGFR3RegNmQueryAll failed with %Rrc"), vrc);

                RTMemFree(paRegs);
            }
            else
                hrc = E_OUTOFMEMORY;
        }
        else
            hrc = setErrorBoth(E_FAIL, vrc, tr("DBGFR3RegNmQueryAllCount failed with %Rrc"), vrc);
    }
    return hrc;
}

static int _str2num(const char *pachExpr, size_t cchExpr, unsigned uBase, uint64_t* pArg)
{
    /*
     * Empty expressions cannot be valid numbers.
     */
    if (!cchExpr)
        return VERR_DBGC_PARSE_INVALID_NUMBER;

    /*
     * Convert to number.
     */
    uint64_t    u64 = 0;
    while (cchExpr-- > 0)
    {
        char const ch = *pachExpr;
        uint64_t    u64Prev = u64;
        unsigned    u = ch - '0';
        if (u < 10 && u < uBase)
            u64 = u64 * uBase + u;
        else if (ch >= 'a' && (u = ch - ('a' - 10)) < uBase)
            u64 = u64 * uBase + u;
        else if (ch >= 'A' && (u = ch - ('A' - 10)) < uBase)
            u64 = u64 * uBase + u;
        else
            return VERR_DBGC_PARSE_INVALID_NUMBER;

        /* check for overflow - ARG!!! How to detect overflow correctly!?!?!? */
        if (u64Prev != u64 / uBase)
            return VERR_DBGC_PARSE_NUMBER_TOO_BIG;

        /* next */
        pachExpr++;
    }

    /*
     * Initialize the argument.
     */
    *pArg = u64;

    return VINF_SUCCESS;
}

static int str2num(char *pszExpr, uint64_t* pResult)
{
    char const  ch  = pszExpr[0];
    char const  ch2 = pszExpr[1];
    size_t cchExpr = strlen(pszExpr);

    /* 0x<hex digits> */
    if (ch == '0' && (ch2 == 'x' || ch2 == 'X'))
        return _str2num(pszExpr + 2, cchExpr - 2, 16, pResult);

    /* <hex digits>h */
    if (RT_C_IS_XDIGIT(*pszExpr) && (pszExpr[cchExpr - 1] == 'h' || pszExpr[cchExpr - 1] == 'H'))
    {
        pszExpr[cchExpr] = '\0';
        return _str2num(pszExpr, cchExpr - 1, 16, pResult);
    }

    /* 0i<decimal digits> */
    if (ch == '0' && ch2 == 'i')
        return _str2num(pszExpr + 2, cchExpr - 2, 10, pResult);

    /* 0t<octal digits> */
    if (ch == '0' && ch2 == 't')
        return _str2num(pszExpr + 2, cchExpr - 2, 8, pResult);

    /* 0y<binary digits> */
    if (ch == '0' && ch2 == 'y')
        return _str2num(pszExpr + 2, cchExpr - 2, 10, pResult);

    /* Hex number? */
    unsigned off = 0;
    while (off < cchExpr && (RT_C_IS_XDIGIT(pszExpr[off]) || pszExpr[off] == '`'))
        off++;
    if (off == cchExpr)
        return _str2num(pszExpr, cchExpr, 16, pResult);

    return VERR_DBGC_PARSE_INVALID_NUMBER;
}



HRESULT MachineDebugger::setRegister(ULONG aCpuId, const com::Utf8Str &aName, const com::Utf8Str &aValue)
{
    AutoWriteLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    int vrc;
    if (SUCCEEDED(hrc))
    {
        // from getRegister()
        DBGFREGVAL      Value;
        DBGFREGVALTYPE  enmType;
        vrc = DBGFR3RegNmQuery(ptrVM.rawUVM(), aCpuId, aName.c_str(), &Value, &enmType);
        if (RT_FAILURE(vrc))
        {
            if (vrc == VERR_DBGF_REGISTER_NOT_FOUND)
                return setErrorBoth(E_FAIL, vrc, tr("Register '%s' was not found"), aName.c_str());
            else if (vrc == VERR_INVALID_CPU_ID)
                return setErrorBoth(E_FAIL, vrc, tr("Invalid CPU ID: %u"), aCpuId);
            else
                return setErrorBoth(VBOX_E_VM_ERROR, vrc,
                               tr("DBGFR3RegNmQuery failed with rc=%Rrc querying register '%s' with default cpu set to %u"),
                               vrc, aName.c_str(), aCpuId);
        }





        // origin
        const char *reg_value_s = aValue.c_str();
        char *reg_value_s_array = (char *)malloc(strlen(reg_value_s) + 1);
        uint64_t reg_value;
        strcpy(reg_value_s_array, reg_value_s);
        vrc = str2num(reg_value_s_array, &reg_value);

        if (RT_SUCCESS(vrc))
        {
            Value.u64 = reg_value;
            vrc = DBGFR3RegNmSet(ptrVM.rawUVM(), aCpuId, aName.c_str(), &Value, enmType);
            if (RT_FAILURE(vrc))
                return setErrorBoth(E_FAIL, vrc, tr("DBGFR3RegNmSet() failed!"));
        }
        else
            return E_INVALIDARG;
    }

    return hrc;
}

HRESULT MachineDebugger::setRegisters(ULONG aCpuId, const std::vector<com::Utf8Str> &aNames,
                                      const std::vector<com::Utf8Str> &aValues)
{
    RT_NOREF(aCpuId, aNames, aValues);
    ReturnComNotImplemented();
}

HRESULT MachineDebugger::dumpGuestStack(ULONG aCpuId, com::Utf8Str &aStack)
{
    /*
     * The prologue.
     */
    LogFlowThisFunc(("\n"));
    AutoWriteLock alock(this COMMA_LOCKVAL_SRC_POS);
    Console::SafeVMPtr ptrVM(mParent);
    HRESULT hrc = ptrVM.rc();
    if (SUCCEEDED(hrc))
    {
        /*
         * There is currently a problem with the windows diggers and SMP, where
         * guest driver memory is being read from CPU zero in order to ensure that
         * we've got a consisten virtual memory view.  If one of the other CPUs
         * initiates a rendezvous while we're unwinding the stack and trying to
         * read guest driver memory, we will deadlock.
         *
         * So, check the VM state and maybe suspend the VM before we continue.
         */
        int  vrc     = VINF_SUCCESS;
        bool fPaused = false;
        if (aCpuId != 0)
        {
            VMSTATE enmVmState = VMR3GetStateU(ptrVM.rawUVM());
            if (   enmVmState == VMSTATE_RUNNING
                || enmVmState == VMSTATE_RUNNING_LS)
            {
                alock.release();
                vrc = VMR3Suspend(ptrVM.rawUVM(), VMSUSPENDREASON_USER);
                alock.acquire();
                fPaused = RT_SUCCESS(vrc);
            }
        }
        if (RT_SUCCESS(vrc))
        {
            PCDBGFSTACKFRAME pFirstFrame;
            vrc = DBGFR3StackWalkBegin(ptrVM.rawUVM(), aCpuId, DBGFCODETYPE_GUEST, &pFirstFrame);
            if (RT_SUCCESS(vrc))
            {
                /*
                 * Print header.
                 */
                try
                {
                    uint32_t fBitFlags = 0;
                    for (PCDBGFSTACKFRAME pFrame = pFirstFrame;
                         pFrame;
                         pFrame = DBGFR3StackWalkNext(pFrame))
                    {
                        uint32_t const fCurBitFlags = pFrame->fFlags & (DBGFSTACKFRAME_FLAGS_16BIT | DBGFSTACKFRAME_FLAGS_32BIT | DBGFSTACKFRAME_FLAGS_64BIT);
                        if (fCurBitFlags & DBGFSTACKFRAME_FLAGS_16BIT)
                        {
                            if (fCurBitFlags != fBitFlags)
                                aStack.append("SS:BP     Ret SS:BP Ret CS:EIP    Arg0     Arg1     Arg2     Arg3     CS:EIP / Symbol [line]\n");
                            aStack.append(Utf8StrFmt("%04RX16:%04RX16 %04RX16:%04RX16 %04RX32:%08RX32 %08RX32 %08RX32 %08RX32 %08RX32",
                                                     pFrame->AddrFrame.Sel,
                                                     (uint16_t)pFrame->AddrFrame.off,
                                                     pFrame->AddrReturnFrame.Sel,
                                                     (uint16_t)pFrame->AddrReturnFrame.off,
                                                     (uint32_t)pFrame->AddrReturnPC.Sel,
                                                     (uint32_t)pFrame->AddrReturnPC.off,
                                                     pFrame->Args.au32[0],
                                                     pFrame->Args.au32[1],
                                                     pFrame->Args.au32[2],
                                                     pFrame->Args.au32[3]));
                        }
                        else if (fCurBitFlags & DBGFSTACKFRAME_FLAGS_32BIT)
                        {
                            if (fCurBitFlags != fBitFlags)
                                aStack.append("EBP      Ret EBP  Ret CS:EIP    Arg0     Arg1     Arg2     Arg3     CS:EIP / Symbol [line]\n");
                            aStack.append(Utf8StrFmt("%08RX32 %08RX32 %04RX32:%08RX32 %08RX32 %08RX32 %08RX32 %08RX32",
                                                     (uint32_t)pFrame->AddrFrame.off,
                                                     (uint32_t)pFrame->AddrReturnFrame.off,
                                                     (uint32_t)pFrame->AddrReturnPC.Sel,
                                                     (uint32_t)pFrame->AddrReturnPC.off,
                                                     pFrame->Args.au32[0],
                                                     pFrame->Args.au32[1],
                                                     pFrame->Args.au32[2],
                                                     pFrame->Args.au32[3]));
                        }
                        else if (fCurBitFlags & DBGFSTACKFRAME_FLAGS_64BIT)
                        {
                            if (fCurBitFlags != fBitFlags)
                                aStack.append("RBP              Ret SS:RBP            Ret RIP          CS:RIP / Symbol [line]\n");
                            aStack.append(Utf8StrFmt("%016RX64 %04RX16:%016RX64 %016RX64",
                                                     (uint64_t)pFrame->AddrFrame.off,
                                                     pFrame->AddrReturnFrame.Sel,
                                                     (uint64_t)pFrame->AddrReturnFrame.off,
                                                     (uint64_t)pFrame->AddrReturnPC.off));
                        }

                        if (!pFrame->pSymPC)
                            aStack.append(Utf8StrFmt(fCurBitFlags & DBGFSTACKFRAME_FLAGS_64BIT
                                                     ? " %RTsel:%016RGv"
                                                     : fCurBitFlags & DBGFSTACKFRAME_FLAGS_32BIT
                                                     ? " %RTsel:%08RGv"
                                                     : " %RTsel:%04RGv"
                                                     , pFrame->AddrPC.Sel, pFrame->AddrPC.off));
                        else
                        {
                            RTGCINTPTR offDisp = pFrame->AddrPC.FlatPtr - pFrame->pSymPC->Value; /** @todo this isn't 100% correct for segmented stuff. */
                            if (offDisp > 0)
                                aStack.append(Utf8StrFmt(" %s+%llx", pFrame->pSymPC->szName, (int64_t)offDisp));
                            else if (offDisp < 0)
                                aStack.append(Utf8StrFmt(" %s-%llx", pFrame->pSymPC->szName, -(int64_t)offDisp));
                            else
                                aStack.append(Utf8StrFmt(" %s", pFrame->pSymPC->szName));
                        }
                        if (pFrame->pLinePC)
                            aStack.append(Utf8StrFmt(" [%s @ 0i%d]", pFrame->pLinePC->szFilename, pFrame->pLinePC->uLineNo));
                        aStack.append(Utf8StrFmt("\n"));

                        fBitFlags = fCurBitFlags;
                    }
                }
                catch (std::bad_alloc &)
                {
                    hrc = E_OUTOFMEMORY;
                }

                DBGFR3StackWalkEnd(pFirstFrame);
            }
            else
                hrc = setErrorBoth(E_FAIL, vrc, tr("DBGFR3StackWalkBegin failed with %Rrc"), vrc);

            /*
             * Resume the VM if we suspended it.
             */
            if (fPaused)
            {
                alock.release();
                VMR3Resume(ptrVM.rawUVM(), VMRESUMEREASON_USER);
            }
        }
        else
            hrc = setErrorBoth(E_FAIL, vrc, tr("Suspending the VM failed with %Rrc\n"), vrc);
    }

    return hrc;
}

/**
 * Resets VM statistics.
 *
 * @returns COM status code.
 * @param   aPattern            The selection pattern. A bit similar to filename globbing.
 */
HRESULT MachineDebugger::resetStats(const com::Utf8Str &aPattern)
{
    Console::SafeVMPtrQuiet ptrVM(mParent);

    if (!ptrVM.isOk())
        return setError(VBOX_E_INVALID_VM_STATE, "Machine is not running");

    STAMR3Reset(ptrVM.rawUVM(), aPattern.c_str());

    return S_OK;
}

/**
 * Dumps VM statistics to the log.
 *
 * @returns COM status code.
 * @param   aPattern            The selection pattern. A bit similar to filename globbing.
 */
HRESULT MachineDebugger::dumpStats(const com::Utf8Str &aPattern)
{
    Console::SafeVMPtrQuiet ptrVM(mParent);

    if (!ptrVM.isOk())
        return setError(VBOX_E_INVALID_VM_STATE, "Machine is not running");

    STAMR3Dump(ptrVM.rawUVM(), aPattern.c_str());

    return S_OK;
}

/**
 * Get the VM statistics in an XML format.
 *
 * @returns COM status code.
 * @param   aPattern            The selection pattern. A bit similar to filename globbing.
 * @param   aWithDescriptions   Whether to include the descriptions.
 * @param   aStats              The XML document containing the statistics.
 */
HRESULT MachineDebugger::getStats(const com::Utf8Str &aPattern, BOOL aWithDescriptions, com::Utf8Str &aStats)
{
    Console::SafeVMPtrQuiet ptrVM(mParent);
    if (!ptrVM.isOk())
        return setError(VBOX_E_INVALID_VM_STATE, "Machine is not running");

    char *pszSnapshot;
    int vrc = STAMR3Snapshot(ptrVM.rawUVM(), aPattern.c_str(), &pszSnapshot, NULL,
                             !!aWithDescriptions);
    if (RT_FAILURE(vrc))
        return vrc == VERR_NO_MEMORY ? E_OUTOFMEMORY : E_FAIL;

    /** @todo this is horribly inefficient! And it's kinda difficult to tell whether it failed...
     * Must use UTF-8 or ASCII here and completely avoid these two extra copy operations.
     * Until that's done, this method is kind of useless for debugger statistics GUI because
     * of the amount statistics in a debug build. */
    aStats = Utf8Str(pszSnapshot);
    STAMR3SnapshotFree(ptrVM.rawUVM(), pszSnapshot);

    return S_OK;
}


/** Wrapper around TMR3GetCpuLoadPercents. */
HRESULT MachineDebugger::getCPULoad(ULONG aCpuId, ULONG *aPctExecuting, ULONG *aPctHalted, ULONG *aPctOther, LONG64 *aMsInterval)
{
    HRESULT hrc;
    Console::SafeVMPtrQuiet ptrVM(mParent);
    if (ptrVM.isOk())
    {
        uint8_t uPctExecuting = 0;
        uint8_t uPctHalted    = 0;
        uint8_t uPctOther     = 0;
        uint64_t msInterval   = 0;
        int vrc = TMR3GetCpuLoadPercents(ptrVM.rawUVM(), aCpuId >= UINT32_MAX / 2 ? VMCPUID_ALL : aCpuId,
                                         &msInterval, &uPctExecuting, &uPctHalted, &uPctOther);
        if (RT_SUCCESS(vrc))
        {
            *aPctExecuting = uPctExecuting;
            *aPctHalted    = uPctHalted;
            *aPctOther     = uPctOther;
            *aMsInterval   = msInterval;
            hrc = S_OK;
        }
        else
            hrc = setErrorVrc(vrc);
    }
    else
        hrc = setError(VBOX_E_INVALID_VM_STATE, "Machine is not running");
    return hrc;
}


// public methods only for internal purposes
/////////////////////////////////////////////////////////////////////////////

void MachineDebugger::i_flushQueuedSettings()
{
    mFlushMode = true;
    if (mSingleStepQueued != -1)
    {
        COMSETTER(SingleStep)(mSingleStepQueued);
        mSingleStepQueued = -1;
    }
    for (unsigned i = 0; i < EMEXECPOLICY_END; i++)
        if (maiQueuedEmExecPolicyParams[i] != UINT8_MAX)
        {
            i_setEmExecPolicyProperty((EMEXECPOLICY)i, RT_BOOL(maiQueuedEmExecPolicyParams[i]));
            maiQueuedEmExecPolicyParams[i] = UINT8_MAX;
        }
    if (mPatmEnabledQueued != -1)
    {
        COMSETTER(PATMEnabled)(mPatmEnabledQueued);
        mPatmEnabledQueued = -1;
    }
    if (mCsamEnabledQueued != -1)
    {
        COMSETTER(CSAMEnabled)(mCsamEnabledQueued);
        mCsamEnabledQueued = -1;
    }
    if (mLogEnabledQueued != -1)
    {
        COMSETTER(LogEnabled)(mLogEnabledQueued);
        mLogEnabledQueued = -1;
    }
    if (mVirtualTimeRateQueued != UINT32_MAX)
    {
        COMSETTER(VirtualTimeRate)(mVirtualTimeRateQueued);
        mVirtualTimeRateQueued = UINT32_MAX;
    }
    mFlushMode = false;
}

// private methods
/////////////////////////////////////////////////////////////////////////////

bool MachineDebugger::i_queueSettings() const
{
    if (!mFlushMode)
    {
        // check if the machine is running
        MachineState_T machineState;
        mParent->COMGETTER(State)(&machineState);
        switch (machineState)
        {
            // queue the request
            default:
                return true;

            case MachineState_Running:
            case MachineState_Paused:
            case MachineState_Stuck:
            case MachineState_LiveSnapshotting:
            case MachineState_Teleporting:
                break;
        }
    }
    return false;
}
/* vi: set tabstop=4 shiftwidth=4 expandtab: */
