#pragma once

f_NtCreateFile                o_NtCreateFile = nullptr;
f_NtOpenProcess               o_NtOpenProcess = nullptr;
f_NtQuerySystemInformation    o_NtQuerySystemInformation = nullptr;
f_NtQueryInformationProcess   o_NtQueryInformationProcess = nullptr;
f_NtLoadDriver                o_NtLoadDriver = nullptr;
f_NtGdiBitBlt                 o_NtGdiBitBlt = nullptr;
f_NtUserFindWindowEx          o_NtUserFindWindowEx = nullptr;
f_NtUserBuildHwndList         o_NtUserBuildHwndList = nullptr;
f_NtUserGetForegroundWindow   o_NtUserGetForegroundWindow = nullptr;
f_NtUserGetThreadState        o_NtUserGetThreadState = nullptr;
f_NtUserSetWindowsHookEx      o_NtUserSetWindowsHookEx = nullptr;
f_NtUserSetWinEventHook       o_NtUserSetWinEventHook = nullptr;
f_NtUserGetClassName          o_NtUserGetClassName = nullptr;
f_NtUserInternalGetWindowText o_NtUserInternalGetWindowText = nullptr;
f_NtUserInternalGetWindowIcon o_NtUserInternalGetWindowIcon = nullptr;

//ZwRaiseException 