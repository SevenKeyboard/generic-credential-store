#Requires AutoHotkey v2.0.0+
;==============================================================
; GenericCredentialStore — Stores, reads, and deletes generic credentials via Windows Credential Manager (CredWrite/CredRead/CredDelete)
;
; GitHub: https://github.com/SevenKeyboard/generic-credential-store
; Author: SevenKeyboard Ltd. (2026)
; License: MIT License
;
; Documentation / References:
;   CredWriteW function (wincred.h)
;     https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credwritew
;   CredReadW function (wincred.h)
;     https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credreadw
;   CredDeleteW function (wincred.h)
;     https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-creddeletew
;   Store passwords in scripts securely through Windows Credential Manager API
;     https://www.autohotkey.com/boards/viewtopic.php?t=116285
;==============================================================

/*
Example Usage:
    F1::msgBox(GenericCredentialStore.set("Example.BECF5728", "Password", A_UserName))
    F2::  {
        found := GenericCredentialStore.get("Example.BECF5728", &credentialText, &userName)
        if (found)
            msgBox("credentialText: " credentialText "`nuserName: " userName)
        else
            msgBox("Not found.")
    }
    F3::msgBox(GenericCredentialStore.delete("Example.BECF5728"))
*/

/*
    Win + R
    control /name Microsoft.CredentialManager
*/

class VersionManager_GenericCredentialStore
{
    static _ := this._init()
    static _init()    {
        global
        GENERICCREDENTIALSTORE_VERSION := "1.0.0"
    }
}
class GenericCredentialStore
{
    static set(targetName, credentialText, userName := "", persist := "Local Machine")    {
        static CRED_TYPE_GENERIC                := 1
            ,CRED_MAX_DOMAIN_TARGET_NAME_LENGTH := (256 + 1 + 80)
            ,CRED_MAX_CREDENTIAL_BLOB_SIZE      := (5 * 512)
            ,CRED_PERSIST_SESSION               := 1
            ,CRED_PERSIST_LOCAL_MACHINE         := 2
            ,CRED_PERSIST_ENTERPRISE            := 3
            ,CRED_MAX_USERNAME_LENGTH           := (256 + 1 + 256)
        if (targetName == "" || credentialText == "")
            return false
        if (CRED_MAX_DOMAIN_TARGET_NAME_LENGTH < strLen(targetName))
            return false
        credential := buffer(24 + A_PtrSize * 7, 0)
        credentialBlobSize := strPut(credentialText, "UTF-16") - 2
        if (CRED_MAX_CREDENTIAL_BLOB_SIZE < credentialBlobSize)
            return false
        if (CRED_MAX_USERNAME_LENGTH  < strLen(userName))
            return false
        bufTargetName := buffer(strPut(targetName, "UTF-16"))
        strPut(targetName, bufTargetName, "UTF-16")
        bufCredentialBlob := buffer(strPut(credentialText, "UTF-16"))
        strPut(credentialText, bufCredentialBlob, "UTF-16")
        if (userName !== "")    {
            bufUserName := buffer(strPut(userName, "UTF-16"))
            strPut(userName, bufUserName, "UTF-16")
        }
        switch persist, false
        {
            case "Session":         persist := CRED_PERSIST_SESSION
            case "Local Machine":   persist := CRED_PERSIST_LOCAL_MACHINE
            case "Enterprise":      persist := CRED_PERSIST_ENTERPRISE
            default:                persist := CRED_PERSIST_LOCAL_MACHINE
        }
        numPut("UInt"   ,CRED_TYPE_GENERIC      ,credential, 4)
        numPut("Ptr"    ,bufTargetName.Ptr      ,credential, 8)
        numPut("UInt"   ,credentialBlobSize     ,credential, 16 + A_PtrSize * 2)
        numPut("Ptr"    ,bufCredentialBlob.Ptr  ,credential, 16 + A_PtrSize * 3)
        numPut("UInt"   ,persist                ,credential, 16 + A_PtrSize * 4)
        numPut("Ptr"    ,isSet(bufUserName) ? bufUserName.Ptr : 0, credential, 24 + A_PtrSize * 6)
        return dllCall("Advapi32.dll\CredWriteW"
            ,"Ptr",credential
            ,"UInt",0
            ,"Int")
    }
    static get(targetName, &credentialText?, &userName?)    {
        static CRED_TYPE_GENERIC        := 1
            ,CRED_MAX_USERNAME_LENGTH   := (256 + 1 + 256)
        credentialText:= userName:= ""
        if (found := dllCall("Advapi32.dll\CredReadW", "WStr",targetName
            ,"UInt",CRED_TYPE_GENERIC, "UInt",0, "Ptr*",&credential := 0
            ,"Int"))    {
            userName            := strGet(numGet(credential + 24 + A_PtrSize * 6, "Ptr"), CRED_MAX_USERNAME_LENGTH, "UTF-16")
            credentialBlobSize  :=        numGet(credential + 16 + A_PtrSize * 2, "UInt")
            credentialText      := strGet(numGet(credential + 16 + A_PtrSize * 3, "Ptr"), credentialBlobSize / 2, "UTF-16")
        }
        if (credential)
            dllCall("Advapi32.dll\CredFree", "Ptr",credential)    
        return found
    }
    static delete(targetName)    {
        static CRED_TYPE_GENERIC := 1
        return dllCall("Advapi32.dll\CredDeleteW"
            ,"WStr",targetName
            ,"UInt",CRED_TYPE_GENERIC
            ,"UInt",0
            ,"Int")
    }
}