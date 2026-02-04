#Requires AutoHotkey v1.1.37+ Unicode
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
;     https://www.autohotkey.com/boards/viewtopic.php?t=112391
;==============================================================

/*
Example Usage:
    F1::msgBox % GenericCredentialStore.set("Example.BECF5728", "Password", A_UserName)
    F2::
        found := GenericCredentialStore.get("Example.BECF5728", credentialText, userName)
        if (found)
            msgBox % "credentialText: " credentialText "`nuserName: " userName
        else
            msgBox % "Not found."
        return
    F3::msgBox % GenericCredentialStore.delete("Example.BECF5728")
*/

/*
    Win + R
    control /name Microsoft.CredentialManager
*/

class VersionManager_GenericCredentialStore
{
    static _ := VersionManager_GenericCredentialStore._init()
    _init()    {
        global
        GENERICCREDENTIALSTORE_VERSION := "1.0.0"
    }
}
class GenericCredentialStore
{
    set(targetName, credentialText, userName := "", persist := "Local Machine")    {
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
        varSetCapacity(credential, 24 + A_PtrSize * 7, 0)
        credentialBlobSize := (strPut(credentialText, "UTF-16") - 1) * 2
        if (CRED_MAX_CREDENTIAL_BLOB_SIZE < credentialBlobSize)
            return false
        if (CRED_MAX_USERNAME_LENGTH  < strLen(userName))
            return false
        varSetCapacity(bufTargetName, (strPut(targetName, "UTF-16")) * 2)
        strPut(targetName, &bufTargetName, "UTF-16")
        varSetCapacity(bufCredentialBlob, (strPut(credentialText, "UTF-16")) * 2)
        strPut(credentialText, &bufCredentialBlob, "UTF-16")
        if (userName !== "")    {
            varSetCapacity(bufUserName, (strPut(userName, "UTF-16")) * 2)
            strPut(userName, &bufUserName, "UTF-16")
        }
        prevStringCaseSense := A_StringCaseSense
        stringCaseSense Off
        switch (persist)
        {
            case "Session":         persist := CRED_PERSIST_SESSION
            case "Local Machine":   persist := CRED_PERSIST_LOCAL_MACHINE
            case "Enterprise":      persist := CRED_PERSIST_ENTERPRISE
            default:                persist := CRED_PERSIST_LOCAL_MACHINE
        }
        stringCaseSense % prevStringCaseSense
        numPut(CRED_TYPE_GENERIC        ,credential, 4, "UInt")
        numPut(&bufTargetName           ,credential, 8, "Ptr")
        numPut(credentialBlobSize       ,credential, 16 + A_PtrSize * 2, "UInt")
        numPut(&bufCredentialBlob       ,credential, 16 + A_PtrSize * 3, "Ptr")
        numPut(persist                  ,credential, 16 + A_PtrSize * 4, "UInt")
        numPut(isSet(bufUserName) ? &bufUserName : 0, credential, 24 + A_PtrSize * 6, "Ptr")
        return dllCall("Advapi32.dll\CredWriteW"
            ,"Ptr",&credential
            ,"UInt",0
            ,"Int")
    }
    get(targetName, byRef credentialText := "", byRef userName := "")    {
        static CRED_TYPE_GENERIC        := 1
            ,CRED_MAX_USERNAME_LENGTH   := (256 + 1 + 256)
        credentialText:= userName:= ""
        if (found := dllCall("Advapi32.dll\CredReadW", "WStr",targetName
            ,"UInt",CRED_TYPE_GENERIC, "UInt",0, "Ptr*",credential := 0
            ,"Int"))    {
            if (p := numGet(credential + 24 + A_PtrSize * 6, "Ptr"))
                userName        := strGet(p + 0, "UTF-16")
            credentialBlobSize  := numGet(credential + 16 + A_PtrSize * 2, "UInt")
            credentialText      := strGet(numGet(credential + 16 + A_PtrSize * 3, "Ptr"), credentialBlobSize / 2, "UTF-16")
        }
        if (credential)
            dllCall("Advapi32.dll\CredFree", "Ptr",credential)    
        return found
    }
    delete(targetName)    {
        static CRED_TYPE_GENERIC := 1
        return dllCall("Advapi32.dll\CredDeleteW"
            ,"WStr",targetName
            ,"UInt",CRED_TYPE_GENERIC
            ,"UInt",0
            ,"Int")
    }
}