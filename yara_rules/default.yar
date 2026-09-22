/*
  Reliquary offline default rules — strings only, no network.
  Keep simple / safe for optional yara-python scanning.
*/

rule html_smuggling
{
    meta:
        description = "HTML smuggling markers"
    strings:
        $a = "fromCharCode" ascii nocase
        $b = "atob(" ascii nocase
        $c = "new Blob" ascii nocase
        $d = "msSaveOrOpenBlob" ascii nocase
    condition:
        2 of them
}

rule lnk_cmd
{
    meta:
        description = "LNK / shell with cmd or powershell"
    strings:
        $a = "cmd.exe" ascii nocase
        $b = "powershell" ascii nocase
        $c = "pwsh.exe" ascii nocase
    condition:
        any of them
}

rule js_wscript
{
    meta:
        description = "WScript / ActiveX in script"
    strings:
        $a = "WScript.Shell" ascii nocase
        $b = "ActiveXObject" ascii nocase
        $c = "Scripting.FileSystemObject" ascii nocase
    condition:
        any of them
}

rule vbs_createobject
{
    meta:
        description = "VBS CreateObject"
    strings:
        $a = "CreateObject(" ascii nocase
        $b = "GetObject(" ascii nocase
    condition:
        any of them
}

rule onenote_embedded
{
    meta:
        description = "OneNote / embedded package markers"
    strings:
        $a = "OneNote.Package" ascii nocase
        $b = "ONEDOC" ascii
        $c = "embeddedFile" ascii nocase
    condition:
        any of them
}

rule pdf_js_action
{
    meta:
        description = "PDF JavaScript / OpenAction"
    strings:
        $a = "/JavaScript" ascii
        $b = "/JS " ascii
        $c = "/OpenAction" ascii
        $d = "/Launch" ascii
    condition:
        any of them
}

rule svg_onload
{
    meta:
        description = "SVG onload / script"
    strings:
        $a = "onload=" ascii nocase
        $b = "<script" ascii nocase
        $c = "javascript:" ascii nocase
    condition:
        2 of them
}

rule hta_script
{
    meta:
        description = "HTA script host"
    strings:
        $a = "HTA:APPLICATION" ascii nocase
        $b = "<script" ascii nocase
        $c = "mshta" ascii nocase
    condition:
        2 of them
}

rule excel_dde
{
    meta:
        description = "Excel DDE / cmd"
    strings:
        $a = "DDEAUTO" ascii nocase
        $b = "cmd|" ascii nocase
        $c = "DDE " ascii
    condition:
        any of them
}

rule ole_package
{
    meta:
        description = "OLE Package / Ole10Native"
    strings:
        $a = "Ole10Native" ascii
        $b = "Package" ascii
        $c = "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    condition:
        $c and ($a or $b)
}

rule qr_data_url
{
    meta:
        description = "QR / data URL lure"
    strings:
        $a = "data:image" ascii nocase
        $b = "QR code" ascii nocase
        $c = "scan the QR" ascii nocase
        $d = "сканируйте QR" ascii nocase wide
    condition:
        any of them
}

rule encoded_powershell
{
    meta:
        description = "Encoded / obfuscated PowerShell"
    strings:
        $a = "-enc " ascii nocase
        $b = "-EncodedCommand" ascii nocase
        $c = "FromBase64String" ascii nocase
        $d = "IO.MemoryStream" ascii nocase
    condition:
        2 of them
}

rule html_polyglot_zip
{
    meta:
        description = "HTML near ZIP local file header"
    strings:
        $h = "<html" ascii nocase
        $z = { 50 4B 03 04 }
    condition:
        $h and $z
}

rule archive_password_lure
{
    meta:
        description = "Password-protected archive lure text"
    strings:
        $a = "password is" ascii nocase
        $b = "пароль архива" ascii nocase wide
        $c = "password-protected" ascii nocase
    condition:
        any of them
}
