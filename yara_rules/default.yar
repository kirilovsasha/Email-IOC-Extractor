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

/* --- pack v2 (2.17) --- */

rule remote_template
{
    meta:
        description = "OOXML remote / attachedTemplate External"
    strings:
        $a = "TargetMode=\"External\"" ascii nocase
        $b = "attachedTemplate" ascii nocase
        $c = "TargetMode='External'" ascii nocase
    condition:
        $a or ($b and $c) or ($b and $a)
}

rule html_polyglot
{
    meta:
        description = "HTML + PK (ZIP) polyglot"
    strings:
        $h = "<html" ascii nocase
        $d = "<!DOCTYPE html" ascii nocase
        $z = { 50 4B 03 04 }
    condition:
        ($h or $d) and $z
}

rule office_dde
{
    meta:
        description = "Excel DDE / formula injection"
    strings:
        $a = "DDEAUTO" ascii nocase
        $b = "cmd|" ascii nocase
        $c = "=CMD|" ascii nocase
        $d = "MSEXCEL|" ascii nocase
    condition:
        any of them
}

rule ole10native
{
    meta:
        description = "OLE Package Ole10Native stream"
    strings:
        $a = "Ole10Native" ascii
        $b = { 4F 6C 65 31 30 4E 61 74 69 76 65 }
        $c = { D0 CF 11 E0 A1 B1 1A E1 }
    condition:
        $c and ($a or $b)
}

rule pdf_openaction
{
    meta:
        description = "PDF OpenAction with URI"
    strings:
        $a = "/OpenAction" ascii
        $b = "/URI" ascii
    condition:
        $a and $b
}

rule pdf_launch_action
{
    meta:
        description = "PDF Launch / SubmitForm / GoToR"
    strings:
        $a = "/Launch" ascii
        $b = "/SubmitForm" ascii
        $c = "/GoToR" ascii
    condition:
        any of them
}

rule rtf_equation_objupdate
{
    meta:
        description = "RTF Equation Editor or objupdate"
    strings:
        $a = "\\objupdate" ascii nocase
        $b = "Equation.3" ascii nocase
    condition:
        any of them
}

rule vba_live_macro
{
    meta:
        description = "VBA autostart or download/exec"
    strings:
        $a = "AutoOpen" ascii nocase
        $b = "Document_Open" ascii nocase
        $c = "Workbook_Open" ascii nocase
        $d = "URLDownloadToFile" ascii nocase
        $e = "WScript.Shell" ascii nocase
    condition:
        any of them
}

rule clickfix_lure
{
    meta:
        description = "ClickFix: encoded powershell, mshta, or Win+R"
    strings:
        $ps = "powershell" ascii nocase
        $enc = "-enc" ascii nocase
        $mshta = "mshta" ascii nocase
        $win = "Win+R" ascii nocase
        $win2 = "Windows+R" ascii nocase
    condition:
        ($ps and $enc) or $mshta or $win or $win2
}

rule excel_xlm_macrosheet
{
    meta:
        description = "Excel 4.0 / XLM macrosheet"
    strings:
        $a = "xl/macrosheets" ascii nocase
        $b = "Excel 4.0" ascii
    condition:
        any of them
}

rule fake_auth_results_body
{
    meta:
        description = "Authentication-Results pasted into a body or attachment"
    strings:
        $a = "Authentication-Results:" ascii nocase
        $b = "spf=pass" ascii nocase
    condition:
        $a and $b
}

rule dangerous_uri_scheme
{
    meta:
        description = "Mail lure URI schemes"
    strings:
        $a = "search-ms:" ascii nocase
        $b = "ms-msdt:" ascii nocase
        $c = "ms-officecmd:" ascii nocase
    condition:
        any of them
}
