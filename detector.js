// detector.js — pure scoring module (no side effects)
export const CRITICAL_PATTERNS = [
  { re: /msiexec(\.exe)?\s+\/i\s+https?:\/\//i, weight: 90, label: "msiexec remote MSI install", family: "msiexec" },

  // PowerShell execution + download patterns (use \\biex\\b to avoid msiexec substring)
  { re: /powershell[\s\S]*?\biex\b/i, weight: 85, label: "PowerShell code execution (iex)", family: "powershell" },
  { re: /powershell[\s\S]*?invoke-expression/i, weight: 85, label: "PowerShell code execution (Invoke-Expression)", family: "powershell" },
  { re: /powershell[\s\S]{0,500}?(irm|invoke-restmethod)[\s\S]{0,500}?\|[\s\S]{0,200}?\biex\b/i, weight: 90, label: "PowerShell download-and-execute pipe", family: "powershell" },
  { re: /powershell[\s\S]*?downloadfile/i, weight: 90, label: "PowerShell file download (DownloadFile)", family: "powershell" },
  { re: /powershell[\s\S]*?net\.webclient/i, weight: 85, label: "PowerShell WebClient downloader", family: "powershell" },
  { re: /powershell[\s\S]{0,500}?invoke-webrequest[\s\S]{0,500}?\|[\s\S]{0,200}?\biex\b/i, weight: 90, label: "PowerShell iwr pipe to exec", family: "powershell" },
  { re: /powershell[\s\S]*?(-ep\s+bypass|-executionpolicy\s+bypass)/i, weight: 80, label: "PowerShell execution policy bypass", family: "powershell" },
  { re: /powershell[\s\S]*?(-enc\b|-encodedcommand)\b/i, weight: 95, label: "Encoded PowerShell command", family: "powershell" },
  { re: /powershell[\s\S]*?\s-e\s+[A-Za-z0-9+\/=]{20,}/i, weight: 95, label: "PowerShell -e encoded command (bare flag)", family: "powershell" },
  { re: /powershell[\s\S]*?-w(indowstyle)?\s+(h|hidden|mi|min)\b/i, weight: 80, label: "Hidden PowerShell window", family: "powershell" },
  { re: /powershell[\s\S]*?start-process[\s\S]*?\.exe/i, weight: 85, label: "PowerShell launching executable", family: "powershell" },

  // PowerShell Invoke-WebRequest/iwr + Start-Process (download-then-execute without iex pipe)
  // Catches: powershell -c "Invoke-WebRequest -Uri '...' -OutFile '%temp%\x.bat'; Start-Process '%temp%\x.bat'"
  { re: /powershell[\s\S]*?invoke-webrequest[\s\S]*?-outfile[\s\S]*?start-process/i, weight: 90, label: "PowerShell IWR download + Start-Process exec", family: "powershell" },
  { re: /powershell[\s\S]*?\biwr\b[\s\S]*?-outfile[\s\S]*?start-process/i, weight: 90, label: "PowerShell iwr download + Start-Process exec", family: "powershell" },
  { re: /powershell[\s\S]*?start-process[\s\S]*?\.(bat|msi|cmd|vbs)\b/i, weight: 85, label: "PowerShell Start-Process script/installer", family: "powershell" },
  { re: /invoke-webrequest[\s\S]*?-outfile[\s\S]*?\.(bat|exe|msi|ps1|cmd|vbs)\b/i, weight: 85, label: "IWR downloading executable/script to disk", family: "powershell" },

  // cmd /c start mshta (indirect mshta launch via start command)
  // Existing rule requires mshta directly followed by URL; this catches the start wrapper
  { re: /cmd[\s\S]*?start[\s\S]{0,30}?mshta[\s\S]*?https?:\/\//i, weight: 90, label: "cmd start mshta remote HTA", family: "mshta" },
  { re: /start[\s\S]{0,20}?mshta[\s\S]*?https?:\/\//i, weight: 90, label: "start mshta remote execution", family: "mshta" },
  { re: /cmd[\s\S]*?start[\s\S]{0,30}?mshta[\s\S]*?\"\s*https?:\/\//i, weight: 90, label: "cmd start mshta quoted URL", family: "mshta" },

  // finger.exe LOLBin — LOLBAS technique: finger.exe used as data exfil/C2 channel
  { re: /finger\.exe[\s\S]*?\d{1,3}(\.\d{1,3}){3}/i, weight: 90, label: "finger.exe LOLBin with IP (C2 channel)", family: "lolbin" },
  { re: /copy[\s\S]*?finger\.exe/i, weight: 85, label: "finger.exe copy for LOLBin abuse", family: "lolbin" },
  { re: /finger[\s\S]*?@[\s\S]*?\d{1,3}(\.\d{1,3}){3}[\s\S]*?\|\s*cmd/i, weight: 95, label: "finger.exe piped to cmd (C2 exec)", family: "lolbin" },

  // curl downloading .bat/.exe/.cmd then executing (without VBS)
  { re: /curl[\s\S]*?-o[\s\S]*?\.(bat|exe|cmd)\b[\s\S]*?start/i, weight: 90, label: "curl download bat/exe then start", family: "curl-exec" },
  { re: /curl[\s\S]*?-o[\s\S]*?\.(bat|exe|cmd)\b[\s\S]*?&&/i, weight: 85, label: "curl download bat/exe then chain exec", family: "curl-exec" },
  { re: /curl[\s\S]*?-o\s*[\"']?(%appdata%|%temp%|%userprofile%)/i, weight: 85, label: "curl dropping file to user folder", family: "curl-exec" },

  // wscript/cscript via UNC WebDAV path (remote script execution without download)
  { re: /wscript[\s\S]*?\\\\[\s\S]*?\d{1,3}(\.\d{1,3}){3}/i, weight: 90, label: "wscript executing via UNC path with IP", family: "vbs" },
  { re: /cscript[\s\S]*?\\\\[\s\S]*?\d{1,3}(\.\d{1,3}){3}/i, weight: 90, label: "cscript executing via UNC path with IP", family: "vbs" },
  { re: /wscript[\s\S]*?\\\\[\s\S]*?@\d+\\/i, weight: 90, label: "wscript UNC WebDAV path (port-based)", family: "vbs" },

  // PowerShell Get-Variable (GV) obfuscation — reconstructs cmdlet names from variable metadata
  { re: /\(\s*GV\s+['"][^'"]*['"]\s*\)\.Name\s*\[/i, weight: 85, label: "PowerShell GV obfuscation (variable name indexing)", family: "obfuscation" },
  { re: /\.\s*\(\s*\(\s*GV\s/i, weight: 80, label: "PowerShell dot-source via GV resolution", family: "obfuscation" },

  // PowerShell -wInDO/-wINDOWSTYLE obfuscation (case-mixed window style flags)
  { re: /powershell[\s\S]*?-w(i|in|ind|indo|indow|indows)\s+(mi|min|mini|minim)\b/i, weight: 80, label: "PowerShell obfuscated -WindowStyle Min", family: "powershell" },

  // macOS/Linux hex-encoded payloads (echo hex | xxd -r -p | bash)
  { re: /echo\s+['"][0-9a-f]{40,}['"]\s*\|/i, weight: 85, label: "Hex-encoded payload piped to decoder", family: "linux" },

  // cmd /c start /min cmd — double-wrapped cmd for hidden execution
  { re: /cmd[\s\S]*?start[\s\S]{0,20}?\/min[\s\S]*?cmd/i, weight: 80, label: "cmd start /min cmd (double-wrapped hidden)", family: "cmd" },

  // curl → VBScript + pipe-to-exec
  { re: /curl[\s\S]*?-o\s*%temp%[\s\S]*?\.vbs\b/i, weight: 95, label: "curl dropping VBS to temp", family: "curl-vbs" },
  { re: /curl[\s\S]*?\|\s*(\biex\b|bash)\b/i, weight: 95, label: "curl piped to execution", family: "curl-pipe" },

  // VBS download-and-exec
  { re: /createobject[\s\S]*?winhttprequest/i, weight: 95, label: "VBS WinHttpRequest downloader", family: "vbs" },
  { re: /createobject[\s\S]*?execute\s+\w+\.responsetext/i, weight: 95, label: "VBS download and execute (ResponseText)", family: "vbs" },
  { re: /createobject[\s\S]*?msxml2\.xmlhttp/i, weight: 90, label: "VBS MSXML2.XMLHTTP downloader", family: "vbs" },
  { re: /createobject[\s\S]*?xmlhttp[\s\S]*?execute[\s\S]*?response/i, weight: 95, label: "VBS XMLHTTP download and execute", family: "vbs" },

  // mshta
  { re: /mshta\s+https?:\/\//i, weight: 90, label: "mshta remote HTA execution", family: "mshta" },

  // Base64 / decode-to-exec
  { re: /frombase64string/i, weight: 85, label: "Base64 decode present", family: "obfuscation" },
  { re: /\[convert\]::frombase64string/i, weight: 90, label: "Base64 decode in PowerShell", family: "obfuscation" },
  { re: /base64\s+-d[\s\S]*?\|\s*bash/i, weight: 95, label: "Base64 decode piped to bash", family: "linux" },

  // LOLBins
  { re: /syncappvpublishingserver\.vbs/i, weight: 95, label: "SyncAppvPublishingServer LOLBin", family: "lolbin" },
  { re: /ssh\s+-o\s+proxycommand[\s\S]*?msiexec/i, weight: 95, label: "SSH ProxyCommand abuse", family: "lolbin" },

  // bitsadmin LOLBin — Windows BITS service abused for file download + execution
  { re: /bitsadmin[\s\S]*?\/transfer[\s\S]*?https?:\/\//i, weight: 90, label: "bitsadmin /transfer remote download", family: "bitsadmin" },
  { re: /bitsadmin[\s\S]*?\/download[\s\S]*?https?:\/\//i, weight: 90, label: "bitsadmin /download remote file", family: "bitsadmin" },
  { re: /bitsadmin[\s\S]*?\/transfer[\s\S]*?\.(bat|exe|ps1|vbs|msi|cmd|dll|scr)\b/i, weight: 95, label: "bitsadmin downloading executable/script", family: "bitsadmin" },
  { re: /bitsadmin[\s\S]*?&[\s\S]*?start\b/i, weight: 90, label: "bitsadmin download then start execution", family: "bitsadmin" },

  // certutil LOLBin — abused for Base64 decode and file download
  { re: /certutil[\s\S]*?-urlcache[\s\S]*?https?:\/\//i, weight: 90, label: "certutil URL cache download", family: "certutil" },
  { re: /certutil[\s\S]*?-decode/i, weight: 85, label: "certutil Base64 decode", family: "certutil" },
  { re: /certutil[\s\S]*?-urlcache[\s\S]*?\.(bat|exe|ps1|vbs|msi|cmd|dll)\b/i, weight: 95, label: "certutil downloading executable/script", family: "certutil" },

  // regsvr32 LOLBin — proxy execution via scrobj.dll or remote SCT files
  { re: /regsvr32[\s\S]*?\/s[\s\S]*?\/i[\s\S]*?scrobj/i, weight: 95, label: "regsvr32 scrobj proxy execution", family: "regsvr32" },
  { re: /regsvr32[\s\S]*?https?:\/\//i, weight: 90, label: "regsvr32 remote script registration", family: "regsvr32" },

  // Alias obfuscation
  { re: /\(gal\s+\*?i\*x\)/i, weight: 90, label: "Obfuscated Invoke-Expression (gal)", family: "obfuscation" },
  { re: /\(gcm\s+\*?\w+\*\)/i, weight: 80, label: "Obfuscated cmdlet (gcm wildcard)", family: "obfuscation" },

  // Bare PS aliases (no 'powershell' prefix)
  { re: /^\s*iex\s+\(/im, weight: 85, label: "Bare iex execution", family: "powershell" },
  { re: /^\s*iwr\s+\S+[\s\S]*?\|\s*iex/im, weight: 90, label: "Bare iwr piped to iex", family: "powershell" },

  // Bare .NET download methods (no powershell prefix — direct script blocks)
  { re: /Net\.WebClient[\s\S]*?DownloadString/i, weight: 85, label: "Bare Net.WebClient DownloadString", family: "powershell" },
  { re: /Net\.WebClient[\s\S]*?DownloadFile/i, weight: 85, label: "Bare Net.WebClient DownloadFile", family: "powershell" },

  // .Replace chain obfuscation (rebuild strings by replacing junk tokens)
  { re: /\.Replace\('[^']{1,8}',\s*''\)[\s\S]*?\.Replace\('[^']{1,8}',\s*''\)/i, weight: 80, label: ".Replace chain string obfuscation", family: "obfuscation" },

  // WMI
  { re: /wmiclass[\s\S]*?win32_process[\s\S]*?create/i, weight: 90, label: "WMI process creation", family: "wmi" },

  // wscript
  { re: /wscript\.exe[\s\S]*?\.vbs\b/i, weight: 80, label: "wscript executing VBS", family: "vbs" },

  // Obfuscation techniques
  { re: /'[^']{1,10}'\s*\+\s*'[^']{1,10}'[\s\S]*?https?:\/\//i, weight: 80, label: "String concat URL obfuscation", family: "obfuscation" },
  { re: /[\u0080-\uffff][\s\S]*?(\.com|\.net|\.org|\.ru)\b/i, weight: 85, label: "Non-ASCII/homoglyph domain indicator", family: "obfuscation" },
  { re: /[\u200b\u200c\u200d\ufeff]/, weight: 30, label: "Zero-width space padding", family: "obfuscation" },
  { re: /\$\w+\s*=\s*'[0-9a-f]{20,}'/i, weight: 85, label: "Hex-encoded URL string", family: "obfuscation" },
  { re: /\[-1\.\.-?\d+\]/, weight: 80, label: "String reversal slicing", family: "obfuscation" },
  { re: /conhost\.exe\s+--headless/i, weight: 85, label: "conhost --headless LOLBin", family: "lolbin" },
  { re: /conhost(\.\w+)?\s+(--headless\s+)?cmd/i, weight: 85, label: "conhost launching cmd", family: "lolbin" },

  // Linux: /bin/bash with curl + base64 subshell (7 missed payloads)
  { re: /\/bin\/bash[\s\S]*?curl[\s\S]*?base64/i, weight: 95, label: "bash curl base64 subshell (Linux)", family: "linux" },
  { re: /\/bin\/bash[\s\S]*?curl[\s\S]*?\$\(echo\s/i, weight: 90, label: "bash curl echo subshell (Linux)", family: "linux" },

  // PowerShell wget obfuscation: . 'wget' (3 missed payloads)
  { re: /powershell[\s\S]*?wget/i, weight: 80, label: "PowerShell wget download", family: "powershell" },

  // .NET decode methods used as obfuscation (3 missed payloads)
  { re: /\[Uri\]::UnescapeDataString/i, weight: 85, label: "URI unescape decode obfuscation", family: "obfuscation" },
  { re: /SoapHexBinary/i, weight: 90, label: "SoapHexBinary decode obfuscation", family: "obfuscation" },
  { re: /Text\.Encoding[\s\S]*?GetString/i, weight: 80, label: "Text.Encoding decode", family: "obfuscation" },

  // PowerShell Expand-Archive zip dropper (1 missed payload)
  { re: /Expand-Archive[\s\S]*?-DestinationPath/i, weight: 80, label: "PowerShell Expand-Archive zip dropper", family: "powershell" },

  // PowerShell /e flag (encoded, different from -enc) used by conhost chains
  { re: /powershell\s+\/e\s+[A-Za-z0-9+\/=]{20,}/i, weight: 90, label: "PowerShell /e encoded command", family: "powershell" },

  // cmd /c start /min powershell — hidden launch via start
  { re: /cmd[\s\S]*?start\s+\/min[\s\S]*?powershell/i, weight: 85, label: "cmd start /min powershell (hidden)", family: "powershell" },

  // PowerShell iwr (Invoke-WebRequest alias) piped to iex — with powershell prefix
  // Catches: powershell -command "iwr http://... | iex"
  { re: /powershell[\s\S]{0,500}?\biwr\b[\s\S]{0,500}?\|\s*\biex\b/i, weight: 90, label: "PowerShell iwr piped to iex (alias form)", family: "powershell" },

  // PowerShell -command with download-and-execute inside quoted string
  { re: /powershell[\s\S]*?-command[\s\S]*?(iwr|irm|curl|wget)[\s\S]*?\|\s*\biex\b/i, weight: 90, label: "PowerShell -command download pipe exec", family: "powershell" },

  // DNS-based ClickFix: nslookup abuse for payload staging (Feb 2026 — ModeloRAT)
  { re: /nslookup[\s\S]*?\|[\s\S]*?findstr/i, weight: 90, label: "nslookup piped to findstr (DNS payload staging)", family: "nslookup" },
  { re: /nslookup[\s\S]*?\|[\s\S]*?for\s+\/f/i, weight: 90, label: "nslookup piped to for /f (DNS payload parsing)", family: "nslookup" },
  { re: /cmd\s*\/c[\s\S]*?nslookup/i, weight: 85, label: "cmd /c wrapping nslookup", family: "nslookup" },

  // Caret obfuscation (cmd trick to evade string matching: c^m^d, n^s^l^o^o^k^u^p, p^o^w^e^r^s^h^e^l^l)
  { re: /n\^s\^l\^?o\^?o\^?k\^?u\^?p/i, weight: 90, label: "Caret-obfuscated nslookup", family: "obfuscation" },
  { re: /p\^o\^w\^e\^r\^s\^h\^e\^l\^l/i, weight: 90, label: "Caret-obfuscated powershell", family: "obfuscation" },
  { re: /c\^m\^d/i, weight: 80, label: "Caret-obfuscated cmd", family: "obfuscation" },
  { re: /m\^s\^h\^t\^a/i, weight: 85, label: "Caret-obfuscated mshta", family: "obfuscation" },
  { re: /f\^i\^n\^d\^s\^t\^r/i, weight: 75, label: "Caret-obfuscated findstr", family: "obfuscation" },

  // cmd.exe indirection: %COMSPEC%, set/call variable assembly (HIGH-3b)
  { re: /%COMSPEC%/i, weight: 80, label: "%COMSPEC% indirect command execution", family: "cmd" },
  { re: /\bset\s+\w+=\S+[\s\S]*?\bcall\s+%/i, weight: 85, label: "set/call variable assembly (cmd obfuscation)", family: "obfuscation" },
  { re: /\bset\s+\w+=\S+[\s\S]*?\bset\s+\w+=\S+[\s\S]*?%\w+%%\w+%/i, weight: 85, label: "Multi-set variable concatenation", family: "obfuscation" }
];

export const SUPPORTING_PATTERNS = [
  { re: /%temp%/i, weight: 20, label: "temp folder reference" },
  { re: /\\downloads\\/i, weight: 15, label: "downloads folder drop" },
  { re: /\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b/, weight: 25, label: "bare IP address" },
  { re: /\/qn\b/i, weight: 30, label: "silent install flag (/qn)" },
  { re: /-nop\b/i, weight: 20, label: "no profile flag (-nop)" },
  { re: /start-sleep/i, weight: 20, label: "sleep delay (evasion)" },
  { re: /remove-item[\s\S]*?-force/i, weight: 25, label: "self-cleanup (Remove-Item -Force)" },
  { re: />\s*nul\b/i, weight: 15, label: "output suppression (>nul)" },
  { re: /\bcmd\s*\/c\b/i, weight: 15, label: "cmd /c wrapper" },
  { re: /\.vbs\b/i, weight: 25, label: "VBScript file reference" },
  { re: /\.ps1\b/i, weight: 25, label: "PowerShell script reference" },
  { re: /-outfile\b/i, weight: 20, label: "file write flag (-OutFile)" },
  { re: /\bstart\s+\/b\b/i, weight: 20, label: "background execution (start /b)" },
  { re: /\.exe\b/i, weight: 15, label: ".exe referenced" },
  { re: /\bnslookup\b/i, weight: 20, label: "nslookup command present" },
  { re: /\bfindstr\b/i, weight: 15, label: "findstr command present" },
  { re: /for\s+\/f\s+"tokens/i, weight: 20, label: "for /f tokens parsing" },
  { re: /&&\s*exit/i, weight: 15, label: "&& exit (run and close)" },
  { re: /nslookup\s+\S+\s+\d{1,3}(\.\d{1,3}){3}/i, weight: 25, label: "nslookup with explicit DNS server IP" },
  { re: /\biwr\b/i, weight: 20, label: "iwr (Invoke-WebRequest alias) present" },
  { re: /powershell[\s\S]*?-command/i, weight: 15, label: "powershell -command flag" },
  { re: /update\.\w+\.\w+/i, weight: 15, label: "update subdomain URL pattern" },
  { re: /\.bat\b/i, weight: 20, label: ".bat batch file reference" },
  { re: /\bbitsadmin\b/i, weight: 25, label: "bitsadmin command present" },
  { re: /\bcertutil\b/i, weight: 25, label: "certutil command present" },
  { re: /\bregsvr32\b/i, weight: 25, label: "regsvr32 command present" },
  { re: /\/priority\s+(foreground|high|normal)/i, weight: 20, label: "bitsadmin priority flag" },
  { re: /start\s+\"\"[\s\S]*?\.(bat|exe|cmd)\b/i, weight: 25, label: "start \"\" executing file" },
  { re: /\\temp\\/i, weight: 20, label: "Temp folder path reference" },
  { re: /%appdata%/i, weight: 20, label: "%APPDATA% folder reference" },
  { re: /start-process/i, weight: 20, label: "Start-Process command" },
  { re: /-usebasicparsing/i, weight: 15, label: "-UseBasicParsing flag" },
  { re: /\bfinger(\.exe)?\b/i, weight: 20, label: "finger.exe present" },
  { re: /\\\\[^\\]+@\d+\\/i, weight: 25, label: "UNC WebDAV path with port" },
  { re: /\.msi\b/i, weight: 20, label: ".msi installer reference" }
];

export function scoreClipboard(inputText) {
  const text = (inputText || "").toString();
  const maxLen = 8000; // mitigate regex DoS
  let sample = text.length > maxLen ? text.slice(0, maxLen) : text;

  // HIGH-3: Normalize Unicode (NFKD decomposition — collapses homoglyphs to ASCII equivalents)
  // then strip combining marks, control characters, and zero-width characters
  try { sample = sample.normalize("NFKD"); } catch {}
  sample = sample
    .replace(/[\u0300-\u036F]/g, "")  // combining diacritical marks
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, "")  // control chars
    .replace(/[\u200B\u200C\u200D\u200E\u200F\uFEFF\u00AD\u2060\u2061-\u2064\u2066-\u2069\u061C]/g, ""); // zero-width

  // HIGH-3a: Map common Cyrillic/Greek homoglyphs to ASCII (NFKD doesn't cover cross-script lookalikes)
  const HOMOGLYPHS = { "\u0410":"A","\u0412":"B","\u0421":"C","\u0415":"E","\u041D":"H","\u041A":"K","\u041C":"M","\u041E":"O","\u0420":"P","\u0422":"T","\u0425":"X","\u0430":"a","\u0435":"e","\u043E":"o","\u0440":"p","\u0441":"c","\u0443":"y","\u0445":"x","\u0456":"i","\u0455":"s","\u0458":"j","\u0501":"d","\u04BB":"h","\u0391":"A","\u0392":"B","\u0395":"E","\u0397":"H","\u0399":"I","\u039A":"K","\u039C":"M","\u039D":"N","\u039F":"O","\u03A1":"P","\u03A4":"T","\u03A7":"X","\u03B1":"a","\u03BF":"o","\u03C1":"p" };
  sample = sample.replace(/[\u0391-\u03C9\u0400-\u04FF\u0500-\u052F]/g, ch => HOMOGLYPHS[ch] || ch);

  // HIGH-4: Normalize em dash (U+2014), en dash (U+2013), and other dash-like chars to ASCII hyphen
  // Evasion technique: powershell —e (em dash) instead of powershell -e (hyphen)
  sample = sample.replace(/[\u2013\u2014\u2015\u2212\uFE58\uFE63\uFF0D]/g, "-");

  // HIGH-5: Strip inline double/single quotes used to break Base64 pattern matching
  // Evasion technique: a"QBy"AG0A → aQByAG0A (quotes are no-ops in PowerShell string context)
  // Only strip quotes that appear to be embedded within alphanumeric sequences (not legitimate quoting)
  // Look for pattern: alnum + quote + alnum (quote used as splitter, not delimiter)
  sample = sample.replace(/([A-Za-z0-9+/=])"([A-Za-z0-9+/=])/g, "$1$2");
  // Second pass for adjacent remaining quotes
  sample = sample.replace(/([A-Za-z0-9+/=])"([A-Za-z0-9+/=])/g, "$1$2");

  let floor = 0;
  const matches = [];

  for (const rule of CRITICAL_PATTERNS) {
    if (rule.re.test(sample)) {
      floor = Math.max(floor, rule.weight);
      matches.push({ label: rule.label, family: rule.family, weight: rule.weight, type: "critical" });
    }
  }

  let bonus = 0;
  for (const rule of SUPPORTING_PATTERNS) {
    if (rule.re.test(sample)) {
      bonus += rule.weight;
      matches.push({ label: rule.label, weight: rule.weight, type: "supporting" });
    }
  }

  const finalScore = Math.min(100, floor + Math.min(30, bonus));
  let verdict = "clean";
  if (finalScore >= 60) verdict = "malicious";
  else if (finalScore >= 30) verdict = "suspicious";

  return { score: finalScore, verdict, matches };
}
