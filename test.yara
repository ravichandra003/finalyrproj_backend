import "pe"
import "math"

rule INDICATOR_SUSPICIOUS_GENRansomware {
    meta:
        description = "Detects command variations typically used by ransomware"
        author = "ditekSHen"
        score = 50
    strings:
        $cmd1 = "cmd /c \"WMIC.exe shadowcopy delet\"" ascii wide nocase
        $cmd2 = "vssadmin.exe Delete Shadows /all" ascii wide nocase
        $cmd3 = "Delete Shadows /all" ascii wide nocase
        $cmd4 = "} recoveryenabled no" ascii wide nocase
        $cmd5 = "} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $cmd6 = "wmic SHADOWCOPY DELETE" ascii wide nocase
        $cmd7 = "\\Microsoft\\Windows\\SystemRestore\\SR\" /disable" ascii wide nocase
        $cmd8 = "resize shadowstorage /for=c: /on=c: /maxsize=" ascii wide nocase
        $cmd9 = "shadowcopy where \"ID='%s'\" delete" ascii wide nocase
        $cmd10 = "wmic.exe SHADOWCOPY /nointeractive" ascii wide nocase
        $cmd11 = "WMIC.exe shadowcopy delete" ascii wide nocase
        $cmd12 = "Win32_Shadowcopy | ForEach-Object {$_.Delete();}" ascii wide nocase
        $delr = /del \/s \/f \/q(( [A-Za-z]:\\(\*\.|[Bb]ackup))(VHD|bac|bak|wbcat|bkf)?)+/ ascii wide
        $wp1 = "delete catalog -quiet" ascii wide nocase
        $wp2 = "wbadmin delete backup" ascii wide nocase
        $wp3 = "delete systemstatebackup" ascii wide nocase
    condition:
        (uint16(0) == 0x5a4d and 2 of ($cmd*) or (1 of ($cmd*) and 1 of ($wp*)) or #delr > 4) or (4 of them)
}

rule RANSOM_Exorcist
{
    meta:
        description = "Rule to detect Exorcist"
        author = "McAfee ATR Team"
        date = "2020-09-01"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransomware:W32/Exorcist"
        actor_type = "Cybercrime"
        hash1 = "793dcc731fa2c6f7406fd52c7ac43926ac23e39badce09677128cce0192e19b0"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
    strings:
        $sq1 = { 48 8B C4 48 89 58 08 48 89 70 10 48 89 78 18 4C 89 60 20 55 41 56 41 57 48 8D 68 A1 48 81 EC 90 00 00 00 49 8B F1 49 8B F8 4C 8B FA 48 8B D9 E8 ?? ?? ?? ?? 45 33 E4 85 C0 0F 85 B1 00 00 00 48 8B D7 48 8B CB E8 9E 02 00 00 85 C0 0F 85 9E 00 00 00 33 D2 48 8B CB E8 ?? ?? ?? ?? 45 33 C0 48 8D 15 ?? ?? ?? ?? 48 8B CB E8 ?? ?? ?? ?? 45 8D 44 24 01 48 8B D7 48 8B C8 E8 ?? ?? ?? ?? 48 8B D0 48 8B CB 48 8B F8 FF 15 ?? ?? ?? ?? 4C 89 64 24 30 45 33 C9 C7 44 24 28 80 00 00 E8 45 33 C0 BA 00 00 00 C0 C7 44 24 20 03 00 00 00 48 8B CF FF 15 ?? ?? ?? ?? 4C 8B F0 48 8D 48 FF 48 83 F9 FD 77 25 48 8D 55 2F 48 8B C8 FF 15 ?? ?? ?? ?? 4C 39 65 2F 75 3B 49 8B CE FF 15 ?? ?? ?? ?? 48 8B CF FF 15 ?? ?? ?? ?? 48 8B CF E8 ?? ?? ?? ?? 4C 8D 9C 24 90 00 00 00 49 8B 5B 20 49 8B 73 28 49 8B 7B 30 4D 8B 63 38 49 8B E3 41 5F 41 5E 5D C3 48 8D 45 FB 4C 89 65 1F 4C 8D 4D FF 48 89 44 24 20 4C 8B C6 4C 89 65 07 48 8D 55 07 4C 89 65 FF 48 8D 4D 1F 44 89 65 FB E8 ?? ?? ?? ?? 45 33 C9 4C 8D 05 3C F5 FF FF 49 8B D7 49 8B CE FF 15 ?? ?? ?? ?? 48 8D 55 17 49 8B CE FF 15 ?? ?? ?? ?? 49 8B CE 44 89 65 F7 E8 ?? ?? ?? ?? 49 8B F4 4C 89 65 0F 4C 39 65 17 0F 8E 9D 00 00 00 C1 E0 10 44 8B F8 F0 FF 45 F7 B9 50 00 00 00 E8 ?? ?? ?? ?? 8B 4D 13 48 8B D8 89 48 14 89 70 10 4C 89 60 18 44 89 60 28 4C 89 70 30 48 8B 4D 07 48 89 48 48 48 8D 45 F7 B9 00 00 01 00 48 89 43 40 E8 ?? ?? ?? ?? 33 D2 48 89 43 20 41 B8 00 00 01 00 48 8B C8 E8 ?? ?? ?? ?? 48 8B 53 20 4C 8D 4B 38 41 B8 00 00 01 00 48 89 5C 24 20 49 8B CE FF 15 ?? ?? ?? ?? EB 08 33 C9 FF 15 ?? ?? ?? ?? 8B 45 F7 3D E8 03 00 00 77 EE 49 03 F7 48 89 75 0F 48 3B 75 17 0F 8C 6B FF FF FF EB 03 8B 45 F7 85 C0 74 0E 33 C9 FF 15 ?? ?? ?? ?? 44 39 65 F7 77 F2 48 8B 4D 07 E8 ?? ?? ?? ?? 48 8B 4D 1F 33 D2 E8 ?? ?? ?? ?? 49 8B CE FF 15 ?? ?? ?? ?? 4C 89 64 24 30 45 33 C9 C7 44 24 28 80 00 00 00 45 33 C0 BA 00 00 00 C0 C7 44 24 20 03 00 00 00 48 8B CF FF 15 ?? ?? ?? ?? 48 8B D8 48 8D 48 FF 48 83 F9 FD 77 51 48 8D 55 37 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B 55 37 45 33 C9 45 33 C0 48 8B CB FF 15 ?? ?? ?? ?? 44 8B 45 FB 4C 8D 4D 27 48 8B 55 FF 48 8B CB 4C 89 64 24 20 FF 15 ?? ?? ?? ?? 48 8B 4D FF E8 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? E9 14 FE FF FF 48 8B CF E8 ?? ?? ?? ?? 48 8B 4D FF E9 06 FE FF FF }          
        $sq2 = { 48 8B C4 48 81 EC 38 01 00 00 48 8D 50 08 C7 40 08 04 01 00 00 48 8D 4C 24 20 FF 15 ?? ?? ?? ?? 48 8D 4C 24 20 E8 ?? ?? ?? ?? 48 81 C4 38 01 00 00 C3 } 
    condition:
        uint16(0) == 0x5a4d and
         any of them 
}

rule SEH_Save : Tactic_DefensiveEvasion Technique_AntiDebugging SubTechnique_SEH
{
    meta:
        author = "Malware Utkonos"
        original_author = "naxonez"
        source = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
    strings:
        $a = { 64 ff 35 00 00 00 00 }
	$b = { 64 89 25 00 00 00 00 }
    condition:
        $a or $b
}

rule anti_dbg {
    meta:
        author = "x0r"
        description = "Checks if being debugged"
	version = "0.2"
    strings:
    	$d1 = "Kernel32.dll" nocase
        $c1 = "CheckRemoteDebuggerPresent"
        $c2 = "IsDebuggerPresent"
        $c3 = "OutputDebugString"
        $c4 = "ContinueDebugEvent"
        $c5 = "DebugActiveProcess"
    condition:
        $d1 and 1 of ($c*)
}

rule EnigmaProtector11X13XSukhovVladimirSergeNMarkin
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 00 10 40 00 E8 01 00 00 00 9A 83 C4 10 8B E5 5D E9 }
condition:
		$a0
}

rule BobSoftMiniDelphiBoBBobSoft
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 B8 [4] E8 [4] 33 C0 55 68 [4] 64 FF 30 64 89 20 B8 }
	$a1 = { 55 8B EC 83 C4 F0 53 B8 [4] E8 [4] 33 C0 55 68 [4] 64 FF 30 64 89 20 B8 [4] E8 }
	$a2 = { 55 8B EC 83 C4 F0 B8 [4] E8 }
condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}

rule SUSP_XORed_URL_In_EXE {
   meta:
      description = "Detects an XORed URL in an executable"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/stvemillertime/status/1237035794973560834"
      date = "2020-03-09"
      modified = "2022-09-16"
      score = 50
      id = "f83991c8-f2d9-5583-845a-d105034783ab"
   strings:
      $s1 = "http://" xor
      $s2 = "https://" xor
      $f1 = "http://" ascii
      $f2 = "https://" ascii
      $fp01 = "3Com Corporation" ascii  /* old driver */
      $fp02 = "bootloader.jar" ascii  /* DeepGit */
      $fp03 = "AVAST Software" ascii wide
      $fp04 = "smartsvn" wide ascii fullword
      $fp05 = "Avira Operations GmbH" wide fullword
      $fp06 = "Perl Dev Kit" wide fullword
      $fp07 = "Digiread" wide fullword
      $fp08 = "Avid Editor" wide fullword
      $fp09 = "Digisign" wide fullword
      $fp10 = "Microsoft Corporation" wide fullword
      $fp11 = "Microsoft Code Signing" ascii wide
      $fp12 = "XtraProxy" wide fullword
      $fp13 = "A Sophos Company" wide
      $fp14 = "http://crl3.digicert.com/" ascii
      $fp15 = "http://crl.sectigo.com/SectigoRSACodeSigningCA.crl" ascii
      $fp16 = "HitmanPro.Alert" wide fullword
   condition:
      uint16(0) == 0x5a4d and
      filesize < 2000KB and (
         ( $s1 and #s1 > #f1 ) or
         ( $s2 and #s2 > #f2 )
      )
      and not 1 of ($fp*)
      and not pe.number_of_signatures > 0
}

rule maldoc_getEIP_method_1 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {E8 00 00 00 00 (58|59|5A|5B|5C|5D|5E|5F)}
    condition:
        $a
}



rule SHA1
{
  meta:
    description = "Uses constants related to SHA1"
    author = "Ivan Kwiatkowski (@JusticeRage)"
  strings:
    $sha1_f1 = { 99 79 82 5A }
    $sha1_f2 = { a1 eb d9 6e }
    $sha1_f3 = { dc bc 1b 8f }
    $sha1_f4 = { d6 c1 62 ca }
  condition:
    all of ($sha1_f*)
}

rule Ran_Crysis_Sep_2020_1 {
   meta:
      description = "Detect Crysis ransomware"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2020-10-16"
      hash1 = "34c485ad11076ede709ff409c0e1867dc50fd40311ae6e7318ddf50679fa4049"
      hash2 = "4708750c9a6fdeaec5f499a3cd26bb5f61db4f82e66484dc7b44118effbb246f"
      hash3 = "b565c8e1e81796db13409f37e4bd28877272b5e54ab5c0a3d9b6a024e7f5a039"
      hash4 = "8e8b6818423930eea073315743b788aef2f41198961946046b7b89042cb3f95a"
   strings:
      $s1 = { 6f 25 25 4a 72 2e 2e 5c 24 } 
      $s2 = { 52 53 44 53 25 7e 6d }
      $s3 = { 78 78 4a 6f 25 25 5c 72 2e 2e 38 24 }
      $s4 = { 25 65 65 ca af 7a 7a f4 8e ae ae 47 e9 08 08 10 18 ba ba }
      $s5 = { 58 74 1a 1a 34 2e 1b 1b 36 2d 6e 6e dc b2 5a 5a b4 ee a0 a0 5b fb 52 52 a4 f6 3b 3b 76 4d d6 d6 b7 61 b3 b3 7d ce 29 29 52 7b e3 e3 dd 3e 2f 2f 5e 71 84 84 13 97 53 53 }
      $s6 = { 3b 32 32 64 56 3a 3a 74 4e 0a 0a 14 1e 49 49 92 db 06 06 0c 0a 24 24 48 6c 5c 5c b8 e4 c2 c2 9f 5d d3 d3 bd 6e ac ac 43 ef 62 62 }
      $s7 = { 26 4c 6a 26 36 6c 5a 36 3f 7e 41 3f f7 f5 02 f7 cc 83 4f cc 34 68 5c 34 a5 51 f4 a5 e5 d1 34 e5 f1 f9 08 f1 71 e2 93 71 d8 ab 73 d8 31 62 53 31 15 2a 3f 15 04 08 0c 04 c7 95 52 c7 23 46 65 23 }
      $s8 = { 7e fc 82 7e 3d 7a 47 3d 64 c8 ac 64 5d ba e7 5d 19 32 2b 19 73 e6 95 73 60 c0 a0 60 81 19 98 81 4f 9e d1 4f dc a3 7f dc 22 44 66 22 2a 54 7e 2a 90 3b ab 90 88 0b 83 88 46 8c ca 46 ee c7 29 }
      $s9 = "sssssbsss" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize > 30KB and all of them
}

rule MAL_Ransomware_Wadhrama {
   meta:
      description = "Detects Wadhrama Ransomware via Imphash"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-04-07"
      hash1 = "557c68e38dce7ea10622763c10a1b9f853c236b3291cd4f9b32723e8714e5576"
      id = "f7de40e9-fe22-5f14-abc6-f6611a4382ac"
   condition:
      uint16(0) == 0x5a4d and pe.imphash() == "f86dec4a80961955a89e7ed62046cc0e"
}

rule AES
{
  meta:
    description = "Uses constants related to AES"
    author = "Ivan Kwiatkowski (@JusticeRage)"
  strings:
    $aes_se = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0 B7 FD 93 26 36 3F F7 CC 34 A5 E5 F1 71 D8 31 15 04 C7 23 C3 18 96 05 9A 07 12 80 E2 EB 27 B2 75 09 83 2C 1A 1B 6E 5A A0 52 3B D6 B3 29 E3 2F 84 53 D1 00 ED 20 FC B1 5B 6A CB BE 39 4A 4C 58 CF D0 EF AA FB 43 4D 33 85 45 F9 02 7F 50 3C 9F A8 51 A3 40 8F 92 9D 38 F5 BC B6 DA 21 10 FF F3 D2 CD 0C 13 EC 5F 97 44 17 C4 A7 7E 3D 64 5D 19 73 60 81 4F DC 22 2A 90 88 46 EE B8 14 DE 5E 0B DB E0 32 3A 0A 49 06 24 5C C2 D3 AC 62 91 95 E4 79 E7 C8 37 6D 8D D5 4E A9 6C 56 F4 EA 65 7A AE 08 BA 78 25 2E 1C A6 B4 C6 E8 DD 74 1F 4B BD 8B 8A 70 3E B5 66 48 03 F6 0E 61 35 57 B9 86 C1 1D 9E E1 F8 98 11 69 D9 8E 94 9B 1E 87 E9 CE 55 28 DF 8C A1 89 0D BF E6 42 68 41 99 2D 0F B0 54 BB 16 }
    $aes_sd = { 52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB 7C E3 39 82 9B 2F FF 87 34 8E 43 44 C4 DE E9 CB 54 7B 94 32 A6 C2 23 3D EE 4C 95 0B 42 FA C3 4E 08 2E A1 66 28 D9 24 B2 76 5B A2 49 6D 8B D1 25 72 F8 F6 64 86 68 98 16 D4 A4 5C CC 5D 65 B6 92 6C 70 48 50 FD ED B9 DA 5E 15 46 57 A7 8D 9D 84 90 D8 AB 00 8C BC D3 0A F7 E4 58 05 B8 B3 45 06 D0 2C 1E 8F CA 3F 0F 02 C1 AF BD 03 01 13 8A 6B 3A 91 11 41 4F 67 DC EA 97 F2 CF CE F0 B4 E6 73 96 AC 74 22 E7 AD 35 85 E2 F9 37 E8 1C 75 DF 6E 47 F1 1A 71 1D 29 C5 89 6F B7 62 0E AA 18 BE 1B FC 56 3E 4B C6 D2 79 20 9A DB C0 FE 78 CD 5A F4 1F DD A8 33 88 07 C7 31 B1 12 10 59 27 80 EC 5F 60 51 7F A9 19 B5 4A 0D 2D E5 7A 9F 93 C9 9C EF A0 E0 3B 4D AE 2A F5 B0 C8 EB BB 3C 83 53 99 61 17 2B 04 7E BA 77 D6 26 E1 69 14 63 55 21 0C 7D }
    $aes_te0 = { a5 63 63 c6 84 7c 7c f8 99 77 77 ee 8d 7b 7b f6 0d f2 f2 ff bd 6b 6b d6 b1 6f 6f de 54 c5 c5 91 50 30 30 60 03 01 01 02 a9 67 67 ce 7d 2b 2b 56 19 fe fe e7 62 d7 d7 b5 e6 ab ab 4d 9a 76 76 ec 45 ca ca 8f 9d 82 82 1f 40 c9 c9 89 87 7d 7d fa 15 fa fa ef eb 59 59 b2 c9 47 47 8e 0b f0 f0 fb ec ad ad 41 67 d4 d4 b3 fd a2 a2 5f ea af af 45 bf 9c 9c 23 f7 a4 a4 53 96 72 72 e4 5b c0 c0 9b c2 b7 b7 75 1c fd fd e1 ae 93 93 3d 6a 26 26 4c 5a 36 36 6c 41 3f 3f 7e 02 f7 f7 f5 4f cc cc 83 5c 34 34 68 f4 a5 a5 51 34 e5 e5 d1 08 f1 f1 f9 93 71 71 e2 73 d8 d8 ab 53 31 31 62 3f 15 15 2a 0c 04 04 08 52 c7 c7 95 65 23 23 46 5e c3 c3 9d 28 18 18 30 a1 96 96 37 0f 05 05 0a b5 9a 9a 2f 09 07 07 0e 36 12 12 24 9b 80 80 1b 3d e2 e2 df 26 eb eb cd 69 27 27 4e cd b2 b2 7f 9f 75 75 ea 1b 09 09 12 9e 83 83 1d 74 2c 2c 58 2e 1a 1a 34 2d 1b 1b 36 b2 6e 6e dc ee 5a 5a b4 fb a0 a0 5b f6 52 52 a4 4d 3b 3b 76 61 d6 d6 b7 ce b3 b3 7d 7b 29 29 52 3e e3 e3 dd 71 2f 2f 5e 97 84 84 13 f5 53 53 a6 68 d1 d1 b9 00 00 00 00 2c ed ed c1 60 20 20 40 1f fc fc e3 c8 b1 b1 79 ed 5b 5b b6 be 6a 6a d4 46 cb cb 8d d9 be be 67 4b 39 39 72 de 4a 4a 94 d4 4c 4c 98 e8 58 58 b0 4a cf cf 85 6b d0 d0 bb 2a ef ef c5 e5 aa aa 4f 16 fb fb ed c5 43 43 86 d7 4d 4d 9a 55 33 33 66 94 85 85 11 cf 45 45 8a 10 f9 f9 e9 06 02 02 04 81 7f 7f fe f0 50 50 a0 44 3c 3c 78 ba 9f 9f 25 e3 a8 a8 4b f3 51 51 a2 fe a3 a3 5d c0 40 40 80 8a 8f 8f 05 ad 92 92 3f bc 9d 9d 21 48 38 38 70 04 f5 f5 f1 df bc bc 63 c1 b6 b6 77 75 da da af 63 21 21 42 30 10 10 20 1a ff ff e5 0e f3 f3 fd 6d d2 d2 bf 4c cd cd 81 14 0c 0c 18 35 13 13 26 2f ec ec c3 e1 5f 5f be a2 97 97 35 cc 44 44 88 39 17 17 2e 57 c4 c4 93 f2 a7 a7 55 82 7e 7e fc 47 3d 3d 7a ac 64 64 c8 e7 5d 5d ba 2b 19 19 32 95 73 73 e6 a0 60 60 c0 98 81 81 19 d1 4f 4f 9e 7f dc dc a3 66 22 22 44 7e 2a 2a 54 ab 90 90 3b 83 88 88 0b ca 46 46 8c 29 ee ee c7 d3 b8 b8 6b 3c 14 14 28 79 de de a7 e2 5e 5e bc 1d 0b 0b 16 76 db db ad 3b e0 e0 db 56 32 32 64 4e 3a 3a 74 1e 0a 0a 14 db 49 49 92 0a 06 06 0c 6c 24 24 48 e4 5c 5c b8 5d c2 c2 9f 6e d3 d3 bd ef ac ac 43 a6 62 62 c4 a8 91 91 39 a4 95 95 31 37 e4 e4 d3 8b 79 79 f2 32 e7 e7 d5 43 c8 c8 8b 59 37 37 6e b7 6d 6d da 8c 8d 8d 01 64 d5 d5 b1 d2 4e 4e 9c e0 a9 a9 49 b4 6c 6c d8 fa 56 56 ac 07 f4 f4 f3 25 ea ea cf af 65 65 ca 8e 7a 7a f4 e9 ae ae 47 18 08 08 10 d5 ba ba 6f 88 78 78 f0 6f 25 25 4a 72 2e 2e 5c 24 1c 1c 38 f1 a6 a6 57 c7 b4 b4 73 51 c6 c6 97 23 e8 e8 cb 7c dd dd a1 9c 74 74 e8 21 1f 1f 3e dd 4b 4b 96 dc bd bd 61 86 8b 8b 0d 85 8a 8a 0f 90 70 70 e0 42 3e 3e 7c c4 b5 b5 71 aa 66 66 cc d8 48 48 90 05 03 03 06 01 f6 f6 f7 12 0e 0e 1c a3 61 61 c2 5f 35 35 6a f9 57 57 ae d0 b9 b9 69 91 86 86 17 58 c1 c1 99 27 1d 1d 3a b9 9e 9e 27 38 e1 e1 d9 13 f8 f8 eb b3 98 98 2b 33 11 11 22 bb 69 69 d2 70 d9 d9 a9 89 8e 8e 07 a7 94 94 33 b6 9b 9b 2d 22 1e 1e 3c 92 87 87 15 20 e9 e9 c9 49 ce ce 87 ff 55 55 aa 78 28 28 50 7a df df a5 8f 8c 8c 03 f8 a1 a1 59 80 89 89 09 17 0d 0d 1a da bf bf 65 31 e6 e6 d7 c6 42 42 84 b8 68 68 d0 c3 41 41 82 b0 99 99 29 77 2d 2d 5a 11 0f 0f 1e cb b0 b0 7b fc 54 54 a8 d6 bb bb 6d 3a 16 16 2c }
    $aes_te1 = { 63 63 c6 a5 7c 7c f8 84 77 77 ee 99 7b 7b f6 8d f2 f2 ff 0d 6b 6b d6 bd 6f 6f de b1 c5 c5 91 54 30 30 60 50 01 01 02 03 67 67 ce a9 2b 2b 56 7d fe fe e7 19 d7 d7 b5 62 ab ab 4d e6 76 76 ec 9a ca ca 8f 45 82 82 1f 9d c9 c9 89 40 7d 7d fa 87 fa fa ef 15 59 59 b2 eb 47 47 8e c9 f0 f0 fb 0b ad ad 41 ec d4 d4 b3 67 a2 a2 5f fd af af 45 ea 9c 9c 23 bf a4 a4 53 f7 72 72 e4 96 c0 c0 9b 5b b7 b7 75 c2 fd fd e1 1c 93 93 3d ae 26 26 4c 6a 36 36 6c 5a 3f 3f 7e 41 f7 f7 f5 02 cc cc 83 4f 34 34 68 5c a5 a5 51 f4 e5 e5 d1 34 f1 f1 f9 08 71 71 e2 93 d8 d8 ab 73 31 31 62 53 15 15 2a 3f 04 04 08 0c c7 c7 95 52 23 23 46 65 c3 c3 9d 5e 18 18 30 28 96 96 37 a1 05 05 0a 0f 9a 9a 2f b5 07 07 0e 09 12 12 24 36 80 80 1b 9b e2 e2 df 3d eb eb cd 26 27 27 4e 69 b2 b2 7f cd 75 75 ea 9f 09 09 12 1b 83 83 1d 9e 2c 2c 58 74 1a 1a 34 2e 1b 1b 36 2d 6e 6e dc b2 5a 5a b4 ee a0 a0 5b fb 52 52 a4 f6 3b 3b 76 4d d6 d6 b7 61 b3 b3 7d ce 29 29 52 7b e3 e3 dd 3e 2f 2f 5e 71 84 84 13 97 53 53 a6 f5 d1 d1 b9 68 00 00 00 00 ed ed c1 2c 20 20 40 60 fc fc e3 1f b1 b1 79 c8 5b 5b b6 ed 6a 6a d4 be cb cb 8d 46 be be 67 d9 39 39 72 4b 4a 4a 94 de 4c 4c 98 d4 58 58 b0 e8 cf cf 85 4a d0 d0 bb 6b ef ef c5 2a aa aa 4f e5 fb fb ed 16 43 43 86 c5 4d 4d 9a d7 33 33 66 55 85 85 11 94 45 45 8a cf f9 f9 e9 10 02 02 04 06 7f 7f fe 81 50 50 a0 f0 3c 3c 78 44 9f 9f 25 ba a8 a8 4b e3 51 51 a2 f3 a3 a3 5d fe 40 40 80 c0 8f 8f 05 8a 92 92 3f ad 9d 9d 21 bc 38 38 70 48 f5 f5 f1 04 bc bc 63 df b6 b6 77 c1 da da af 75 21 21 42 63 10 10 20 30 ff ff e5 1a f3 f3 fd 0e d2 d2 bf 6d cd cd 81 4c 0c 0c 18 14 13 13 26 35 ec ec c3 2f 5f 5f be e1 97 97 35 a2 44 44 88 cc 17 17 2e 39 c4 c4 93 57 a7 a7 55 f2 7e 7e fc 82 3d 3d 7a 47 64 64 c8 ac 5d 5d ba e7 19 19 32 2b 73 73 e6 95 60 60 c0 a0 81 81 19 98 4f 4f 9e d1 dc dc a3 7f 22 22 44 66 2a 2a 54 7e 90 90 3b ab 88 88 0b 83 46 46 8c ca ee ee c7 29 b8 b8 6b d3 14 14 28 3c de de a7 79 5e 5e bc e2 0b 0b 16 1d db db ad 76 e0 e0 db 3b 32 32 64 56 3a 3a 74 4e 0a 0a 14 1e 49 49 92 db 06 06 0c 0a 24 24 48 6c 5c 5c b8 e4 c2 c2 9f 5d d3 d3 bd 6e ac ac 43 ef 62 62 c4 a6 91 91 39 a8 95 95 31 a4 e4 e4 d3 37 79 79 f2 8b e7 e7 d5 32 c8 c8 8b 43 37 37 6e 59 6d 6d da b7 8d 8d 01 8c d5 d5 b1 64 4e 4e 9c d2 a9 a9 49 e0 6c 6c d8 b4 56 56 ac fa f4 f4 f3 07 ea ea cf 25 65 65 ca af 7a 7a f4 8e ae ae 47 e9 08 08 10 18 ba ba 6f d5 78 78 f0 88 25 25 4a 6f 2e 2e 5c 72 1c 1c 38 24 a6 a6 57 f1 b4 b4 73 c7 c6 c6 97 51 e8 e8 cb 23 dd dd a1 7c 74 74 e8 9c 1f 1f 3e 21 4b 4b 96 dd bd bd 61 dc 8b 8b 0d 86 8a 8a 0f 85 70 70 e0 90 3e 3e 7c 42 b5 b5 71 c4 66 66 cc aa 48 48 90 d8 03 03 06 05 f6 f6 f7 01 0e 0e 1c 12 61 61 c2 a3 35 35 6a 5f 57 57 ae f9 b9 b9 69 d0 86 86 17 91 c1 c1 99 58 1d 1d 3a 27 9e 9e 27 b9 e1 e1 d9 38 f8 f8 eb 13 98 98 2b b3 11 11 22 33 69 69 d2 bb d9 d9 a9 70 8e 8e 07 89 94 94 33 a7 9b 9b 2d b6 1e 1e 3c 22 87 87 15 92 e9 e9 c9 20 ce ce 87 49 55 55 aa ff 28 28 50 78 df df a5 7a 8c 8c 03 8f a1 a1 59 f8 89 89 09 80 0d 0d 1a 17 bf bf 65 da e6 e6 d7 31 42 42 84 c6 68 68 d0 b8 41 41 82 c3 99 99 29 b0 2d 2d 5a 77 0f 0f 1e 11 b0 b0 7b cb 54 54 a8 fc bb bb 6d d6 16 16 2c 3a }
    $aes_te2 = { 63 c6 a5 63 7c f8 84 7c 77 ee 99 77 7b f6 8d 7b f2 ff 0d f2 6b d6 bd 6b 6f de b1 6f c5 91 54 c5 30 60 50 30 01 02 03 01 67 ce a9 67 2b 56 7d 2b fe e7 19 fe d7 b5 62 d7 ab 4d e6 ab 76 ec 9a 76 ca 8f 45 ca 82 1f 9d 82 c9 89 40 c9 7d fa 87 7d fa ef 15 fa 59 b2 eb 59 47 8e c9 47 f0 fb 0b f0 ad 41 ec ad d4 b3 67 d4 a2 5f fd a2 af 45 ea af 9c 23 bf 9c a4 53 f7 a4 72 e4 96 72 c0 9b 5b c0 b7 75 c2 b7 fd e1 1c fd 93 3d ae 93 26 4c 6a 26 36 6c 5a 36 3f 7e 41 3f f7 f5 02 f7 cc 83 4f cc 34 68 5c 34 a5 51 f4 a5 e5 d1 34 e5 f1 f9 08 f1 71 e2 93 71 d8 ab 73 d8 31 62 53 31 15 2a 3f 15 04 08 0c 04 c7 95 52 c7 23 46 65 23 c3 9d 5e c3 18 30 28 18 96 37 a1 96 05 0a 0f 05 9a 2f b5 9a 07 0e 09 07 12 24 36 12 80 1b 9b 80 e2 df 3d e2 eb cd 26 eb 27 4e 69 27 b2 7f cd b2 75 ea 9f 75 09 12 1b 09 83 1d 9e 83 2c 58 74 2c 1a 34 2e 1a 1b 36 2d 1b 6e dc b2 6e 5a b4 ee 5a a0 5b fb a0 52 a4 f6 52 3b 76 4d 3b d6 b7 61 d6 b3 7d ce b3 29 52 7b 29 e3 dd 3e e3 2f 5e 71 2f 84 13 97 84 53 a6 f5 53 d1 b9 68 d1 00 00 00 00 ed c1 2c ed 20 40 60 20 fc e3 1f fc b1 79 c8 b1 5b b6 ed 5b 6a d4 be 6a cb 8d 46 cb be 67 d9 be 39 72 4b 39 4a 94 de 4a 4c 98 d4 4c 58 b0 e8 58 cf 85 4a cf d0 bb 6b d0 ef c5 2a ef aa 4f e5 aa fb ed 16 fb 43 86 c5 43 4d 9a d7 4d 33 66 55 33 85 11 94 85 45 8a cf 45 f9 e9 10 f9 02 04 06 02 7f fe 81 7f 50 a0 f0 50 3c 78 44 3c 9f 25 ba 9f a8 4b e3 a8 51 a2 f3 51 a3 5d fe a3 40 80 c0 40 8f 05 8a 8f 92 3f ad 92 9d 21 bc 9d 38 70 48 38 f5 f1 04 f5 bc 63 df bc b6 77 c1 b6 da af 75 da 21 42 63 21 10 20 30 10 ff e5 1a ff f3 fd 0e f3 d2 bf 6d d2 cd 81 4c cd 0c 18 14 0c 13 26 35 13 ec c3 2f ec 5f be e1 5f 97 35 a2 97 44 88 cc 44 17 2e 39 17 c4 93 57 c4 a7 55 f2 a7 7e fc 82 7e 3d 7a 47 3d 64 c8 ac 64 5d ba e7 5d 19 32 2b 19 73 e6 95 73 60 c0 a0 60 81 19 98 81 4f 9e d1 4f dc a3 7f dc 22 44 66 22 2a 54 7e 2a 90 3b ab 90 88 0b 83 88 46 8c ca 46 ee c7 29 ee b8 6b d3 b8 14 28 3c 14 de a7 79 de 5e bc e2 5e 0b 16 1d 0b db ad 76 db e0 db 3b e0 32 64 56 32 3a 74 4e 3a 0a 14 1e 0a 49 92 db 49 06 0c 0a 06 24 48 6c 24 5c b8 e4 5c c2 9f 5d c2 d3 bd 6e d3 ac 43 ef ac 62 c4 a6 62 91 39 a8 91 95 31 a4 95 e4 d3 37 e4 79 f2 8b 79 e7 d5 32 e7 c8 8b 43 c8 37 6e 59 37 6d da b7 6d 8d 01 8c 8d d5 b1 64 d5 4e 9c d2 4e a9 49 e0 a9 6c d8 b4 6c 56 ac fa 56 f4 f3 07 f4 ea cf 25 ea 65 ca af 65 7a f4 8e 7a ae 47 e9 ae 08 10 18 08 ba 6f d5 ba 78 f0 88 78 25 4a 6f 25 2e 5c 72 2e 1c 38 24 1c a6 57 f1 a6 b4 73 c7 b4 c6 97 51 c6 e8 cb 23 e8 dd a1 7c dd 74 e8 9c 74 1f 3e 21 1f 4b 96 dd 4b bd 61 dc bd 8b 0d 86 8b 8a 0f 85 8a 70 e0 90 70 3e 7c 42 3e b5 71 c4 b5 66 cc aa 66 48 90 d8 48 03 06 05 03 f6 f7 01 f6 0e 1c 12 0e 61 c2 a3 61 35 6a 5f 35 57 ae f9 57 b9 69 d0 b9 86 17 91 86 c1 99 58 c1 1d 3a 27 1d 9e 27 b9 9e e1 d9 38 e1 f8 eb 13 f8 98 2b b3 98 11 22 33 11 69 d2 bb 69 d9 a9 70 d9 8e 07 89 8e 94 33 a7 94 9b 2d b6 9b 1e 3c 22 1e 87 15 92 87 e9 c9 20 e9 ce 87 49 ce 55 aa ff 55 28 50 78 28 df a5 7a df 8c 03 8f 8c a1 59 f8 a1 89 09 80 89 0d 1a 17 0d bf 65 da bf e6 d7 31 e6 42 84 c6 42 68 d0 b8 68 41 82 c3 41 99 29 b0 99 2d 5a 77 2d 0f 1e 11 0f b0 7b cb b0 54 a8 fc 54 bb 6d d6 bb 16 2c 3a 16 }
    $aes_te3 = { c6 a5 63 63 f8 84 7c 7c ee 99 77 77 f6 8d 7b 7b ff 0d f2 f2 d6 bd 6b 6b de b1 6f 6f 91 54 c5 c5 60 50 30 30 02 03 01 01 ce a9 67 67 56 7d 2b 2b e7 19 fe fe b5 62 d7 d7 4d e6 ab ab ec 9a 76 76 8f 45 ca ca 1f 9d 82 82 89 40 c9 c9 fa 87 7d 7d ef 15 fa fa b2 eb 59 59 8e c9 47 47 fb 0b f0 f0 41 ec ad ad b3 67 d4 d4 5f fd a2 a2 45 ea af af 23 bf 9c 9c 53 f7 a4 a4 e4 96 72 72 9b 5b c0 c0 75 c2 b7 b7 e1 1c fd fd 3d ae 93 93 4c 6a 26 26 6c 5a 36 36 7e 41 3f 3f f5 02 f7 f7 83 4f cc cc 68 5c 34 34 51 f4 a5 a5 d1 34 e5 e5 f9 08 f1 f1 e2 93 71 71 ab 73 d8 d8 62 53 31 31 2a 3f 15 15 08 0c 04 04 95 52 c7 c7 46 65 23 23 9d 5e c3 c3 30 28 18 18 37 a1 96 96 0a 0f 05 05 2f b5 9a 9a 0e 09 07 07 24 36 12 12 1b 9b 80 80 df 3d e2 e2 cd 26 eb eb 4e 69 27 27 7f cd b2 b2 ea 9f 75 75 12 1b 09 09 1d 9e 83 83 58 74 2c 2c 34 2e 1a 1a 36 2d 1b 1b dc b2 6e 6e b4 ee 5a 5a 5b fb a0 a0 a4 f6 52 52 76 4d 3b 3b b7 61 d6 d6 7d ce b3 b3 52 7b 29 29 dd 3e e3 e3 5e 71 2f 2f 13 97 84 84 a6 f5 53 53 b9 68 d1 d1 00 00 00 00 c1 2c ed ed 40 60 20 20 e3 1f fc fc 79 c8 b1 b1 b6 ed 5b 5b d4 be 6a 6a 8d 46 cb cb 67 d9 be be 72 4b 39 39 94 de 4a 4a 98 d4 4c 4c b0 e8 58 58 85 4a cf cf bb 6b d0 d0 c5 2a ef ef 4f e5 aa aa ed 16 fb fb 86 c5 43 43 9a d7 4d 4d 66 55 33 33 11 94 85 85 8a cf 45 45 e9 10 f9 f9 04 06 02 02 fe 81 7f 7f a0 f0 50 50 78 44 3c 3c 25 ba 9f 9f 4b e3 a8 a8 a2 f3 51 51 5d fe a3 a3 80 c0 40 40 05 8a 8f 8f 3f ad 92 92 21 bc 9d 9d 70 48 38 38 f1 04 f5 f5 63 df bc bc 77 c1 b6 b6 af 75 da da 42 63 21 21 20 30 10 10 e5 1a ff ff fd 0e f3 f3 bf 6d d2 d2 81 4c cd cd 18 14 0c 0c 26 35 13 13 c3 2f ec ec be e1 5f 5f 35 a2 97 97 88 cc 44 44 2e 39 17 17 93 57 c4 c4 55 f2 a7 a7 fc 82 7e 7e 7a 47 3d 3d c8 ac 64 64 ba e7 5d 5d 32 2b 19 19 e6 95 73 73 c0 a0 60 60 19 98 81 81 9e d1 4f 4f a3 7f dc dc 44 66 22 22 54 7e 2a 2a 3b ab 90 90 0b 83 88 88 8c ca 46 46 c7 29 ee ee 6b d3 b8 b8 28 3c 14 14 a7 79 de de bc e2 5e 5e 16 1d 0b 0b ad 76 db db db 3b e0 e0 64 56 32 32 74 4e 3a 3a 14 1e 0a 0a 92 db 49 49 0c 0a 06 06 48 6c 24 24 b8 e4 5c 5c 9f 5d c2 c2 bd 6e d3 d3 43 ef ac ac c4 a6 62 62 39 a8 91 91 31 a4 95 95 d3 37 e4 e4 f2 8b 79 79 d5 32 e7 e7 8b 43 c8 c8 6e 59 37 37 da b7 6d 6d 01 8c 8d 8d b1 64 d5 d5 9c d2 4e 4e 49 e0 a9 a9 d8 b4 6c 6c ac fa 56 56 f3 07 f4 f4 cf 25 ea ea ca af 65 65 f4 8e 7a 7a 47 e9 ae ae 10 18 08 08 6f d5 ba ba f0 88 78 78 4a 6f 25 25 5c 72 2e 2e 38 24 1c 1c 57 f1 a6 a6 73 c7 b4 b4 97 51 c6 c6 cb 23 e8 e8 a1 7c dd dd e8 9c 74 74 3e 21 1f 1f 96 dd 4b 4b 61 dc bd bd 0d 86 8b 8b 0f 85 8a 8a e0 90 70 70 7c 42 3e 3e 71 c4 b5 b5 cc aa 66 66 90 d8 48 48 06 05 03 03 f7 01 f6 f6 1c 12 0e 0e c2 a3 61 61 6a 5f 35 35 ae f9 57 57 69 d0 b9 b9 17 91 86 86 99 58 c1 c1 3a 27 1d 1d 27 b9 9e 9e d9 38 e1 e1 eb 13 f8 f8 2b b3 98 98 22 33 11 11 d2 bb 69 69 a9 70 d9 d9 07 89 8e 8e 33 a7 94 94 2d b6 9b 9b 3c 22 1e 1e 15 92 87 87 c9 20 e9 e9 87 49 ce ce aa ff 55 55 50 78 28 28 a5 7a df df 03 8f 8c 8c 59 f8 a1 a1 09 80 89 89 1a 17 0d 0d 65 da bf bf d7 31 e6 e6 84 c6 42 42 d0 b8 68 68 82 c3 41 41 29 b0 99 99 5a 77 2d 2d 1e 11 0f 0f 7b cb b0 b0 a8 fc 54 54 6d d6 bb bb 2c 3a 16 16 }
    $aes_te4 = { 63 63 63 63 7c 7c 7c 7c 77 77 77 77 7b 7b 7b 7b f2 f2 f2 f2 6b 6b 6b 6b 6f 6f 6f 6f c5 c5 c5 c5 30 30 30 30 01 01 01 01 67 67 67 67 2b 2b 2b 2b fe fe fe fe d7 d7 d7 d7 ab ab ab ab 76 76 76 76 ca ca ca ca 82 82 82 82 c9 c9 c9 c9 7d 7d 7d 7d fa fa fa fa 59 59 59 59 47 47 47 47 f0 f0 f0 f0 ad ad ad ad d4 d4 d4 d4 a2 a2 a2 a2 af af af af 9c 9c 9c 9c a4 a4 a4 a4 72 72 72 72 c0 c0 c0 c0 b7 b7 b7 b7 fd fd fd fd 93 93 93 93 26 26 26 26 36 36 36 36 3f 3f 3f 3f f7 f7 f7 f7 cc cc cc cc 34 34 34 34 a5 a5 a5 a5 e5 e5 e5 e5 f1 f1 f1 f1 71 71 71 71 d8 d8 d8 d8 31 31 31 31 15 15 15 15 04 04 04 04 c7 c7 c7 c7 23 23 23 23 c3 c3 c3 c3 18 18 18 18 96 96 96 96 05 05 05 05 9a 9a 9a 9a 07 07 07 07 12 12 12 12 80 80 80 80 e2 e2 e2 e2 eb eb eb eb 27 27 27 27 b2 b2 b2 b2 75 75 75 75 09 09 09 09 83 83 83 83 2c 2c 2c 2c 1a 1a 1a 1a 1b 1b 1b 1b 6e 6e 6e 6e 5a 5a 5a 5a a0 a0 a0 a0 52 52 52 52 3b 3b 3b 3b d6 d6 d6 d6 b3 b3 b3 b3 29 29 29 29 e3 e3 e3 e3 2f 2f 2f 2f 84 84 84 84 53 53 53 53 d1 d1 d1 d1 00 00 00 00 ed ed ed ed 20 20 20 20 fc fc fc fc b1 b1 b1 b1 5b 5b 5b 5b 6a 6a 6a 6a cb cb cb cb be be be be 39 39 39 39 4a 4a 4a 4a 4c 4c 4c 4c 58 58 58 58 cf cf cf cf d0 d0 d0 d0 ef ef ef ef aa aa aa aa fb fb fb fb 43 43 43 43 4d 4d 4d 4d 33 33 33 33 85 85 85 85 45 45 45 45 f9 f9 f9 f9 02 02 02 02 7f 7f 7f 7f 50 50 50 50 3c 3c 3c 3c 9f 9f 9f 9f a8 a8 a8 a8 51 51 51 51 a3 a3 a3 a3 40 40 40 40 8f 8f 8f 8f 92 92 92 92 9d 9d 9d 9d 38 38 38 38 f5 f5 f5 f5 bc bc bc bc b6 b6 b6 b6 da da da da 21 21 21 21 10 10 10 10 ff ff ff ff f3 f3 f3 f3 d2 d2 d2 d2 cd cd cd cd 0c 0c 0c 0c 13 13 13 13 ec ec ec ec 5f 5f 5f 5f 97 97 97 97 44 44 44 44 17 17 17 17 c4 c4 c4 c4 a7 a7 a7 a7 7e 7e 7e 7e 3d 3d 3d 3d 64 64 64 64 5d 5d 5d 5d 19 19 19 19 73 73 73 73 60 60 60 60 81 81 81 81 4f 4f 4f 4f dc dc dc dc 22 22 22 22 2a 2a 2a 2a 90 90 90 90 88 88 88 88 46 46 46 46 ee ee ee ee b8 b8 b8 b8 14 14 14 14 de de de de 5e 5e 5e 5e 0b 0b 0b 0b db db db db e0 e0 e0 e0 32 32 32 32 3a 3a 3a 3a 0a 0a 0a 0a 49 49 49 49 06 06 06 06 24 24 24 24 5c 5c 5c 5c c2 c2 c2 c2 d3 d3 d3 d3 ac ac ac ac 62 62 62 62 91 91 91 91 95 95 95 95 e4 e4 e4 e4 79 79 79 79 e7 e7 e7 e7 c8 c8 c8 c8 37 37 37 37 6d 6d 6d 6d 8d 8d 8d 8d d5 d5 d5 d5 4e 4e 4e 4e a9 a9 a9 a9 6c 6c 6c 6c 56 56 56 56 f4 f4 f4 f4 ea ea ea ea 65 65 65 65 7a 7a 7a 7a ae ae ae ae 08 08 08 08 ba ba ba ba 78 78 78 78 25 25 25 25 2e 2e 2e 2e 1c 1c 1c 1c a6 a6 a6 a6 b4 b4 b4 b4 c6 c6 c6 c6 e8 e8 e8 e8 dd dd dd dd 74 74 74 74 1f 1f 1f 1f 4b 4b 4b 4b bd bd bd bd 8b 8b 8b 8b 8a 8a 8a 8a 70 70 70 70 3e 3e 3e 3e b5 b5 b5 b5 66 66 66 66 48 48 48 48 03 03 03 03 f6 f6 f6 f6 0e 0e 0e 0e 61 61 61 61 35 35 35 35 57 57 57 57 b9 b9 b9 b9 86 86 86 86 c1 c1 c1 c1 1d 1d 1d 1d 9e 9e 9e 9e e1 e1 e1 e1 f8 f8 f8 f8 98 98 98 98 11 11 11 11 69 69 69 69 d9 d9 d9 d9 8e 8e 8e 8e 94 94 94 94 9b 9b 9b 9b 1e 1e 1e 1e 87 87 87 87 e9 e9 e9 e9 ce ce ce ce 55 55 55 55 28 28 28 28 df df df df 8c 8c 8c 8c a1 a1 a1 a1 89 89 89 89 0d 0d 0d 0d bf bf bf bf e6 e6 e6 e6 42 42 42 42 68 68 68 68 41 41 41 41 99 99 99 99 2d 2d 2d 2d 0f 0f 0f 0f b0 b0 b0 b0 54 54 54 54 bb bb bb bb 16 16 16 16 }
    $aes_td0 = { 50 a7 f4 51 53 65 41 7e c3 a4 17 1a 96 5e 27 3a cb 6b ab 3b f1 45 9d 1f ab 58 fa ac 93 03 e3 4b 55 fa 30 20 f6 6d 76 ad 91 76 cc 88 25 4c 02 f5 fc d7 e5 4f d7 cb 2a c5 80 44 35 26 8f a3 62 b5 49 5a b1 de 67 1b ba 25 98 0e ea 45 e1 c0 fe 5d 02 75 2f c3 12 f0 4c 81 a3 97 46 8d c6 f9 d3 6b e7 5f 8f 03 95 9c 92 15 eb 7a 6d bf da 59 52 95 2d 83 be d4 d3 21 74 58 29 69 e0 49 44 c8 c9 8e 6a 89 c2 75 78 79 8e f4 6b 3e 58 99 dd 71 b9 27 b6 4f e1 be 17 ad 88 f0 66 ac 20 c9 b4 3a ce 7d 18 4a df 63 82 31 1a e5 60 33 51 97 45 7f 53 62 e0 77 64 b1 84 ae 6b bb 1c a0 81 fe 94 2b 08 f9 58 68 48 70 19 fd 45 8f 87 6c de 94 b7 f8 7b 52 23 d3 73 ab e2 02 4b 72 57 8f 1f e3 2a ab 55 66 07 28 eb b2 03 c2 b5 2f 9a 7b c5 86 a5 08 37 d3 f2 87 28 30 b2 a5 bf 23 ba 6a 03 02 5c 82 16 ed 2b 1c cf 8a 92 b4 79 a7 f0 f2 07 f3 a1 e2 69 4e cd f4 da 65 d5 be 05 06 1f 62 34 d1 8a fe a6 c4 9d 53 2e 34 a0 55 f3 a2 32 e1 8a 05 75 eb f6 a4 39 ec 83 0b aa ef 60 40 06 9f 71 5e 51 10 6e bd f9 8a 21 3e 3d 06 dd 96 ae 05 3e dd 46 bd e6 4d b5 8d 54 91 05 5d c4 71 6f d4 06 04 ff 15 50 60 24 fb 98 19 97 e9 bd d6 cc 43 40 89 77 9e d9 67 bd 42 e8 b0 88 8b 89 07 38 5b 19 e7 db ee c8 79 47 0a 7c a1 e9 0f 42 7c c9 1e 84 f8 00 00 00 00 83 86 80 09 48 ed 2b 32 ac 70 11 1e 4e 72 5a 6c fb ff 0e fd 56 38 85 0f 1e d5 ae 3d 27 39 2d 36 64 d9 0f 0a 21 a6 5c 68 d1 54 5b 9b 3a 2e 36 24 b1 67 0a 0c 0f e7 57 93 d2 96 ee b4 9e 91 9b 1b 4f c5 c0 80 a2 20 dc 61 69 4b 77 5a 16 1a 12 1c 0a ba 93 e2 e5 2a a0 c0 43 e0 22 3c 1d 17 1b 12 0b 0d 09 0e ad c7 8b f2 b9 a8 b6 2d c8 a9 1e 14 85 19 f1 57 4c 07 75 af bb dd 99 ee fd 60 7f a3 9f 26 01 f7 bc f5 72 5c c5 3b 66 44 34 7e fb 5b 76 29 43 8b dc c6 23 cb 68 fc ed b6 63 f1 e4 b8 ca dc 31 d7 10 85 63 42 40 22 97 13 20 11 c6 84 7d 24 4a 85 f8 3d bb d2 11 32 f9 ae 6d a1 29 c7 4b 2f 9e 1d f3 30 b2 dc ec 52 86 0d d0 e3 c1 77 6c 16 b3 2b 99 b9 70 a9 fa 48 94 11 22 64 e9 47 c4 8c fc a8 1a 3f f0 a0 d8 2c 7d 56 ef 90 33 22 c7 4e 49 87 c1 d1 38 d9 fe a2 ca 8c 36 0b d4 98 cf 81 f5 a6 28 de 7a a5 26 8e b7 da a4 bf ad 3f e4 9d 3a 2c 0d 92 78 50 9b cc 5f 6a 62 46 7e 54 c2 13 8d f6 e8 b8 d8 90 5e f7 39 2e f5 af c3 82 be 80 5d 9f 7c 93 d0 69 a9 2d d5 6f b3 12 25 cf 3b 99 ac c8 a7 7d 18 10 6e 63 9c e8 7b bb 3b db 09 78 26 cd f4 18 59 6e 01 b7 9a ec a8 9a 4f 83 65 6e 95 e6 7e e6 ff aa 08 cf bc 21 e6 e8 15 ef d9 9b e7 ba ce 36 6f 4a d4 09 9f ea d6 7c b0 29 af b2 a4 31 31 23 3f 2a 30 94 a5 c6 c0 66 a2 35 37 bc 4e 74 a6 ca 82 fc b0 d0 90 e0 15 d8 a7 33 4a 98 04 f1 f7 da ec 41 0e 50 cd 7f 2f f6 91 17 8d d6 4d 76 4d b0 ef 43 54 4d aa cc df 04 96 e4 e3 b5 d1 9e 1b 88 6a 4c b8 1f 2c c1 7f 51 65 46 04 ea 5e 9d 5d 35 8c 01 73 74 87 fa 2e 41 0b fb 5a 1d 67 b3 52 d2 db 92 33 56 10 e9 13 47 d6 6d 8c 61 d7 9a 7a 0c a1 37 8e 14 f8 59 89 3c 13 eb ee 27 a9 ce 35 c9 61 b7 ed e5 1c e1 3c b1 47 7a 59 df d2 9c 3f 73 f2 55 79 ce 14 18 bf 37 c7 73 ea cd f7 53 5b aa fd 5f 14 6f 3d df 86 db 44 78 81 f3 af ca 3e c4 68 b9 2c 34 24 38 5f 40 a3 c2 72 c3 1d 16 0c 25 e2 bc 8b 49 3c 28 41 95 0d ff 71 01 a8 39 de b3 0c 08 9c e4 b4 d8 90 c1 56 64 61 84 cb 7b 70 b6 32 d5 74 5c 6c 48 42 57 b8 d0 }
    $aes_td1 = { a7 f4 51 50 65 41 7e 53 a4 17 1a c3 5e 27 3a 96 6b ab 3b cb 45 9d 1f f1 58 fa ac ab 03 e3 4b 93 fa 30 20 55 6d 76 ad f6 76 cc 88 91 4c 02 f5 25 d7 e5 4f fc cb 2a c5 d7 44 35 26 80 a3 62 b5 8f 5a b1 de 49 1b ba 25 67 0e ea 45 98 c0 fe 5d e1 75 2f c3 02 f0 4c 81 12 97 46 8d a3 f9 d3 6b c6 5f 8f 03 e7 9c 92 15 95 7a 6d bf eb 59 52 95 da 83 be d4 2d 21 74 58 d3 69 e0 49 29 c8 c9 8e 44 89 c2 75 6a 79 8e f4 78 3e 58 99 6b 71 b9 27 dd 4f e1 be b6 ad 88 f0 17 ac 20 c9 66 3a ce 7d b4 4a df 63 18 31 1a e5 82 33 51 97 60 7f 53 62 45 77 64 b1 e0 ae 6b bb 84 a0 81 fe 1c 2b 08 f9 94 68 48 70 58 fd 45 8f 19 6c de 94 87 f8 7b 52 b7 d3 73 ab 23 02 4b 72 e2 8f 1f e3 57 ab 55 66 2a 28 eb b2 07 c2 b5 2f 03 7b c5 86 9a 08 37 d3 a5 87 28 30 f2 a5 bf 23 b2 6a 03 02 ba 82 16 ed 5c 1c cf 8a 2b b4 79 a7 92 f2 07 f3 f0 e2 69 4e a1 f4 da 65 cd be 05 06 d5 62 34 d1 1f fe a6 c4 8a 53 2e 34 9d 55 f3 a2 a0 e1 8a 05 32 eb f6 a4 75 ec 83 0b 39 ef 60 40 aa 9f 71 5e 06 10 6e bd 51 8a 21 3e f9 06 dd 96 3d 05 3e dd ae bd e6 4d 46 8d 54 91 b5 5d c4 71 05 d4 06 04 6f 15 50 60 ff fb 98 19 24 e9 bd d6 97 43 40 89 cc 9e d9 67 77 42 e8 b0 bd 8b 89 07 88 5b 19 e7 38 ee c8 79 db 0a 7c a1 47 0f 42 7c e9 1e 84 f8 c9 00 00 00 00 86 80 09 83 ed 2b 32 48 70 11 1e ac 72 5a 6c 4e ff 0e fd fb 38 85 0f 56 d5 ae 3d 1e 39 2d 36 27 d9 0f 0a 64 a6 5c 68 21 54 5b 9b d1 2e 36 24 3a 67 0a 0c b1 e7 57 93 0f 96 ee b4 d2 91 9b 1b 9e c5 c0 80 4f 20 dc 61 a2 4b 77 5a 69 1a 12 1c 16 ba 93 e2 0a 2a a0 c0 e5 e0 22 3c 43 17 1b 12 1d 0d 09 0e 0b c7 8b f2 ad a8 b6 2d b9 a9 1e 14 c8 19 f1 57 85 07 75 af 4c dd 99 ee bb 60 7f a3 fd 26 01 f7 9f f5 72 5c bc 3b 66 44 c5 7e fb 5b 34 29 43 8b 76 c6 23 cb dc fc ed b6 68 f1 e4 b8 63 dc 31 d7 ca 85 63 42 10 22 97 13 40 11 c6 84 20 24 4a 85 7d 3d bb d2 f8 32 f9 ae 11 a1 29 c7 6d 2f 9e 1d 4b 30 b2 dc f3 52 86 0d ec e3 c1 77 d0 16 b3 2b 6c b9 70 a9 99 48 94 11 fa 64 e9 47 22 8c fc a8 c4 3f f0 a0 1a 2c 7d 56 d8 90 33 22 ef 4e 49 87 c7 d1 38 d9 c1 a2 ca 8c fe 0b d4 98 36 81 f5 a6 cf de 7a a5 28 8e b7 da 26 bf ad 3f a4 9d 3a 2c e4 92 78 50 0d cc 5f 6a 9b 46 7e 54 62 13 8d f6 c2 b8 d8 90 e8 f7 39 2e 5e af c3 82 f5 80 5d 9f be 93 d0 69 7c 2d d5 6f a9 12 25 cf b3 99 ac c8 3b 7d 18 10 a7 63 9c e8 6e bb 3b db 7b 78 26 cd 09 18 59 6e f4 b7 9a ec 01 9a 4f 83 a8 6e 95 e6 65 e6 ff aa 7e cf bc 21 08 e8 15 ef e6 9b e7 ba d9 36 6f 4a ce 09 9f ea d4 7c b0 29 d6 b2 a4 31 af 23 3f 2a 31 94 a5 c6 30 66 a2 35 c0 bc 4e 74 37 ca 82 fc a6 d0 90 e0 b0 d8 a7 33 15 98 04 f1 4a da ec 41 f7 50 cd 7f 0e f6 91 17 2f d6 4d 76 8d b0 ef 43 4d 4d aa cc 54 04 96 e4 df b5 d1 9e e3 88 6a 4c 1b 1f 2c c1 b8 51 65 46 7f ea 5e 9d 04 35 8c 01 5d 74 87 fa 73 41 0b fb 2e 1d 67 b3 5a d2 db 92 52 56 10 e9 33 47 d6 6d 13 61 d7 9a 8c 0c a1 37 7a 14 f8 59 8e 3c 13 eb 89 27 a9 ce ee c9 61 b7 35 e5 1c e1 ed b1 47 7a 3c df d2 9c 59 73 f2 55 3f ce 14 18 79 37 c7 73 bf cd f7 53 ea aa fd 5f 5b 6f 3d df 14 db 44 78 86 f3 af ca 81 c4 68 b9 3e 34 24 38 2c 40 a3 c2 5f c3 1d 16 72 25 e2 bc 0c 49 3c 28 8b 95 0d ff 41 01 a8 39 71 b3 0c 08 de e4 b4 d8 9c c1 56 64 90 84 cb 7b 61 b6 32 d5 70 5c 6c 48 74 57 b8 d0 42 }
    $aes_td2 = { f4 51 50 a7 41 7e 53 65 17 1a c3 a4 27 3a 96 5e ab 3b cb 6b 9d 1f f1 45 fa ac ab 58 e3 4b 93 03 30 20 55 fa 76 ad f6 6d cc 88 91 76 02 f5 25 4c e5 4f fc d7 2a c5 d7 cb 35 26 80 44 62 b5 8f a3 b1 de 49 5a ba 25 67 1b ea 45 98 0e fe 5d e1 c0 2f c3 02 75 4c 81 12 f0 46 8d a3 97 d3 6b c6 f9 8f 03 e7 5f 92 15 95 9c 6d bf eb 7a 52 95 da 59 be d4 2d 83 74 58 d3 21 e0 49 29 69 c9 8e 44 c8 c2 75 6a 89 8e f4 78 79 58 99 6b 3e b9 27 dd 71 e1 be b6 4f 88 f0 17 ad 20 c9 66 ac ce 7d b4 3a df 63 18 4a 1a e5 82 31 51 97 60 33 53 62 45 7f 64 b1 e0 77 6b bb 84 ae 81 fe 1c a0 08 f9 94 2b 48 70 58 68 45 8f 19 fd de 94 87 6c 7b 52 b7 f8 73 ab 23 d3 4b 72 e2 02 1f e3 57 8f 55 66 2a ab eb b2 07 28 b5 2f 03 c2 c5 86 9a 7b 37 d3 a5 08 28 30 f2 87 bf 23 b2 a5 03 02 ba 6a 16 ed 5c 82 cf 8a 2b 1c 79 a7 92 b4 07 f3 f0 f2 69 4e a1 e2 da 65 cd f4 05 06 d5 be 34 d1 1f 62 a6 c4 8a fe 2e 34 9d 53 f3 a2 a0 55 8a 05 32 e1 f6 a4 75 eb 83 0b 39 ec 60 40 aa ef 71 5e 06 9f 6e bd 51 10 21 3e f9 8a dd 96 3d 06 3e dd ae 05 e6 4d 46 bd 54 91 b5 8d c4 71 05 5d 06 04 6f d4 50 60 ff 15 98 19 24 fb bd d6 97 e9 40 89 cc 43 d9 67 77 9e e8 b0 bd 42 89 07 88 8b 19 e7 38 5b c8 79 db ee 7c a1 47 0a 42 7c e9 0f 84 f8 c9 1e 00 00 00 00 80 09 83 86 2b 32 48 ed 11 1e ac 70 5a 6c 4e 72 0e fd fb ff 85 0f 56 38 ae 3d 1e d5 2d 36 27 39 0f 0a 64 d9 5c 68 21 a6 5b 9b d1 54 36 24 3a 2e 0a 0c b1 67 57 93 0f e7 ee b4 d2 96 9b 1b 9e 91 c0 80 4f c5 dc 61 a2 20 77 5a 69 4b 12 1c 16 1a 93 e2 0a ba a0 c0 e5 2a 22 3c 43 e0 1b 12 1d 17 09 0e 0b 0d 8b f2 ad c7 b6 2d b9 a8 1e 14 c8 a9 f1 57 85 19 75 af 4c 07 99 ee bb dd 7f a3 fd 60 01 f7 9f 26 72 5c bc f5 66 44 c5 3b fb 5b 34 7e 43 8b 76 29 23 cb dc c6 ed b6 68 fc e4 b8 63 f1 31 d7 ca dc 63 42 10 85 97 13 40 22 c6 84 20 11 4a 85 7d 24 bb d2 f8 3d f9 ae 11 32 29 c7 6d a1 9e 1d 4b 2f b2 dc f3 30 86 0d ec 52 c1 77 d0 e3 b3 2b 6c 16 70 a9 99 b9 94 11 fa 48 e9 47 22 64 fc a8 c4 8c f0 a0 1a 3f 7d 56 d8 2c 33 22 ef 90 49 87 c7 4e 38 d9 c1 d1 ca 8c fe a2 d4 98 36 0b f5 a6 cf 81 7a a5 28 de b7 da 26 8e ad 3f a4 bf 3a 2c e4 9d 78 50 0d 92 5f 6a 9b cc 7e 54 62 46 8d f6 c2 13 d8 90 e8 b8 39 2e 5e f7 c3 82 f5 af 5d 9f be 80 d0 69 7c 93 d5 6f a9 2d 25 cf b3 12 ac c8 3b 99 18 10 a7 7d 9c e8 6e 63 3b db 7b bb 26 cd 09 78 59 6e f4 18 9a ec 01 b7 4f 83 a8 9a 95 e6 65 6e ff aa 7e e6 bc 21 08 cf 15 ef e6 e8 e7 ba d9 9b 6f 4a ce 36 9f ea d4 09 b0 29 d6 7c a4 31 af b2 3f 2a 31 23 a5 c6 30 94 a2 35 c0 66 4e 74 37 bc 82 fc a6 ca 90 e0 b0 d0 a7 33 15 d8 04 f1 4a 98 ec 41 f7 da cd 7f 0e 50 91 17 2f f6 4d 76 8d d6 ef 43 4d b0 aa cc 54 4d 96 e4 df 04 d1 9e e3 b5 6a 4c 1b 88 2c c1 b8 1f 65 46 7f 51 5e 9d 04 ea 8c 01 5d 35 87 fa 73 74 0b fb 2e 41 67 b3 5a 1d db 92 52 d2 10 e9 33 56 d6 6d 13 47 d7 9a 8c 61 a1 37 7a 0c f8 59 8e 14 13 eb 89 3c a9 ce ee 27 61 b7 35 c9 1c e1 ed e5 47 7a 3c b1 d2 9c 59 df f2 55 3f 73 14 18 79 ce c7 73 bf 37 f7 53 ea cd fd 5f 5b aa 3d df 14 6f 44 78 86 db af ca 81 f3 68 b9 3e c4 24 38 2c 34 a3 c2 5f 40 1d 16 72 c3 e2 bc 0c 25 3c 28 8b 49 0d ff 41 95 a8 39 71 01 0c 08 de b3 b4 d8 9c e4 56 64 90 c1 cb 7b 61 84 32 d5 70 b6 6c 48 74 5c b8 d0 42 57 }
    $aes_td3 = { 51 50 a7 f4 7e 53 65 41 1a c3 a4 17 3a 96 5e 27 3b cb 6b ab 1f f1 45 9d ac ab 58 fa 4b 93 03 e3 20 55 fa 30 ad f6 6d 76 88 91 76 cc f5 25 4c 02 4f fc d7 e5 c5 d7 cb 2a 26 80 44 35 b5 8f a3 62 de 49 5a b1 25 67 1b ba 45 98 0e ea 5d e1 c0 fe c3 02 75 2f 81 12 f0 4c 8d a3 97 46 6b c6 f9 d3 03 e7 5f 8f 15 95 9c 92 bf eb 7a 6d 95 da 59 52 d4 2d 83 be 58 d3 21 74 49 29 69 e0 8e 44 c8 c9 75 6a 89 c2 f4 78 79 8e 99 6b 3e 58 27 dd 71 b9 be b6 4f e1 f0 17 ad 88 c9 66 ac 20 7d b4 3a ce 63 18 4a df e5 82 31 1a 97 60 33 51 62 45 7f 53 b1 e0 77 64 bb 84 ae 6b fe 1c a0 81 f9 94 2b 08 70 58 68 48 8f 19 fd 45 94 87 6c de 52 b7 f8 7b ab 23 d3 73 72 e2 02 4b e3 57 8f 1f 66 2a ab 55 b2 07 28 eb 2f 03 c2 b5 86 9a 7b c5 d3 a5 08 37 30 f2 87 28 23 b2 a5 bf 02 ba 6a 03 ed 5c 82 16 8a 2b 1c cf a7 92 b4 79 f3 f0 f2 07 4e a1 e2 69 65 cd f4 da 06 d5 be 05 d1 1f 62 34 c4 8a fe a6 34 9d 53 2e a2 a0 55 f3 05 32 e1 8a a4 75 eb f6 0b 39 ec 83 40 aa ef 60 5e 06 9f 71 bd 51 10 6e 3e f9 8a 21 96 3d 06 dd dd ae 05 3e 4d 46 bd e6 91 b5 8d 54 71 05 5d c4 04 6f d4 06 60 ff 15 50 19 24 fb 98 d6 97 e9 bd 89 cc 43 40 67 77 9e d9 b0 bd 42 e8 07 88 8b 89 e7 38 5b 19 79 db ee c8 a1 47 0a 7c 7c e9 0f 42 f8 c9 1e 84 00 00 00 00 09 83 86 80 32 48 ed 2b 1e ac 70 11 6c 4e 72 5a fd fb ff 0e 0f 56 38 85 3d 1e d5 ae 36 27 39 2d 0a 64 d9 0f 68 21 a6 5c 9b d1 54 5b 24 3a 2e 36 0c b1 67 0a 93 0f e7 57 b4 d2 96 ee 1b 9e 91 9b 80 4f c5 c0 61 a2 20 dc 5a 69 4b 77 1c 16 1a 12 e2 0a ba 93 c0 e5 2a a0 3c 43 e0 22 12 1d 17 1b 0e 0b 0d 09 f2 ad c7 8b 2d b9 a8 b6 14 c8 a9 1e 57 85 19 f1 af 4c 07 75 ee bb dd 99 a3 fd 60 7f f7 9f 26 01 5c bc f5 72 44 c5 3b 66 5b 34 7e fb 8b 76 29 43 cb dc c6 23 b6 68 fc ed b8 63 f1 e4 d7 ca dc 31 42 10 85 63 13 40 22 97 84 20 11 c6 85 7d 24 4a d2 f8 3d bb ae 11 32 f9 c7 6d a1 29 1d 4b 2f 9e dc f3 30 b2 0d ec 52 86 77 d0 e3 c1 2b 6c 16 b3 a9 99 b9 70 11 fa 48 94 47 22 64 e9 a8 c4 8c fc a0 1a 3f f0 56 d8 2c 7d 22 ef 90 33 87 c7 4e 49 d9 c1 d1 38 8c fe a2 ca 98 36 0b d4 a6 cf 81 f5 a5 28 de 7a da 26 8e b7 3f a4 bf ad 2c e4 9d 3a 50 0d 92 78 6a 9b cc 5f 54 62 46 7e f6 c2 13 8d 90 e8 b8 d8 2e 5e f7 39 82 f5 af c3 9f be 80 5d 69 7c 93 d0 6f a9 2d d5 cf b3 12 25 c8 3b 99 ac 10 a7 7d 18 e8 6e 63 9c db 7b bb 3b cd 09 78 26 6e f4 18 59 ec 01 b7 9a 83 a8 9a 4f e6 65 6e 95 aa 7e e6 ff 21 08 cf bc ef e6 e8 15 ba d9 9b e7 4a ce 36 6f ea d4 09 9f 29 d6 7c b0 31 af b2 a4 2a 31 23 3f c6 30 94 a5 35 c0 66 a2 74 37 bc 4e fc a6 ca 82 e0 b0 d0 90 33 15 d8 a7 f1 4a 98 04 41 f7 da ec 7f 0e 50 cd 17 2f f6 91 76 8d d6 4d 43 4d b0 ef cc 54 4d aa e4 df 04 96 9e e3 b5 d1 4c 1b 88 6a c1 b8 1f 2c 46 7f 51 65 9d 04 ea 5e 01 5d 35 8c fa 73 74 87 fb 2e 41 0b b3 5a 1d 67 92 52 d2 db e9 33 56 10 6d 13 47 d6 9a 8c 61 d7 37 7a 0c a1 59 8e 14 f8 eb 89 3c 13 ce ee 27 a9 b7 35 c9 61 e1 ed e5 1c 7a 3c b1 47 9c 59 df d2 55 3f 73 f2 18 79 ce 14 73 bf 37 c7 53 ea cd f7 5f 5b aa fd df 14 6f 3d 78 86 db 44 ca 81 f3 af b9 3e c4 68 38 2c 34 24 c2 5f 40 a3 16 72 c3 1d bc 0c 25 e2 28 8b 49 3c ff 41 95 0d 39 71 01 a8 08 de b3 0c d8 9c e4 b4 64 90 c1 56 7b 61 84 cb d5 70 b6 32 48 74 5c 6c d0 42 57 b8 }
    $aes_td4 = { 52 52 52 52 09 09 09 09 6a 6a 6a 6a d5 d5 d5 d5 30 30 30 30 36 36 36 36 a5 a5 a5 a5 38 38 38 38 bf bf bf bf 40 40 40 40 a3 a3 a3 a3 9e 9e 9e 9e 81 81 81 81 f3 f3 f3 f3 d7 d7 d7 d7 fb fb fb fb 7c 7c 7c 7c e3 e3 e3 e3 39 39 39 39 82 82 82 82 9b 9b 9b 9b 2f 2f 2f 2f ff ff ff ff 87 87 87 87 34 34 34 34 8e 8e 8e 8e 43 43 43 43 44 44 44 44 c4 c4 c4 c4 de de de de e9 e9 e9 e9 cb cb cb cb 54 54 54 54 7b 7b 7b 7b 94 94 94 94 32 32 32 32 a6 a6 a6 a6 c2 c2 c2 c2 23 23 23 23 3d 3d 3d 3d ee ee ee ee 4c 4c 4c 4c 95 95 95 95 0b 0b 0b 0b 42 42 42 42 fa fa fa fa c3 c3 c3 c3 4e 4e 4e 4e 08 08 08 08 2e 2e 2e 2e a1 a1 a1 a1 66 66 66 66 28 28 28 28 d9 d9 d9 d9 24 24 24 24 b2 b2 b2 b2 76 76 76 76 5b 5b 5b 5b a2 a2 a2 a2 49 49 49 49 6d 6d 6d 6d 8b 8b 8b 8b d1 d1 d1 d1 25 25 25 25 72 72 72 72 f8 f8 f8 f8 f6 f6 f6 f6 64 64 64 64 86 86 86 86 68 68 68 68 98 98 98 98 16 16 16 16 d4 d4 d4 d4 a4 a4 a4 a4 5c 5c 5c 5c cc cc cc cc 5d 5d 5d 5d 65 65 65 65 b6 b6 b6 b6 92 92 92 92 6c 6c 6c 6c 70 70 70 70 48 48 48 48 50 50 50 50 fd fd fd fd ed ed ed ed b9 b9 b9 b9 da da da da 5e 5e 5e 5e 15 15 15 15 46 46 46 46 57 57 57 57 a7 a7 a7 a7 8d 8d 8d 8d 9d 9d 9d 9d 84 84 84 84 90 90 90 90 d8 d8 d8 d8 ab ab ab ab 00 00 00 00 8c 8c 8c 8c bc bc bc bc d3 d3 d3 d3 0a 0a 0a 0a f7 f7 f7 f7 e4 e4 e4 e4 58 58 58 58 05 05 05 05 b8 b8 b8 b8 b3 b3 b3 b3 45 45 45 45 06 06 06 06 d0 d0 d0 d0 2c 2c 2c 2c 1e 1e 1e 1e 8f 8f 8f 8f ca ca ca ca 3f 3f 3f 3f 0f 0f 0f 0f 02 02 02 02 c1 c1 c1 c1 af af af af bd bd bd bd 03 03 03 03 01 01 01 01 13 13 13 13 8a 8a 8a 8a 6b 6b 6b 6b 3a 3a 3a 3a 91 91 91 91 11 11 11 11 41 41 41 41 4f 4f 4f 4f 67 67 67 67 dc dc dc dc ea ea ea ea 97 97 97 97 f2 f2 f2 f2 cf cf cf cf ce ce ce ce f0 f0 f0 f0 b4 b4 b4 b4 e6 e6 e6 e6 73 73 73 73 96 96 96 96 ac ac ac ac 74 74 74 74 22 22 22 22 e7 e7 e7 e7 ad ad ad ad 35 35 35 35 85 85 85 85 e2 e2 e2 e2 f9 f9 f9 f9 37 37 37 37 e8 e8 e8 e8 1c 1c 1c 1c 75 75 75 75 df df df df 6e 6e 6e 6e 47 47 47 47 f1 f1 f1 f1 1a 1a 1a 1a 71 71 71 71 1d 1d 1d 1d 29 29 29 29 c5 c5 c5 c5 89 89 89 89 6f 6f 6f 6f b7 b7 b7 b7 62 62 62 62 0e 0e 0e 0e aa aa aa aa 18 18 18 18 be be be be 1b 1b 1b 1b fc fc fc fc 56 56 56 56 3e 3e 3e 3e 4b 4b 4b 4b c6 c6 c6 c6 d2 d2 d2 d2 79 79 79 79 20 20 20 20 9a 9a 9a 9a db db db db c0 c0 c0 c0 fe fe fe fe 78 78 78 78 cd cd cd cd 5a 5a 5a 5a f4 f4 f4 f4 1f 1f 1f 1f dd dd dd dd a8 a8 a8 a8 33 33 33 33 88 88 88 88 07 07 07 07 c7 c7 c7 c7 31 31 31 31 b1 b1 b1 b1 12 12 12 12 10 10 10 10 59 59 59 59 27 27 27 27 80 80 80 80 ec ec ec ec 5f 5f 5f 5f 60 60 60 60 51 51 51 51 7f 7f 7f 7f a9 a9 a9 a9 19 19 19 19 b5 b5 b5 b5 4a 4a 4a 4a 0d 0d 0d 0d 2d 2d 2d 2d e5 e5 e5 e5 7a 7a 7a 7a 9f 9f 9f 9f 93 93 93 93 c9 c9 c9 c9 9c 9c 9c 9c ef ef ef ef a0 a0 a0 a0 e0 e0 e0 e0 3b 3b 3b 3b 4d 4d 4d 4d ae ae ae ae 2a 2a 2a 2a f5 f5 f5 f5 b0 b0 b0 b0 c8 c8 c8 c8 eb eb eb eb bb bb bb bb 3c 3c 3c 3c 83 83 83 83 53 53 53 53 99 99 99 99 61 61 61 61 17 17 17 17 2b 2b 2b 2b 04 04 04 04 7e 7e 7e 7e ba ba ba ba 77 77 77 77 d6 d6 d6 d6 26 26 26 26 e1 e1 e1 e1 69 69 69 69 14 14 14 14 63 63 63 63 55 55 55 55 21 21 21 21 0c 0c 0c 0c 7d 7d 7d 7d }
  condition:
    any of them
}

rule Borland
{
      meta:
		author="malware-lu"
	strings:
		$patternBorland = "Borland" wide ascii
	condition:
		$patternBorland
}

rule MAL_Neshta_Generic : HIGHVOL {
   meta:
      description = "Detects Neshta malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-01-15"
      modified = "2021-04-14"
      hash1 = "27c67eb1378c2fd054c6649f92ec8ee9bfcb6f790224036c974f6c883c46f586"
      hash1 = "0283c0f02307adc4ee46c0382df4b5d7b4eb80114fbaf5cb7fe5412f027d165e"
      hash2 = "b7f8233dafab45e3abbbb4f3cc76e6860fae8d5337fb0b750ea20058b56b0efb"
      hash3 = "1954e06fc952a5a0328774aaf07c23970efd16834654793076c061dffb09a7eb"
      id = "9a3b8369-7e19-5c21-9eba-0bb81507696a"
   strings:
      $x1 = "the best. Fuck off all the rest."
      $x2 = "! Best regards 2 Tommy Salo. [Nov-2005] yours [Dziadulja Apanas]" fullword ascii
      $s1 = "Neshta" ascii fullword
      $s2 = "Made in Belarus. " ascii fullword
      $op1 = { 85 c0 93 0f 85 62 ff ff ff 5e 5b 89 ec 5d c2 04 }
      $op2 = { e8 e5 f1 ff ff 8b c3 e8 c6 ff ff ff 85 c0 75 0c }
      $op3 = { eb 02 33 db 8b c3 5b c3 53 85 c0 74 15 ff 15 34 }
      $sop1 = { e8 3c 2a ff ff b8 ff ff ff 7f eb 3e 83 7d 0c 00 }
      $sop2 = { 2b c7 50 e8 a4 40 ff ff ff b6 88 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 3000KB and (
         1 of ($x*) or 
         all of ($s*) or 
         3 of them or 
         pe.imphash() == "9f4693fc0c511135129493f2161d1e86"
      )
}rule MAL_EXE_LockBit_v2
{
	meta:
		author = "Silas Cutler, modified by Florian Roth"
		description = "Detection for LockBit version 2.x from 2011"
		date = "2023-01-01"
      modified = "2023-01-06"
		version = "1.0"
      score = 80
		hash = "00260c390ffab5734208a7199df0e4229a76261c3f5b7264c4515acb8eb9c2f8"
		DaysofYARA = "1/100"
		id = "a2c27110-e63b-5f93-88a0-98c12811e8b4"
	strings:
		$s01 = "that is located in every encrypted folder." wide
		$s02 = "Would you like to earn millions of dollars?" wide
		$x = "3085B89A0C515D2FB124D645906F5D3DA5CB97CEBEA975959AE4F95302A04E1D709C3C4AE9B7" wide
		$x_ransom_url = "http://lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion" wide
		$str1 = "Active:[ %d [                  Completed:[ %d" wide
		$str2 = "\\LockBit_Ransomware.hta" wide ascii
		$s_str2 = "Ransomware.hta" wide ascii
	condition:
		uint16(0) == 0x5A4D and ( 1 of ($x*) or 2 of them ) or 3 of them
}

rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_DisableWinDefender {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding registry key / value combination indicative of disabling Windows Defender features"
        score = 60
    strings:
        $r1 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" ascii wide nocase
        $k1 = "DisableAntiSpyware" ascii wide
        $r2 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" ascii wide nocase
        $k2 = "DisableBehaviorMonitoring" ascii wide
        $k3 = "DisableOnAccessProtection" ascii wide
        $k4 = "DisableScanOnRealtimeEnable" ascii wide
        $r3 = "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection" ascii wide nocase
        $k5 = "vDisableRealtimeMonitoring" ascii wide
        $r4 = "SOFTWARE\\Microsoft\\Windows Defender\\Spynet" ascii wide nocase
        $k6 = "SpyNetReporting" ascii wide
        $k7 = "SubmitSamplesConsent" ascii wide
        $r5 = "SOFTWARE\\Microsoft\\Windows Defender\\Features" ascii wide nocase
        $k8 = "TamperProtection" ascii wide
        $r6 = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths" ascii wide nocase
        $k9 = "Add-MpPreference -ExclusionPath \"{0}\"" ascii wide
    condition:
        uint16(0) == 0x5a4d and (1 of ($r*) and 1 of ($k*))
}

rule DebuggerHiding__Thread : AntiDebug DebuggerHiding {
	meta:
	    Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
		weight = 1
	strings:
		$ ="SetInformationThread"
	condition:
		any of them
}

rule INDICATOR_SUSPICIOUS_USNDeleteJournal {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing anti-forensic artifacts of deleting USN change journal. Observed in ransomware"
        score = 60
    strings:
        $cmd1 = "fsutil.exe" ascii wide nocase
        $s1 = "usn deletejournal /D C:" ascii wide nocase
        $s2 = "fsutil.exe usn deletejournal" ascii wide nocase
        $s3 = "fsutil usn deletejournal" ascii wide nocase
        $s4 = "fsutil file setZeroData offset=0" ascii wide nocase
        $ne1 = "fsutil usn readdata C:\\Temp\\sample.txt" wide
        $ne2 = "fsutil transaction query {0f2d8905-6153-449a-8e03-7d3a38187ba1}" wide
        $ne3 = "fsutil resource start d:\\foobar d:\\foobar\\LogDir\\LogBLF::TxfLog d:\\foobar\\LogDir\\LogBLF::TmLog" wide
        $ne4 = "fsutil objectid query C:\\Temp\\sample.txt" wide
    condition:
        uint16(0) == 0x5a4d and (not any of ($ne*) and ((1 of ($cmd*) and 1 of ($s*)) or 1 of ($s*)))
}


rule maldoc_find_kernel32_base_method_1 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {64 8B (05|0D|15|1D|25|2D|35|3D) 30 00 00 00}
        $a2 = {64 A1 30 00 00 00}
    condition:
        any of them
}

rule MAL_RANSOM_Darkside_May21_1 {
   meta:
      description = "Detects Darkside Ransomware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://app.any.run/tasks/020c1740-717a-4191-8917-5819aa25f385/"
      date = "2021-05-10"
      hash1 = "ec368752c2cf3b23efbfa5705f9e582fc9d6766435a7b8eea8ef045082c6fbce"
      id = "e5592065-591e-597b-bebb-f20bc306fe52"
   strings:
      $op1 = { 85 c9 75 ed ff 75 10 ff b5 d8 fe ff ff ff b5 dc fe ff ff e8 7d fc ff ff ff 8d cc fe ff ff 8b 8d cc fe ff ff }
      $op2 = { 66 0f 6f 06 66 0f 7f 07 83 c6 10 83 c7 10 49 85 c9 75 ed 5f }
      $op3 = { 6a 00 ff 15 72 0d 41 00 ab 46 81 fe 80 00 00 00 75 2e 6a ff 6a 01 }
      $op4 = { 0f b7 0c 5d 88 0f 41 00 03 4c 24 04 89 4c 24 04 83 e1 3f 0f b7 14 4d 88 0f 41 00 03 54 24 08 89 54 24 08 83 e2 3f }
      $s1 = "http://darksid" ascii
      $s2 = "[ Welcome to DarkSide ]" ascii
      $s3 = ".onion/" ascii
   condition:
      uint16(0) == 0x5a4d and
      filesize < 200KB and
      3 of them or all of ($op*) or all of ($s*)
}

rule Unspecified_Malware_Sep1_A1 {
   meta:
      description = "Detects malware from DrqgonFly APT report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
      date = "2017-09-12"
      hash1 = "28143c7638f22342bff8edcd0bedd708e265948a5fcca750c302e2dca95ed9f0"
      id = "cff49e85-c8c3-5240-9948-0551e38e7040"
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 200KB and
        pe.imphash() == "17a4bd9c95f2898add97f309fc6f9bcd"
      )
}

rule suspicious_packer_section : packer PE {
    meta:
        author = "@j0sm1"
        date = "2016/10/21"
        description = "The packer/protector section names/keywords"
        reference = "http://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/"
        filetype = "binary"
    strings:
        $s1 = ".aspack" wide ascii
        $s2 = ".adata" wide ascii
        $s3 = "ASPack" wide ascii
        $s4 = ".ASPack" wide ascii
        $s5 = ".ccg" wide ascii
        $s6 = "BitArts" wide ascii
        $s7 = "DAStub" wide ascii
        $s8 = "!EPack" wide ascii
        $s9 = "FSG!" wide ascii
        $s10 = "kkrunchy" wide ascii
        $s11 = ".mackt" wide ascii
        $s12 = ".MaskPE" wide ascii
        $s13 = "MEW" wide ascii
        $s14 = ".MPRESS1" wide ascii
        $s15 = ".MPRESS2" wide ascii
        $s16 = ".neolite" wide ascii
        $s17 = ".neolit" wide ascii
        $s18 = ".nsp1" wide ascii
        $s19 = ".nsp2" wide ascii
        $s20 = ".nsp0" wide ascii
        $s21 = "nsp0" wide ascii
        $s22 = "nsp1" wide ascii
        $s23 = "nsp2" wide ascii
        $s24 = ".packed" wide ascii
        $s25 = "pebundle" wide ascii
        $s26 = "PEBundle" wide ascii
        $s27 = "PEC2TO" wide ascii
        $s28 = "PECompact2" wide ascii
        $s29 = "PEC2" wide ascii
        $s30 = "pec1" wide ascii
        $s31 = "pec2" wide ascii
        $s32 = "PEC2MO" wide ascii
        $s33 = "PELOCKnt" wide ascii
        $s34 = ".perplex" wide ascii
        $s35 = "PESHiELD" wide ascii
        $s36 = ".petite" wide ascii
        $s37 = "ProCrypt" wide ascii
        $s38 = ".RLPack" wide ascii
        $s39 = "RCryptor" wide ascii
        $s40 = ".RPCrypt" wide ascii
        $s41 = ".sforce3" wide ascii
        $s42 = ".spack" wide ascii
        $s43 = ".svkp" wide ascii
        $s44 = "Themida" wide ascii
        $s45 = ".Themida" wide ascii
        $s46 = ".packed" wide ascii
        $s47 = ".Upack" wide ascii
        $s48 = ".ByDwing" wide ascii
        $s49 = "UPX0" wide ascii
        $s50 = "UPX1" wide ascii
        $s51 = "UPX2" wide ascii
        $s52 = ".UPX0" wide ascii
        $s53 = ".UPX1" wide ascii
        $s54 = ".UPX2" wide ascii
        $s55 = ".vmp0" wide ascii
        $s56 = ".vmp1" wide ascii
        $s57 = ".vmp2" wide ascii
        $s58 = "VProtect" wide ascii
        $s59 = "WinLicen" wide ascii
        $s60 = "WWPACK" wide ascii
        $s61 = ".yP" wide ascii
        $s62 = ".y0da" wide ascii
        $s63 = "UPX!" wide ascii
    condition:
        uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (
            for any of them : ( $ in (0..1024) )
        )
}

rule url{
   meta:
      descritpion = "Detects URL http://www.upx.sourceforge.net"
   strings:
      $a = "upx.sourceforge.net"
   condition:
      any of them
}
rule SEH_Init : Tactic_DefensiveEvasion Technique_AntiDebugging SubTechnique_SEH
{
    meta:
        author = "Malware Utkonos"
        original_author = "naxonez"
        source = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
    strings:
        $a = { 64 A3 00 00 00 00 }
        $b = { 64 89 25 00 00 00 00 }
    condition:
        $a or $b
}

rule IceID_Bank_trojan {
	meta:
		description = "Detects IcedID..adjusted several times"
		author = "unixfreaxjp"
		org = "MalwareMustDie"
		date = "2018-01-14"
	strings:
		$header = { 4D 5A }
		$magic1 = { E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 6A ?? 68 ?? ?? }
		$st01 = "CCmdTarget" fullword nocase wide ascii
		$st02 = "CUserException" fullword nocase wide ascii
		$st03 = "FileType" fullword nocase wide ascii
		$st04 = "FlsGetValue" fullword nocase wide ascii
		$st05 = "AVCShellWrapper@@" fullword nocase wide ascii
		$st06 = "AVCCmdTarget@@" fullword nocase wide ascii
		$st07 = "AUCThreadData@@" fullword nocase wide ascii
		$st08 = "AVCUserException@@" fullword nocase wide ascii
	condition:
		$header at 0 and all of ($magic*) and 6 of ($st0*)
		and pe.sections[0].name contains ".text"
		and pe.sections[1].name contains ".rdata"
		and pe.sections[2].name contains ".data"
		and pe.sections[3].name contains ".rsrc"
		and pe.characteristics & pe.EXECUTABLE_IMAGE
		and pe.characteristics & pe.RELOCS_STRIPPED
}

rule RAN_Conti_May_2021_2 {
   meta:
        description = "Detect unpacked Conti ransomware (May 2021)"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-05-20"
        hash1 = "Redacted"
        hash2 = "a5751a46768149c5ddf318fd75afc66b3db28a5b76254ee0d6ae27b21712e266"
        hash3 = "74b7a1da50ce44b640d84422bb3f99e2f338cc5d5be9ef5f1ad03c8e947296c3"
        hash4 = "ef2cd9ded5532af231e0990feaf2df8fd79dc63f7a677192e17b89ef4adb7dd2"
   strings:      
        $seq1 = { 33 db 3c 2f 74 0a 3c 5c 74 06 3c 3a 8a c3 75 02 b0 01 2b cf 0f b6 c0 41 89 9d 68 fd ff ff f7 d8 89 9d 6c fd ff ff 56 1b c0 89 9d 70 fd ff ff 23 c1 89 9d 74 fd ff ff 89 85 88 fd ff ff 89 9d 78 fd ff ff 88 9d 7c fd ff ff e8 [4] 50 8d 85 68 fd ff ff 50 57 e8 68 fc ff ff 83 c4 0c 8d 8d ac fd ff ff f7 d8 1b c0 53 53 53 51 f7 d0 23 85 70 fd ff ff 53 50 ff 15 [4] 8b f0 83 fe ff 75 18 ff b5 a4 fd ff ff 53 53 57 e8 42 fe ff ff 83 c4 10 8b d8 e9 1c 01 00 00 8b 85 a4 fd ff ff 8b 48 04 2b 08 c1 f9 02 89 8d 84 fd ff ff 89 9d 8c fd ff ff 89 9d 90 fd ff ff 89 9d 94 fd ff ff 89 9d 98 fd ff ff 89 9d 9c fd ff ff 88 9d a0 fd ff ff e8 [4] 50 8d 85 ab fd ff ff 50 8d 85 8c fd ff ff 50 8d 85 d8 fd ff ff 50 e8 01 fb ff ff 83 c4 10 f7 d8 1b c0 f7 d0 23 85 94 fd ff ff 80 }
        $seq2 = { 38 9d a0 fd ff ff 74 0c ff b5 94 fd ff ff e8 [2] ff ff 59 8d 85 ac fd ff ff 50 56 ff 15 [4] 85 c0 0f 85 4d ff ff ff 8b 85 a4 fd ff ff 8b 8d 84 fd ff ff 8b 10 8b 40 04 2b c2 c1 f8 02 3b c8 74 34 68 [4] 2b c1 6a 04 50 8d 04 8a 50 e8 [2] 00 00 83 c4 10 eb 1c 38 9d a0 fd ff ff 74 12 ff b5 94 fd ff ff e8 [2] ff ff 8b 85 80 fd ff ff 59 8b d8 56 ff 15 [4] 80 bd 7c fd ff ff 00 5e 74 0c ff b5 70 fd ff ff e8 [2] ff ff 59 8b }
        $seq3 = { 6a 0c 68 [4] e8 [2] ff ff 33 f6 89 75 e4 8b 45 08 ff 30 e8 [2] ff ff 59 89 75 fc 8b 45 0c 8b 00 8b 38 8b d7 c1 fa 06 8b c7 83 e0 3f 6b c8 38 8b 04 95 [4] f6 44 08 28 01 74 21 57 e8 [2] ff ff 59 50 ff 15 [4] 85 c0 75 1d e8 [2] ff ff 8b f0 ff 15 [4] 89 06 e8 [2] ff ff c7 00 09 00 00 00 83 ce ff 89 75 e4 c7 45 fc fe ff ff ff e8 0d 00 00 00 8b c6 e8 [2] ff }
        $seq4 = { 8b ff 55 8b ec 56 6a 00 ff 75 10 ff 75 0c ff 75 08 ff 35 [4] ff 15 [4] 8b f0 85 f6 75 2d ff 15 [4] 83 f8 06 75 22 e8 b6 ff ff ff e8 73 ff ff ff 56 ff 75 10 ff 75 0c ff 75 08 ff 35 [4] ff 15 [4] 8b f0 8b c6 5e }
        $seq5 = { 55 8b ec 81 ec b4 09 00 00 a1 08 [3] 33 c5 89 45 fc 53 56 57 6a ?? 68 [4] ba 18 00 00 00 33 c9 e8 [2] ff ff 83 c4 08 6a 00 6a 00 ff d0 8b f0 85 f6 0f 88 9a 03 00 00 c7 85 8c f7 ff ff [3] 00 bb 03 00 00 00 8b 85 8c f7 ff ff 99 f7 fb 8b 85 8c f7 ff ff 8d 7b 02 85 d2 74 57 83 c0 02 03 c6 89 85 8c f7 ff ff 8b 85 8c f7 ff ff 25 03 00 00 80 79 07 48 83 c8 fc 83 c0 01 0f 85 64 01 00 00 66 66 0f 1f 84 00 00 00 00 00 8b 85 8c f7 ff ff 40 89 85 8c f7 ff ff 8b 85 8c f7 ff ff 25 03 00 00 80 79 07 48 83 c8 fc 83 c0 01 74 dd e9 32 01 00 00 25 01 00 00 80 79 07 48 83 c8 fe 83 c0 01 74 47 b8 02 00 00 00 2b }
        $seq6 = { 83 3b 00 c7 45 94 00 00 00 00 0f 86 57 02 00 00 8b 35 b4 21 41 00 8d 4b 14 8b 3d c8 21 41 00 8b 1d 9c 21 41 00 89 4d 90 c7 45 98 7f 00 00 00 89 b5 7c ff ff ff 89 bd 78 ff ff ff 89 5d 9c 0f 1f 40 00 8b 11 8d 45 d0 89 55 cc b9 2c 00 00 00 0f 1f 00 c6 00 00 8d 40 01 83 e9 01 75 f5 52 ff d6 8b f0 ff d7 c6 45 b4 00 bf 7f 00 00 00 c6 45 b5 42 c6 45 b6 31 c6 45 b7 2a c6 45 b8 0b c6 45 b9 63 8a 4d b5 80 7d b4 00 75 28 33 c9 66 0f 1f 44 00 00 8a 44 0d b5 0f b6 c0 83 e8 63 6b c0 25 99 f7 ff 8d 42 7f 99 f7 ff 88 54 0d b5 41 83 f9 05 72 e0 8d 45 b5 50 56 ff d3 c6 45 a0 00 c6 45 a1 51 c6 45 a2 1f c6 45 a3 2b c6 45 a4 44 c6 45 a5 51 c6 45 a6 12 c6 45 a7 45 c6 45 a8 44 c6 45 a9 26 89 45 84 8a 45 a1 80 7d a0 00 75 27 33 c9 0f 1f 00 8a 44 0d a1 0f b6 c0 83 e8 26 8d 04 80 03 c0 99 f7 ff 8d 42 7f 99 f7 ff 88 54 0d a1 41 83 f9 09 72 de 8d 45 a1 50 56 ff d3 c6 45 bc 00 8b d8 c6 45 bd 42 c6 45 be 19 c6 45 bf 46 c6 45 c0 59 8a 4d bd 80 7d bc 00 89 5d 88 75 2c 33 ff 8d 5f 7f 8a 44 3d bd 0f b6 c8 83 e9 59 8b c1 c1 e0 05 2b c1 99 f7 fb 8d 42 7f 99 f7 fb 88 54 3d bd 47 83 ff 04 72 dc 8b 5d 88 8d 45 bd 50 56 ff 55 9c c6 45 ac 00 8b f8 c6 45 ad 76 c6 45 ae 30 c6 45 af 06 c6 45 b0 21 c6 45 b1 2a 8a 4d ad 80 7d ac 00 75 24 33 c9 8a 44 0d ad 0f b6 c0 83 e8 2a 8d 04 c0 99 f7 7d 98 8d 42 7f 99 f7 7d 98 88 54 0d ad 41 83 f9 05 72 de 8d 45 ad 50 56 ff 55 9c }
    condition:
         uint16(0) == 0x5a4d and filesize > 50KB and 5 of ($seq*) 
}

rule RSA_pubKey_constants {
	meta:
        author = "OPSWAT"
        description = "Bytes related to public RSA key references"
		//b7b5e1253710d8927cbe07d52d2d2e10.exe_
		//data-manipulation/encryption/rsa/reference-public-rsa-key.yml
	strings:
		$st0 = {52 53 41 31 00 08 00 00} // RSA1 bitlen 1024
		$st1 = {52 53 41 31 00 04 00 00} // RSA1 bitlen 2048
		$st2 = {52 53 41 31 00 10 00 00} // RSA1 bitlen 4096
		$pubkblob = {06 02 00 00 00 A4 00 00 52 53 41 31}
	condition:
		any of ($st*) and $pubkblob
}

rule ransom_conti {
   meta:
      description = "Conti ransomware is havnig capability too scan and encrypt oover the network"
      author = "McAfee ATR team"
      reference = "https://www.carbonblack.com/blog/tau-threat-discovery-conti-ransomware/"
      date = "2020-07-09"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Conti"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash = "eae876886f19ba384f55778634a35a1d975414e83f22f6111e3e792f706301fe"
   strings:
      $string1 = "HOW_TO_DECRYPTP" fullword ascii
      $string2 = "The system is LOCKED." fullword ascii
      $string3 = "The network is LOCKED." fullword ascii
      $code1 = { ff b4 b5 48 ff ff ff 53 ff 15 bc b0 41 00 85 c0 }
      $code2 = { 6a 02 6a 00 6a ff 68 ec fd ff ff ff 76 0c ff 15 }
      $code3 = { 56 8d 85 38 ff ff ff 50 ff d7 85 c0 0f 84 f2 01 }
   condition:
      uint16(0) == 0x5a4d and 
      filesize < 300KB and 
      pe.number_of_sections == 5 and
      ( pe.imphash() == "30fe3f044289487cddc09bfb16ee1fde" or 
      ( all of them and
      all of ($code*) ) )
}




rule suspicious_obfuscation_toString {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation toString"
		mitre = "T1027"
	strings:
		$h_raw1 = "toString(" nocase
	condition: filesize < 1MB and any of them
}

rule suspicious_obfuscation_using_substr {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation using substr"
		mitre = "T1027"
	strings:
		$h_raw1 = "substr(" nocase
	condition: filesize < 1MB and any of them
}



rule suspicious_obfuscation_using_String_fromCharCode {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation using String.fromCharCode"
		mitre = "T1027"
	strings:
		$h_raw1 = "\"rCo\",\"t\",\"cha\",\"\",\"deA\"" nocase
		$h_raw2 = "\"deA\",\"cha\",\"rCo\",\"t\"" nocase
		$h_reg3 = /from([\W]{0,6}?)C([\W]{0,6}?)h([\W]{0,6}?)a(.{0,6}?)r(.{0,6}?)C(.{0,6}?)o([\W]{0,6}?)d([\W]{0,6}?)e/
		$h_raw4 = ".fromCharC" nocase
	condition: any of them
}

rule Ran_Conti_Loader_V3_Nov_2020_1 {
   meta:
      description = "Detect Conti V3 loader"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      // For analysis see it -> https://0xthreatintel.medium.com/reversing-conti-ransomware-bfce15019e74
      date = "2020-12-15"
      level= "experimental"
      hash1 = "707b752f6bd89d4f97d08602d0546a56d27acfe00e6d5df2a2cb67c5e2eeee30"
      // From intezer analysis, same code reuse (november 2020) -> https://analyze.intezer.com/files/26b2401211769d2fa1415228b4b1305eeeed249a996d149ad83b6fc9c4f703ce
      hash2 = "26b2401211769d2fa1415228b4b1305eeeed249a996d149ad83b6fc9c4f703ce"
   strings:
      // seq main
      $seq1 = { 83 ec 1c 68 80 00 00 00 68 54 21 40 00 ff 15 30 20 40 00 85 c0 0f 85 e9 00 00 00 56 57 68 48 21 40 00 89 44 24 14 89 44 24 10 c7 44 24 1c 17 00 00 00 c7 44 24 20 55 1e 00 00 c7 44 24 24 09 04 00 00 ff 15 34 20 40 00 8b 3d 3c 20 40 00 8b f0 68 34 21 40 00 56 ff d7 68 20 21 40 00 56 a3 e4 33 40 00 ff d7 a3 0c 36 40 00 8d 44 24 14 50 6a 03 8d 4c 24 20 51 68 00 00 40 00 ff 15 e4 33 40 00 85 c0 7c 1a 8b 4c 24 14 8d 54 24 0c 52 8d 44 24 14 50 51 68 00 00 40 00 ff 15 0c 36 40 00 68 18 21 40 00 ff 15 70 20 40 00 8b 54 24 10 83 c4 04 50 68 00 10 00 00 52 6a 00 ff 15 38 20 40 00 8b 4c 24 10 8b f0 8b 44 24 0c 50 51 56 e8 4a 00 00 00 8d 54 24 14 52 }
      $seq2 = { 8b 4c 24 24 8d 44 24 20 50 51 56 e8 1d fe ff ff 83 c4 24 ff d6 8b 54 24 28 5f 89 15 08 36 40 00 5e 33 c0 83 c4 }
      $s1 = { 3e 35 44 35 4c 35 53 35 58 35 5e 35 64 35 6c 35 72 35 79 35 }
      $s2 = { 31 07 32 0d 32 25 32 2b 32 30 32 36 32 4c 32 6a 32 }
      $s3 = "_invoke_watson" fullword ascii
      $s4 = { 8b 2d bc 36 40 00 0f b6 04 2f 0f b6 da 8b 54 24 14 0f b6 14 13 8d 0c 2f 03 d6 03 c2 99 be 40 03 00 00 f7 fe 0f b6 f2 8d 04 2e e8 7f ff ff ff 8d 43 01 99 f7 7c 24 18 47 81 ff 40 }
   condition:
      uint16(0) == 0x5a4d and filesize > 100KB and all of ($seq*) and 2 of ($s*)
}




rule suspicious_obfuscation_using_String_replace {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation using String.replace"
		mitre = "T1027"
	strings:
		$h_reg1 = /'re'(.{1,24}?)'place'/
		$h_raw2 = ".replace" nocase
	condition: filesize < 1MB and any of them
}

rule suspicious_javascript_object {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.javascript object"
		mitre = "T1027 T1059.007"
	strings:
		$h_raw1 = "/JavaScript" nocase
		$h_raw2 = "/JS " 
	condition: any of them
}
rule Check_OutputDebugStringA_iat
{
	meta:
		Author = "http://twitter.com/j0sm1"
		Description = "Detect in IAT OutputDebugstringA"
		Date = "20/04/2015"
	condition:
		pe.imports("kernel32.dll","OutputDebugStringA")
}

rule Win32_Trojan_Dridex : tc_detection malicious
{
    meta:
        author              = "ReversingLabs"
        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "DRIDEX"
        description         = "Yara rule that detects Dridex trojan."
        tc_detection_type   = "Trojan"
        tc_detection_name   = "Dridex"
        tc_detection_factor = 5
		
    strings:
        $resolve_api_wrapper_1 = {
            56 57 8B FA 8B F1 8B CF E8 ?? ?? ?? ?? 85 C0 75 ?? 81 FE ?? ?? ?? ?? 75 ?? 33 C0 5F 
            5E C3 8B CE E8 ?? ?? ?? ?? 85 C0 75 ?? 8B CE E8 ?? ?? ?? ?? 84 C0 74 ?? 8B CE E8 ?? 
            ?? ?? ?? 85 C0 74 ?? 8B D7 ?? ?? ?? ?? E9 
        }
        $resolve_api_wrapper_2 = {
            57 53 8B FA 8B D9 8B CF E8 ?? ?? ?? ?? 85 C0 75 ?? 81 FB ?? ?? ?? ?? 74 ?? 8B CB E8 
            ?? ?? ?? ?? 85 C0 74 ?? 8B C8 8B D7 E8 ?? ?? ?? ?? 5B 5F C3 8B CB E8 ?? ?? ?? ?? 84 
            C0 74 ?? 8B CB E8 ?? ?? ?? ?? 85 C0 75 ?? 33 C0 EB 
        }
        $resolve_api_wrapper_3 = {
            55 8B EC 57 8B 7D ?? 57 E8 ?? ?? ?? ?? 85 C0 75 ?? 56 8B 75 ?? 81 FE ?? ?? ?? ?? 74 
            ?? 56 E8 ?? ?? ?? ?? 85 C0 75 ?? 8B CE E8 ?? ?? ?? ?? 84 C0 74 ?? 56 E8 ?? ?? ?? ?? 
            85 C0 75 ?? 5E 33 C0 5F 5D C2 ?? ?? 57 50 E8 ?? ?? ?? ?? 5E 5F 5D C2 
        }
        $resolve_api_wrapper_4 = {
            55 8B EC FF 75 ?? E8 ?? ?? ?? ?? 85 C0 75 ?? 56 8B 75 ?? 81 FE ?? ?? ?? ?? 74 ?? 56 
            E8 ?? ?? ?? ?? 85 C0 75 ?? 8B CE E8 ?? ?? ?? ?? 84 C0 74 ?? 56 E8 ?? ?? ?? ?? 85 C0 
            74 ?? 5E 89 45 ?? 5D E9 
        }
        $find_first_file_snippet_1 = {
            53 56 8B F1 57 33 DB 32 C9 89 5E ?? 33 FF E8 ?? ?? ?? ?? 83 38 ?? 7C ?? [4-6] BA ?? 
            ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 4E ?? 57 6A ?? 6A ?? 8D 56 ?? 
            52 53 51 FF D0 
        }
        $find_first_file_snippet_2 = {
            57 53 55 8B E9 33 C9 C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? 
            ?? 8B 18 E8 ?? ?? ?? ?? 8B C8 85 C9 74 ?? 33 D2 83 FB ?? 6A ?? 5B 8D 7D ?? 0F 4C DA 
            8B C2 53 52 52 57 0F 9D C0 50 FF 75 ?? FF D1 
        }
        $find_first_file_snippet_3 = {
            53 56 8B F1 33 DB 57 32 C9 89 5E ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B 
            38 E8 ?? ?? ?? ?? 8B D0 85 D2 74 ?? 6A ?? 33 C0 83 FF ?? 59 0F 4C C8 8D 46 ?? 51 53 
            53 50 33 C0 83 FF ?? 0F 9D C0 50 FF 76 ?? FF D2 
        }
        $find_first_file_snippet_4 = {
            53 56 8B F1 57 33 DB 32 C9 89 5E ?? 33 FF E8 ?? ?? ?? ?? 83 38 ?? 7C ?? 8D 7B ?? 8D 
            5F ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 4E ?? 57 6A ?? 6A 
            ?? 8D 56 ?? 52 53 51 CC C3 
        }
        $find_first_file_snippet_5 = {
            56 8B F1 32 C9 57 C7 46 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 
            8B 38 E8 ?? ?? ?? ?? 8B D0 85 D2 74 ?? 33 C0 B9 ?? ?? ?? ?? 83 FF ?? 0F 4C C8 51 50 
            50 8D 46 ?? 50 33 C0 83 FF ?? 0F 9D C0 50 FF 76 ?? FF D2 
        }
		
    condition:
        uint16(0) == 0x5A4D and
        (
            any of ($resolve_api_wrapper_*) and 
            any of ($find_first_file_snippet_*)
        )
}

rule Sus_Obf_Enc_Spoof_Hide_PE {

    meta:
        author = "XiAnzheng"
        source_url = "https://github.com/XiAnzheng-ID/Yara-Rules"
        description = "Check for Overlay, Obfuscating, Encrypting, Spoofing, Hiding, or Entropy Technique(can create FP)"
        date = "2024-11-18"
        updated = "2024-11-21"
        yarahub_license = "CC0 1.0"
        yarahub_uuid = "fa466824-f124-45bc-8398-eaecef7271f9"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "ffea1266b09abbf0ceb59119746d8630"

    condition:
        // Missing, Suspicious, Spoofed Import/Export tables combination 
        (pe.number_of_imports == 0)
        or (pe.number_of_imports == 0 and pe.entry_point_raw == 0)
        or (pe.size_of_optional_header < 0xE0 or pe.size_of_optional_header > 0xF0)
        or (pe.number_of_exports != 0 and pe.number_of_imports == 0)

        // Suspicious or Spoofed Section Headers Number
        or (pe.number_of_sections == 0 or pe.number_of_sections < 0 or pe.number_of_sections > 11)

        // Contain Overlay File (Can create FP)
        or (pe.overlay.size > 0)

        // Invalid PE Header
        or (pe.size_of_headers < 0x200 or pe.size_of_headers > 0x400)

        // High Entropy Section (Could Be Compressed or Packed, Can Create FP)
        or (math.entropy(0, filesize) > 7.25)
        
        or (for any ent_sec in (0..pe.number_of_sections - 1): (
                math.entropy(pe.sections[ent_sec].raw_data_offset, pe.sections[ent_sec].raw_data_offset + pe.sections[ent_sec].raw_data_size) > 7.25
            )
        )
}  


rule aPLib_decompression
{     
	meta:
		description = "Detects aPLib decompression code often used in malware"
		author="@r3c0nst"
		date="2021-24-03"
		reference="https://ibsensoftware.com/files/aPLib-1.1.1.zip"

	strings:
		$pattern1 = { FC B2 80 31 DB A4 B3 02 }
		$pattern2 = { AC D1 E8 74 ?? 11 C9 EB }
		$pattern3 = { 73 0A 80 FC 05 73 ?? 83 F8 7F 77 }

	condition:
		filesize < 10MB and all of them
}

rule crime_win32_doppelpaymer_ransomware_1 {
   meta:
      description = "Detects DoppelPaymer payload Nov 11 Signed"
      author = "@VK_Intel"
      reference = "https://twitter.com/VK_Intel/status/1193937831766429696"
      date = "2019-11-11"
      hash1 = "46254a390027a1708f6951f8af3da13d033dee9a71a4ee75f257087218676dd5"
   strings:
       $s1 = "Setup run" fullword wide
       $hash_function = { ?? ?? 8b fa 8b ?? 8b cf e8 ?? ?? ?? ?? 85 c0 75 ?? 81 ?? }
   condition:
      ( uint16(0) == 0x5a4d and
         filesize < 2500KB and
         ( all of them )
      )
}


rule Darkside
{
    meta:
        id = "5qjcs58k9iHd3EU3xv66sV"
        fingerprint = "57bc5c7353c8c518e057456b2317e1dbf59ee17ce69cd336f1bacaf627e9efd5"
        version = "1.0"
        creation_date = "2021-05-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Darkside ransomware."
        category = "MALWARE"
        malware = "DARKSIDE"
        malware_type = "RANSOMWARE"

    strings:
       // $ = "darkside_readme.txt" ascii wide
        $ = "[ Welcome to DarkSide ]" ascii wide
        $ = { 66 c7 04 47 2a 00 c7 44 47 02 72 00 65 00 c7 44 47 06 63 00 79 00 c7 44 47 0a 63 00 6c 00 c7 44 47 0e 65 00 2a 00 66 c7 44 47 12 00 00 }
        $ = { c7 00 2a 00 72 00 c7 40 04 65 00 63 00 c7 40 08 79 00 63 00 c7 40 0c 6c 00 65 00 c7 40 10 2a 00 00 00 }

    condition:
        any of them
}

rule UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser
{
      meta:
		author="malware-lu"
strings:
		$a0 = { FF D5 8D 87 [4] 80 20 ?? 80 60 [2] 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }
condition:
		$a0
}

rule UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 BE [4] 8D BE [4] 57 83 CD FF 89 E5 8D 9C 24 [4] 31 C0 50 39 DC 75 FB 46 46 53 68 [4] 57 83 C3 04 53 68 [4] 56 83 C3 04 53 50 C7 03 [4] 90 90 }
	$a1 = { 60 BE [4] 8D BE [4] 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB }
condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

rule RAN_BlackMatter_Aug_2021_1
{
    meta:
        description = "Detect BlackMatter ransomware"
        author = "Arkbird_SOLG"
        date = "2021-08-02"
        reference = "https://twitter.com/abuse_ch/status/1421834305416933376"
        hash1 = "22d7d67c3af10b1a37f277ebabe2d1eb4fd25afbd6437d4377400e148bcc08d6"
        hash2 = "7f6dd0ca03f04b64024e86a72a6d7cfab6abccc2173b85896fc4b431990a5984"
        level = "Experimental"
        tlp = "white"
        adversary = "-"
    strings:
        $s1 = { 55 8b ec 81 ec ac 02 00 00 53 51 52 56 57 c7 45 fc 00 00 00 00 c7 45 f4 00 00 00 00 c7 45 f0 00 00 00 00 c7 45 ec 00 00 00 00 6a 00 ff 15 00 15 41 00 85 c0 0f 85 3e 04 00 00 8d 45 d4 50 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 84 15 41 00 85 c0 0f 85 1c 04 00 00 8d 85 7c ff ff ff c7 00 b1 5f 5a 22 c7 40 04 c8 5f 75 22 c7 40 08 b1 5f 06 22 b9 03 00 00 00 81 30 ed 5f 06 22 83 c0 04 49 75 f4 8b 7d 08 8b 4d d4 8d 45 f8 50 6a 00 6a 00 6a 00 6a 00 6a 02 ff 71 1c ff 15 88 15 41 00 85 c0 75 6d 8d 45 dc 50 6a 00 6a 00 ff 75 f8 ff 15 8c 15 41 00 85 }
        $s2 = { 8d 45 88 c7 00 a1 5f 42 22 c7 40 04 ac 5f 56 22 c7 40 08 d7 5f 29 22 c7 40 0c c2 5f 45 22 c7 40 10 a3 5f 3b 22 c7 40 14 ae 5f 69 22 c7 40 18 80 5f 76 22 c7 40 1c 98 5f 72 22 c7 40 20 88 5f 74 22 c7 40 24 9e 5f 2a 22 c7 40 28 ed 5f 06 22 b9 0b 00 00 00 81 30 ed 5f 06 22 83 c0 04 49 75 f4 8d 45 88 50 8d 85 54 fd ff ff 50 ff 15 dc 12 41 00 83 c4 08 ff 75 cc 8d 85 54 fd ff ff 50 ff 15 d8 12 41 00 83 c4 08 8d 45 ec 50 8d 85 5c ff ff ff 50 6a 01 6a 00 6a 00 8d 85 54 fd ff ff 50 ff 15 98 15 41 00 }
        $s3 = { 8d 45 b4 c7 00 21 0a 83 e9 c7 40 04 c5 ce d7 33 c7 40 08 40 c4 06 e2 c7 40 0c a2 87 fb dd b9 04 00 00 00 81 30 ed 5f 06 22 83 c0 04 49 75 f4 8d 45 a4 c7 00 6a f9 14 fe c7 40 04 92 2c c9 33 c7 40 08 65 12 06 88 c7 40 0c ed 14 28 06 b9 04 00 00 00 81 30 ed 5f 06 22 83 c0 04 49 75 f4 8d 45 94 c7 00 75 39 4d 45 c7 40 04 7f b1 d6 33 c7 40 08 40 2e 06 e2 c7 40 0c a2 87 fb dd b9 04 00 00 00 81 30 ed 5f 06 22 83 c0 04 49 75 f4 8d 45 84 c7 00 99 f9 aa 66 c7 40 04 11 b7 d6 33 c7 40 08 4d 23 06 e2 c7 40 0c a2 e9 8e 02 b9 04 00 00 00 81 30 ed 5f 06 22 83 c0 04 49 75 f4 8d 85 b8 fe ff ff c7 00 b2 5f 59 22 c7 40 04 bd 5f 74 22 c7 40 08 82 5f 70 22 c7 40 0c 84 5f 62 22 c7 40 10 88 5f 74 22 c7 40 14 ac 5f 74 22 c7 40 18 8e 5f 6e 22 c7 40 1c 84 5f 72 22 c7 40 20 88 5f 65 22 c7 40 24 99 5f 73 22 c7 40 28 9f 5f 63 22 c7 40 2c ed 5f 06 22 b9 0c 00 00 00 81 30 ed 5f 06 22 83 c0 04 49 75 f4 8d 85 6c ff ff ff c7 00 bf 5f 49 22 c7 40 04 a2 5f 52 22 c7 40 08 b1 5f 45 22 c7 40 0c a4 5f 4b 22 c7 40 10 bb 5f 34 22 c7 40 14 ed 5f 06 22 b9 06 00 00 }
        $s4 = { 8d bd fc fe ff ff 32 c0 aa b9 2a 00 00 00 b0 ff f3 aa b0 3e aa b9 03 00 00 00 b0 ff f3 aa b0 3f aa b9 0a 00 00 00 b0 34 aa fe c0 e2 fb b9 03 00 00 00 b0 ff f3 aa 32 c0 aa b9 03 00 00 00 b0 ff f3 aa }
        $s5 = { 35 35 35 4f 35 58 35 22 36 35 36 3f 36 2c 37 3f 37 60 37 76 37 }
        $s6 = { 3d 2b 3d 47 3d 4d 3d 60 3d 67 3d 6d 3d }
        $s7 = { 8b 0e 0f b6 d1 0f b6 dd 57 8d bd fc fe ff ff 8a 04 3a 8a 24 3b c1 e9 10 83 c6 04 0f b6 d1 0f b6 cd 8a 1c 3a 8a 3c 39 5f 8a d4 8a f3 c0 e0 02 c0 eb 02 c0 e6 06 c0 e4 04 c0 ea 04 0a fe 0a c2 0a e3 88 07 88 7f 02 88 67 01 ff 4d fc }
    condition:
       uint16(0) == 0x5A4D and filesize > 25KB and 5 of ($s*) 
}  

rule  Blackmatter_own
{
	meta:
	score=100
	
	strings:
	$str1 = "BitBlt@gdi32.dll"
	
	
	condition: all of them
}
rule RAN_MountLocker_May_2021_1 {
   meta:
        description = "Detect the Mountlocker ransomware"
        author = "Arkbird_SOLG"
        // thanks to @dragan_security for his help
        reference = "Internal Research"
        date = "2020-05-12"
        hash1 = "0aa8099c5a65062ba4baec8274e1a0650ff36e757a91312e1755fded50a79d47"
        hash2 = "f570d5b17671e6f3e56eae6ad87be3a6bbfac46c677e478618afd9f59bf35963"
        hash3 = "5eae13527d4e39059025c3e56dad966cf67476fe7830090e40c14d0a4046adf0"
        tlp = "White"
        adversary = "MountLocker"
   strings:      
        $seq_Sep_2020_1 = { 40 53 48 81 ec f0 02 00 00 b9 e8 03 00 00 ff 15 ec 1a 00 00 bb 68 00 00 00 48 8d 4c 24 70 44 8b c3 33 d2 e8 9c 00 00 00 ba 04 01 00 00 89 5c 24 70 48 8d 8c 24 e0 00 00 00 ff 15 51 1a 00 00 48 8d 15 a2 9c 00 00 48 8d 8c 24 e0 00 00 00 ff 15 64 1a 00 00 48 8d 44 24 50 45 33 c9 48 89 44 24 48 48 8d 94 24 e0 00 00 00 48 8d 44 24 70 45 33 c0 48 89 44 24 40 33 c9 48 83 64 24 38 00 48 83 64 24 30 00 c7 44 24 28 10 00 00 00 83 64 24 20 00 ff 15 c1 19 00 00 8b d8 85 c0 74 16 48 8b 4c 24 58 ff 15 50 1a 00 00 48 8b 4c 24 50 ff 15 45 1a 00 00 8b c3 48 81 c4 f0 02 }
        $seq_Sep_2020_2 = { 68 00 00 00 f0 6a 01 68 a0 51 00 10 57 8d 45 f8 89 5d f4 50 89 7d f8 89 7d fc ff 15 30 50 00 10 85 c0 0f 84 81 00 00 00 8d 45 fc 50 57 57 68 14 01 00 00 68 d0 d0 00 10 ff 75 f8 ff 15 08 50 00 10 8b f0 85 f6 74 26 68 00 01 00 00 8d 45 f4 50 68 60 42 01 10 57 6a 01 57 ff 75 fc ff 15 04 50 00 10 ff 75 fc 8b f0 ff 15 00 50 00 10 57 ff 75 f8 ff 15 0c 50 00 10 }
        $seq_Jan_2021_1 = { 48 21 4d 77 4c 8d 05 [2] 00 00 48 21 4d 6f ?? 8b ?? 48 8d 4d 77 [6-9] c7 44 24 20 00 00 00 f0 ff 15 [2] 00 00 85 c0 0f 84 [2] 00 00 48 8b 4d 77 48 8d 45 6f 48 89 44 24 28 48 8d [3] 00 00 83 64 24 20 00 [2-5] c9 41 b8 14 01 00 00 ff 15 [2] 00 00 8b d8 85 c0 74 3b 48 8b 4d 6f 48 8d 45 67 c7 44 24 30 00 01 00 00 45 33 c9 48 89 44 24 28 ?? 8b ?? 48 8d 05 [2-3] 00 33 d2 48 89 44 24 20 ff 15 [2] 00 00 48 8b 4d 6f 8b d8 ff 15 [2] 00 00 48 8b 4d 77 33 d2 ff 15 [2] 00 00 85 db [4-12] 00 00 48 8d }
        $seq_Jan_2021_2 = { 4c 8d 05 20 47 00 00 41 8b ce 48 8d 15 1e 47 00 00 e8 [2] 00 00 ba 04 01 00 00 48 8d 4c 24 40 ff 15 ?? 43 00 00 85 c0 75 12 b8 5c 00 00 00 c7 44 24 40 43 00 3a 00 66 89 44 24 44 89 6c 24 38 4c 8d 8c 24 78 02 00 00 48 89 6c 24 30 48 8d 4c 24 40 48 89 6c 24 28 45 33 c0 33 d2 48 89 6c 24 20 66 89 6c 24 46 ff 15 6b 44 00 00 44 8b 84 24 78 02 00 00 48 8d 15 e4 45 00 00 85 c0 b9 bd 07 a2 41 44 0f 44 c1 41 8b c8 44 89 84 24 78 02 00 00 c1 c9 09 41 8b c0 89 4c 24 28 45 8b c8 c1 c8 06 48 8d 4c 24 40 41 c1 c9 03 89 44 24 20 ff 15 8b 44 00 00 4c 8d 44 24 40 33 d2 33 c9 ff 15 ?? 42 00 00 48 85 c0 74 1b ff 15 [2] 00 00 3d b7 00 00 00 74 0e bf 01 00 00 00 48 8d 15 fe 45 00 00 eb 09 8b fd 48 8d 15 a3 45 00 00 41 8b }
    condition:
         uint16(0) == 0x5a4d and filesize > 30KB and 1 of ($seq*)     
}

rule Ran_Mount_Locker_Nov_2020_1 {
   meta:
      description = "Detect Mount Locker ransomware (November 2020 variant)"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2020-11-20"
      hash1 = "e7c277aae66085f1e0c4789fe51cac50e3ea86d79c8a242ffc066ed0b0548037"
      hash2 = "226a723ffb4a91d9950a8b266167c5b354ab0db1dc225578494917fe53867ef2"
   strings:
      $s1 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword wide
      $s2 = "VBA6.DLL" fullword ascii
      $s3 = "MSComDlg.CommonDialog" fullword ascii
      $s4 = "DllFunctionCall" fullword ascii 
      $s5 = { 00 2a 00 5c 00 41 00 43 00 3a 00 5c [35-160] 00 2e 00 76 00 62 00 70 } // check vbp path existance
      $s6 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\COMCTL32.oca" fullword wide
      $s7 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\MSFLXGRD.oca" fullword ascii 
      $s8 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s9 = "SFLXGRD.OCX" fullword ascii
      $s10 = "COMDLG32.OCX" fullword ascii
      $s11 = "COMCTL32.OCX" fullword ascii
      $seq1 = { 42 00 24 00 40 00 43 00 67 00 2f 00 44 00 08 00 4a 00 51 00 77 00 54 00 76 00 25 00 55 00 48 00 00 00 00 00 5d 00 4c 00 09 00 53 00 3e 00 73 00 62 00 52 00 50 00 0b 00 61 00 01 00 61 01 3a 00 03 00 57 00 4f 00 75 00 54 00 71 00 22 00 53 00 37 00 00 00 30 00 1d 00 46 00 5a 00 5c 00 48 00 78 00 63 00 02 00 1d 00 23 00 3b 00 28 00 55 00 73 00 28 00 61 00 3b 00 00 00 00 00 44 00 4e 00 4a 00 4d 00 61 00 40 00 59 00 2b 00 38 00 02 01 04 01 54 00 08 00 52 00 56 00 1d 00 42 00 3e 00 00 00 00 00 35 00 70 00 3b 00 37 00 6f 00 26 00 26 00 40 00 64 00 02 00 51 00 3c 00 41 00 16 00 3e 00 00 00 47 00 58 00 33 00 89 00 54 00 2d 00 29 00 50 00 04 00 59 00 5d 00 4f 00 1b 00 36 00 30 00 83 00 41 00 00 00 2a 00 54 00 47 00 86 00 56 00 19 00 24 00 4e 00 3a 00 45 00 51 00 4d 00 1e 00 3b 00 2b 00 81 00 35 00 00 00 3a 00 65 00 57 00 03 00 2d 00 62 00 53 }
      $seq2 = { 5a 00 3d 00 14 00 51 00 1f 00 67 00 1c 00 24 00 00 00 00 00 00 00 6f 00 27 00 62 00 5d 00 6d 00 30 00 01 00 27 01 25 00 62 00 7b 00 05 00 56 00 24 00 3c 00 3d 00 5d 00 2e 00 62 00 03 00 0a 00 57 00 6a 00 02 00 5d 00 02 01 23 01 67 00 20 00 54 00 01 00 6c 01 17 00 0b 00 44 00 21 00 1e 00 01 00 52 01 60 00 3b 00 11 00 45 00 2a 00 59 00 2c 00 19 00 00 00 5a 00 1e 00 61 00 5c 00 6b 00 31 00 01 00 1a 01 2d 00 4a 00 6f 00 11 00 57 00 2c 00 3a 00 3a 00 50 00 2a 00 61 00 02 00 07 00 53 00 7b 00 01 01 5b 00 02 01 6a 01 0b 00 03 00 6d 00 43 00 0c 00 64 00 4d 00 44 00 5f 00 08 00 5a 00 68 00 2b 00 32 00 68 }
         condition:
      uint16(0) == 0x5a4d and filesize > 100KB and 6 of ($s*) and 1 of ($seq*)
}
rule SUSP_RANSOMWARE_Indicator_Jul20 {
   meta:
      description = "Detects ransomware indicator"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/lazarus-on-the-hunt-for-big-game/97757/"
      date = "2020-07-28"
      score = 60
      hash1 = "52888b5f881f4941ae7a8f4d84de27fc502413861f96ee58ee560c09c11880d6"
      hash2 = "5e78475d10418c6938723f6cfefb89d5e9de61e45ecf374bb435c1c99dd4a473"
      hash3 = "6cb9afff8166976bd62bb29b12ed617784d6e74b110afcf8955477573594f306"
      id = "6036fdfd-8474-5d79-ac75-137ac2efdc77"
   strings:
      $ = "Decrypt.txt" ascii wide 
      $ = "DecryptFiles.txt" ascii wide
      $ = "Decrypt-Files.txt" ascii wide
      $ = "DecryptFilesHere.txt" ascii wide
      $ = "DECRYPT.txt" ascii wide 
      $ = "DecryptFiles.txt" ascii wide
      $ = "DECRYPT-FILES.txt" ascii wide
      $ = "DecryptFilesHere.txt" ascii wide
      $ = "DECRYPT_INSTRUCTION.TXT" ascii wide 
      $ = "FILES ENCRYPTED.txt" ascii wide
      $ = "DECRYPT MY FILES" ascii wide 
      $ = "DECRYPT-MY-FILES" ascii wide 
      $ = "DECRYPT_MY_FILES" ascii wide
      $ = "DECRYPT YOUR FILES" ascii wide  
      $ = "DECRYPT-YOUR-FILES" ascii wide 
      $ = "DECRYPT_YOUR_FILES" ascii wide 
      $ = "DECRYPT FILES.txt" ascii wide
   condition:
      uint16(0) == 0x5a4d and
      filesize < 1400KB and
      1 of them
}

rule URL_Detection_and_device_LOC{
   meta:
      description = "Detects malicous URLs"
   strings:
      $a = "http://filestorage.biz/download.php?file=e541302686cca000584050d41e254261"
      $b = "memesmix.net"
      $c = "SOFTWARE\\Microsoft\\WindowsNT"
      $d = "SOFTWARE\\keys_data\\data"
   condition:
      ($a or $b) and ($c or $d)

}

rule SEH__vba : AntiDebug SEH {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = "vbaExceptHandler"
	condition:
		any of them
}

		
rule SHA256

{

  meta:

    description = "Uses constants related to SHA256"

    author = "Ivan Kwiatkowski (@JusticeRage)"

  strings:

    $sha256_init0 = { 67 E6 09 6A }

    $sha256_init1 = { 85 AE 67 BB }

    $sha256_init2 = { 72 F3 6E 3C }

    $sha256_init3 = { 3A F5 4F A5 }

    $sha256_init4 = { 7F 52 0E 51 }

    $sha256_init5 = { 8C 68 05 9B }

    $sha256_init6 = { AB D9 83 1F }

    $sha256_init7 = { 19 CD E0 5B }

    $sha256_k0 = { 98 2F 8A 42 }

    $sha256_k1 = { 91 44 37 71 }

    $sha256_k2 = { CF FB C0 B5 }

    $sha256_k3 = { A5 DB B5 E9 }

    $sha256_k4 = { 5B C2 56 39 }

    $sha256_k5 = { F1 11 F1 59 }

    $sha256_k6 = { A4 82 3F 92 }

    $sha256_k7 = { D5 5E 1C AB }

    $sha256_k8 = { 98 AA 07 D8 }

    $sha256_k9 = { 01 5B 83 12 }

    $sha256_k10 = { BE 85 31 24 }

    $sha256_k11 = { C3 7D 0C 55 }

    $sha256_k12 = { 74 5D BE 72 }

    $sha256_k13 = { FE B1 DE 80 }

    $sha256_k14 = { A7 06 DC 9B }

    $sha256_k15 = { 74 F1 9B C1 }

    $sha256_k16 = { C1 69 9B E4 }

    $sha256_k17 = { 86 47 BE EF }

    $sha256_k18 = { C6 9D C1 0F }

    $sha256_k19 = { CC A1 0C 24 }

    $sha256_k20 = { 6F 2C E9 2D }

    $sha256_k21 = { AA 84 74 4A }

    $sha256_k22 = { DC A9 B0 5C }

    $sha256_k23 = { DA 88 F9 76 }

    $sha256_k24 = { 52 51 3E 98 }

    $sha256_k25 = { 6D C6 31 A8 }

    $sha256_k26 = { C8 27 03 B0 }

    $sha256_k27 = { C7 7F 59 BF }

    $sha256_k28 = { F3 0B E0 C6 }

    $sha256_k29 = { 47 91 A7 D5 }

    $sha256_k30 = { 51 63 CA 06 }

    $sha256_k31 = { 67 29 29 14 }

    $sha256_k32 = { 85 0A B7 27 }

    $sha256_k33 = { 38 21 1B 2E }

    $sha256_k34 = { FC 6D 2C 4D }

    $sha256_k35 = { 13 0D 38 53 }

    $sha256_k36 = { 54 73 0A 65 }

    $sha256_k37 = { BB 0A 6A 76 }

    $sha256_k38 = { 2E C9 C2 81 }

    $sha256_k39 = { 85 2C 72 92 }

    $sha256_k40 = { A1 E8 BF A2 }

    $sha256_k41 = { 4B 66 1A A8 }

    $sha256_k42 = { 70 8B 4B C2 }

    $sha256_k43 = { A3 51 6C C7 }

    $sha256_k44 = { 19 E8 92 D1 }

    $sha256_k45 = { 24 06 99 D6 }

    $sha256_k46 = { 85 35 0E F4 }

    $sha256_k47 = { 70 A0 6A 10 }

    $sha256_k48 = { 16 C1 A4 19 }

    $sha256_k49 = { 08 6C 37 1E }

    $sha256_k50 = { 4C 77 48 27 }

    $sha256_k51 = { B5 BC B0 34 }

    $sha256_k52 = { 4A AA D8 4E }

    $sha256_k53 = { 4F CA 9C 5B }

    $sha256_k54 = { F3 6F 2E 68 }

    $sha256_k55 = { EE 82 8F 74 }

    $sha256_k56 = { 6F 63 A5 78 }

    $sha256_k57 = { 14 78 C8 84 }

    $sha256_k58 = { 08 02 C7 8C }

    $sha256_k59 = { FA FF BE 90 }

    $sha256_k60 = { EB 6C 50 A4 }

    $sha256_k61 = { F7 A3 F9 BE }

    $sha256_k62 = { F2 78 71 C6 }

  condition:

    all of ($sha256_init*) or 20 of ($sha256_k*)

}

rule INDICATOR_SUSPICOUS_EXE_References_VEEAM {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing many references to VEEAM. Observed in ransomware"
        score = 40
    strings:
        $s1 = "VeeamNFSSvc" ascii wide nocase
        $s2 = "VeeamRESTSvc" ascii wide nocase
        $s3 = "VeeamCloudSvc" ascii wide nocase
        $s4 = "VeeamMountSvc" ascii wide nocase
        $s5 = "VeeamBackupSvc" ascii wide nocase
        $s6 = "VeeamBrokerSvc" ascii wide nocase
        $s7 = "VeeamDeploySvc" ascii wide nocase
        $s8 = "VeeamCatalogSvc" ascii wide nocase
        $s9 = "VeeamTransportSvc" ascii wide nocase
        $s10 = "VeeamDeploymentService" ascii wide nocase
        $s11 = "VeeamHvIntegrationSvc" ascii wide nocase
        $s12 = "VeeamEnterpriseManagerSvc" ascii wide nocase
        $s13 = "\"Veeam Backup Catalog Data Service\"" ascii wide nocase
        $e1 = "veeam.backup.agent.configurationservice.exe" ascii wide nocase
        $e2 = "veeam.backup.brokerservice.exe" ascii wide nocase
        $e3 = "veeam.backup.catalogdataservice.exe" ascii wide nocase
        $e4 = "veeam.backup.cloudservice.exe" ascii wide nocase
        $e5 = "veeam.backup.externalinfrastructure.dbprovider.exe" ascii wide nocase
        $e6 = "veeam.backup.manager.exe" ascii wide nocase
        $e7 = "veeam.backup.mountservice.exe" ascii wide nocase
        $e8 = "veeam.backup.service.exe" ascii wide nocase
        $e9 = "veeam.backup.uiserver.exe" ascii wide nocase
        $e10 = "veeam.backup.wmiserver.exe" ascii wide nocase
        $e11 = "veeamdeploymentsvc.exe" ascii wide nocase
        $e12 = "veeamfilesysvsssvc.exe" ascii wide nocase
        $e13 = "veeam.guest.interaction.proxy.exe" ascii wide nocase
        $e14 = "veeamnfssvc.exe" ascii wide nocase
        $e15 = "veeamtransportsvc.exe" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule Ransom_Babuk {
    meta:
        description = "Rule to detect Babuk Locker"
        author = "TS @ McAfee ATR"
        date = "2021-01-19"
        hash = "e10713a4a5f635767dcd54d609bed977"
        rule_version = "v2"
        malware_family = "Ransom:Win/Babuk"
        malware_type = "Ransom"
        mitre_attack = "T1027, T1083, T1057, T1082, T1129, T1490, T1543.003"
    strings:
        $s1 = {005C0048006F007700200054006F00200052006500730074006F0072006500200059006F00750072002000460069006C00650073002E007400780074}
        //  \ How To Restore Your Files .txt
        $s2 = "delete shadows /all /quiet" fullword wide
        $pattern1 = {006D656D74617300006D65706F63730000736F70686F730000766565616D0000006261636B7570000047785673730000004778426C7200000047784657440000004778435644000000477843494D67720044656657617463680000000063634576744D67720000000063635365744D677200000000536176526F616D005254567363616E0051424643536572766963650051424944505365727669636500000000496E747569742E517569636B426F6F6B732E46435300}
        $pattern2 = {004163725363683253766300004163726F6E69734167656E74000000004341534144324457656253766300000043414152435570646174655376630000730071}
        $pattern3 = {FFB0154000C78584FDFFFFB8154000C78588FDFFFFC0154000C7858CFDFFFFC8154000C78590FDFFFFD0154000C78594FDFFFFD8154000C78598FDFFFFE0154000C7859CFDFFFFE8154000C785A0FDFFFFF0154000C785A4FDFFFFF8154000C785A8FDFFFF00164000C785ACFDFFFF08164000C785B0FDFFFF10164000C785B4FDFFFF18164000C785B8FDFFFF20164000C785BCFDFFFF28164000C785C0FDFFFF30164000C785C4FDFFFF38164000C785C8FDFFFF40164000C785CCFDFFFF48164000C785D0FDFFFF50164000C785D4FDFFFF581640}
        $pattern4 = {400010104000181040002010400028104000301040003810400040104000481040005010400058104000601040006C10400078104000841040008C10400094104000A0104000B0104000C8104000DC104000E8104000F01040000011400008114000181140002411400038114000501140005C11400064114000741140008C114000A8114000C0114000E0114000F4114000101240002812400034124000441240005412400064124000741240008C124000A0124000B8124000D4124000EC1240000C1340002813400054134000741340008C134000A4134000C4134000E8134000FC134000141440003C144000501440006C144000881440009C144000B4144000CC144000E8144000FC144000141540003415400048154000601540007815}
    condition:
        filesize >= 15KB and filesize <= 90KB and 
        1 of ($s*) and 3 of ($pattern*) 
}

rule Destructive_Ransomware_Gen1 {
   meta:
      description = "Detects destructive malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://blog.talosintelligence.com/2018/02/olympic-destroyer.html"
      date = "2018-02-12"
      hash1 = "ae9a4e244a9b3c77d489dee8aeaf35a7c3ba31b210e76d81ef2e91790f052c85"
      id = "3a7ce55e-fb28-577b-91bb-fe02d7b3d73c"
   strings:
      $x1 = "/set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no" fullword wide
      $x2 = "delete shadows /all /quiet" fullword wide
      $x3 = "delete catalog -quiet" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and 1 of them
}

rule BitcoinAddress
{
    meta:
        description = "Contains a valid Bitcoin address"
        author = "Didier Stevens (@DidierStevens)"
    strings:
		$btc = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,33}\b/ wide ascii
    condition:
        any of them
}

rule suspicious_javascript_in_XFA_block {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.javascript in XFA block"
		mitre = "T1027 T1059.007"
	strings:
		$h_raw1 = "application/x-javascript" nocase
		$h_raw2 = "application#2Fx-javascript" nocase
		//$h_reg3 = /(\&\#0*97;|a)(\&\#0*112;|p)(\&\#0*112;|p)(\&\#0*108;|l)(\&\#0*105;|i)(\&\#0*99;|c)(\&\#0*97;|a)(\&\#0*116;|t)(\&\#0*105;|i)(\&\#0*111;|o)(\&\#0*110;|n)(\&\#0*47;|\/)(\&\#0*120;|x)(\&\#0*45;|\-)(\&\#0*106;|j)(\&\#0*97;|a)(\&\#0*76;|v)(\&\#0*97;|a)(\&\#0*115;|s)(\&\#0*99;|c)(\&\#0*114;|r)(\&\#0*105;|i)(\&\#0*112;|p)(\&\#0*116;|t)/
	condition: any of them
}

rule Ran_BabukLockers_Jan_2021_1 {
   meta:
      description = "Detect the BabukLocker ransomware"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2020-01-03"
      hash1 = "8203c2f00ecd3ae960cb3247a7d7bfb35e55c38939607c85dbdb5c92f0495fa9"
      level = "Experimental"
   strings:
      // sequence of the discovery process from imported DLL (TTPs)
      $seq1 = { 55 8b ec 83 ec 14 a1 b0 81 40 00 33 c5 89 45 fc c7 45 f8 ff ff ff ff c7 45 f4 00 40 00 00 8d 45 f0 50 8b 4d 08 51 6a 13 6a 00 6a 02 e8 85 2b 00 00 85 c0 0f 85 a3 00 00 00 8b 55 f4 52 e8 ae 06 00 00 83 c4 04 89 45 08 83 7d 08 00 0f 84 81 00 00 00 8d 45 f4 50 8b 4d 08 51 8d 55 f8 52 8b 45 f0 50 e8 55 2b 00 00 85 c0 75 5c c7 45 ec 00 00 00 00 eb 09 8b 4d ec 83 c1 01 89 4d ec 8b 55 ec 3b 55 f8 73 40 8b 45 ec c1 e0 05 8b 4d 08 8b 54 01 0c 83 e2 02 74 14 8b 45 ec c1 e0 05 03 45  }         
      // sequence of the parsing arguments + shutdown process
      $seq2 = { 68 68 22 40 00 b8 04 00 00 00 c1 e0 00 8b 8d 9c fd ff ff 8b 14 01 52 ff 15 b8 90 40 00 85 c0 75 0c c7 85 b0 fd ff ff 01 00 00 00 eb 58 68 74 22 40 00 b8 04 00 00 00 c1 e0 00 8b 8d 9c fd ff ff 8b 14 01 52 ff 15 b8 90 40 00 85 c0 75 0c c7 85 b0 fd ff ff 00 00 00 00 eb 2b 68 80 22 40 00 b8 04 00 00 00 c1 e0 00 8b 8d 9c fd ff ff 8b 14 01 52 ff 15 b8 90 40 00 85 c0 75 0a c7 85 b0 fd ff ff ff ff ff ff e9 55 ff ff ff 6a 00 6a 00 ff 15 a8 90 40 00 e8 aa 04 00 00 e8 05 }
      // sequence of write op (key) in the disk
      $seq3 = { 83 c4 0c 68 f4 00 00 00 8d 85 f4 fd ff ff 50 68 88 22 40 00 ff 15 6c 90 40 00 68 98 22 40 00 8d 8d f4 fd ff ff 51 ff 15 c4 90 40 00 c7 85 ec fd ff ff 00 00 00 00 6a 00 68 80 00 00 00 6a 01 6a 00 6a 01 68 00 00 00 40 8d 95 f4 fd ff ff 52 ff 15 70 90 40 00 89 85 98 fd ff ff 83 bd 98 fd ff ff ff 0f 84 2e 03 00 00 6a 00 8d 85 ec fd ff ff 50 68 90 00 00 00 68 78 82 40 00 8b 8d 98 fd ff ff 51 ff 15 90 90 }
      $s1 = "\\ecdh_pub_k.bin" fullword wide 
      $s2 = "ntuser.dat.log" fullword wide 
      $s3 = "cmd.exe" fullword ascii
      $s4 = "/c vssadmin.exe delete shadows /all /quiet" fullword wide 
      $s5 = { 5c 00 5c 00 3f 00 5c 00 00 00 00 00 3a 00 00 00 98 2f } 
   condition:
      uint16(0) == 0x5a4d and filesize > 15KB and 2 of ($seq*) and 3 of ($s*) 
}



rule Suspicious_APIs_File_Hashes
{
    meta:
        description = "Detects suspicious file path, hash values, and API functions"
        author = "Dharmik Sanneganti"
        sample = "a0c3976f5d93927b0ee4e5c17057d3bb028ff26e4200ba63fbc9fa0d311eda57"
        date = "2024-11-28"
        version = "1.0"

    strings:
        $file_path = "F:\\ACTUALLIST\\LOGINFIRST!!!\\@RTGWEHW.exe"
        $sha256_hash1 = "088346136523f3ecf1cd1f4f5197a2db62908570d3d6ac94754ca971ce3cd55c"
        $sha256_hash2 = "0c903a4b233e5f13351f729a968a6dba9fc7762853ee05d984fb7c3bb61ab79a"
        $SetWinEventHook = "SetWinEventHook"
        $UnhookWinEvent = "UnhookWinEvent"

    condition:
        all of them
}



rule Ins_NSIS_Buer_Nov_2020_1 {
   meta:
      description = "Detect NSIS installer used for Buer loader"
      author = "Arkbird_SOLG"
      reference1 = "https://twitter.com/ffforward/status/1333703755439742977"
      reference2 = "https://twitter.com/VK_Intel/status/1333647007920033793"
      reference3 = "https://twitter.com/James_inthe_box/status/1333551419735953409"
      date = "2020-12-01"
      level = "Experimental"
      hash1 = "b298ead0400aaf886dbe0a0720337e6f2efd5e2a3ac1a7e7da54fc7b6e4f4277"
      hash2 = "66f5a68f6b5067feb07bb88a3bfaa6671a5e8fcf525e9cd2355de631c4ca2088"
      hash3 = "1c8260f2d597cfc1922ca72162e1eb3f8272c2d18fa41d77b145d32256c0063d"
   strings:
      $s1 = "\\Microsoft\\Internet Explorer\\Quick Launch" fullword ascii
      $s2 = "Software\\Microsoft\\Windows\\CurrentVersion" fullword ascii
      $s3 = "Control Panel\\Desktop\\ResourceLocale" fullword ascii
      $s4 = { 25 73 25 73 2e 64 6c 6c }
      $s5 = "CRYPTBASE" fullword ascii
      $s6 = { 25 75 2e 25 75 25 73 25 73 }
      $s7 = "PROPSYS" fullword ascii
      $s8 = { 5b 52 65 6e 61 6d 65 5d 0d 0a 00 00 25 73 3d 25 73 }
      $s9 = "APPHELP" fullword ascii
      $s10 = "NSIS Error" fullword ascii
      $s11 = "K=t%)xMx" fullword ascii
      $s12 = "4/##=?1" fullword ascii
      $dbg1 = "Error launching installer" fullword ascii
      $dbg2 = { 76 65 72 69 66 79 69 6e 67 20 69 6e 73 74 61 6c 6c 65 72 3a 20 25 64 25 25 }
      $dbg3 = { 54 4d 50 00 54 45 4d 50 00 00 00 00 4c 6f 77 00 5c 54 65 6d 70 00 00 00 20 2f 44 3d 00 00 00 00 4e 43 52 43 }
      $dbg4 = { e8 73 2a 00 00 3b fb 74 0b 68 4c a1 40 00 56 e8 64 2a 00 00 68 44 a1 40 00 56 e8 59 2a 00 00 bd 00 5c 43 00 55 56 ff 15 18 81 40 00 85 c0 74 97 3b fb 56 74 07 e8 0f 20 00 00 eb 05 e8 85 20 00 00 56 ff 15 f8 80 40 00 38 1d 00 54 43 00 75 0b 55 68 00 54 43 00 e8 01 2a 00 00 ff 74 24 1c 68 00 00 43 00 e8 f3 29 00 00 66 0f be 0d 40 a1 40 00 33 c0 6a 1a 8a 25 41 }
   condition:
      uint16(0) == 0x5a4d and filesize > 40KB and ( 10 of ($s*) and 3 of ($dbg*) )
}

rule IShellLink_Shortcut {
	meta:
        author = "OPSWAT"
        mitre_attack = "T1547.009"
        description = "The file may create or modify shortcuts that can execute a program during system boot or user login"
		//7f403f7d643d90c7cbadf3ccfc68bd1badf06f89a35af5fc7811920e820bbcc9
		//nursery/create-shortcut-via-ishelllink.yml
	strings:
		$clsid1 = {01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46} // CLSID_ShellLink
		$iid0 = {(EE|F9) 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46} //IID_IShellLinkA | IID_IShellLinkW
		$iid1 = {0B 01 00 00 00 00 00 00 C0 00 00 00 00 00 00 46} //IID_IPersistFile
	condition:
		all of them
		and pe.imports("ole32.dll", "CoCreateInstance")
}

rule blackhole_basic :  EK
{
    strings:
        $a = /\.php\?.*?\:[a-zA-Z0-9\:]{6,}?\&.*?\&/
    condition:
        $a
}

rule win_hook {
    meta:
        author = "x0r"
        description = "Affect hook table"
    version = "0.1"
    strings:
        $f1 = "user32.dll" nocase
        $c1 = "UnhookWindowsHookEx"
        $c2 = "SetWindowsHookExA"
        $c3 = "CallNextHookEx"
    condition:
        $f1 and 1 of ($c*)
}



rule NETexecutableMicrosoft
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 00 00 00 00 00 00 00 00 5F 43 6F 72 45 78 65 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C 00 00 00 00 00 FF 25 }
condition:
		$a0
}

rule Win32_Ransomware_Makop : tc_detection malicious
{
    meta:
        description = "Rule to detect the unpacked Makop ransomware samples"
        author = "Marc Rivero | McAfee ATR Team"
        date = "2020-07-19"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransom:W32/Makop"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        hash = "008e4c327875110b96deef1dd8ef65cefa201fef60ca1cbb9ab51b5304e66fe1"
    strings:
        $pattern_0 = { 50 8d7c2420 e8???????? 84c0 0f84a6020000 8b742460 ba???????? }
        $pattern_1 = { 51 52 53 ffd5 85c0 746d 8b4c240c }
        $pattern_2 = { 7521 68000000f0 6a18 6a00 6a00 56 ff15???????? }
        $pattern_3 = { 83c40c 8d4e0c 51 66c7060802 66c746041066 c6460820 }
        $pattern_4 = { 51 ffd3 50 ffd7 8b4628 85c0 }
        $pattern_5 = { 85c9 741e 8b4508 8b4d0c 8a11 }
        $pattern_6 = { 83c002 6685c9 75f5 2bc6 d1f8 66390c46 8d3446 }
        $pattern_7 = { 895a2c 8b7f04 85ff 0f85f7feffff 55 6a00 }
        $pattern_8 = { 8b3d???????? 6a01 6a00 ffd7 50 ff15???????? }
        $pattern_9 = { 85c0 7407 50 ff15???????? }
    condition:
        7 of them and
        filesize < 237568
}

rule RedLine_1
{
	meta:
		author = "ditekSHen"
		description = "Detects RedLine infostealer"
		cape_type = "RedLine Payload"
		original_yara_name = "RedLine"
		ruleset = "RedLine.yar"
		repository = "CAPESandbox/community"
		source_url = "https://github.com/CAPESandbox/community/blob/30a130d01407ba0f0637fb44e8159131a0c4e1e5/data/yara/CAPE/RedLine.yar"
		score = 75
	strings:
		$s1 = { 23 00 2b 00 33 00 3b 00 43 00 53 00 63 00 73 00 }
		$s2 = { 68 10 84 2d 2c 71 ea 7e 2c 71 ea 7e 2c 71 ea 7e
                32 23 7f 7e 3f 71 ea 7e 0b b7 91 7e 2b 71 ea 7e
                2c 71 eb 7e 5c 71 ea 7e 32 23 6e 7e 1c 71 ea 7e
                32 23 69 7e a2 71 ea 7e 32 23 7b 7e 2d 71 ea 7e }
		$s3 = { 83 ec 38 53 b0 ?? 88 44 24 2b 88 44 24 2f b0 ??
                88 44 24 30 88 44 24 31 88 44 24 33 55 56 8b f1
                b8 0c 00 fe ff 2b c6 89 44 24 14 b8 0d 00 fe ff
                2b c6 89 44 24 1c b8 02 00 fe ff 2b c6 89 44 24
                18 b3 32 b8 0e 00 fe ff 2b c6 88 5c 24 32 88 5c
                24 41 89 44 24 28 57 b1 ?? bb 0b 00 fe ff b8 03
                00 fe ff 2b de 2b c6 bf 00 00 fe ff b2 ?? 2b fe
                88 4c 24 38 88 4c 24 42 88 4c 24 47 c6 44 24 34
                78 c6 44 24 35 61 88 54 24 3a c6 44 24 3e 66 c6
                44 24 41 33 c6 44 24 43 ?? c6 44 24 44 74 88 54
                24 46 c6 44 24 40 ?? c6 44 24 39 62 c7 44 24 10 }
		$s4 = "B|BxBtBpBlBhBdB`B\\BXBTBPBLBHBDB@B<B8B4B0B,B(B$B B" fullword wide
		$s5 = " delete[]" fullword ascii
		$s6 = "constructor or from DllMain." ascii
		$x1 = "RedLine.Reburn" ascii
		$x2 = "RedLine.Client." ascii
		$x3 = "hostIRemotePanel, CommandLine: " fullword wide
		$u1 = "<ParseCoinomi>" ascii
		$u2 = "<ParseBrowsers>" ascii
		$u3 = "<GrabScreenshot>" ascii
		$u4 = "UserLog" ascii nocase
		$u5 = "FingerPrintT" fullword ascii
		$u6 = "InstalledBrowserInfoT" fullword ascii
		$u7 = "RunPE" fullword ascii
		$u8 = "DownloadAndEx" fullword ascii
		$u9 = ".Data.Applications.Wallets" ascii
		$u10 = ".Data.Browsers" ascii
		$u11 = ".Models.WMI" ascii
		$u12 = "DefenderSucks" wide
		$pat1 = "(((([0-9.])\\d)+){1})" fullword wide
		$pat2 = "^(?:2131|1800|35\\\\d{3})\\\\d{11}$" fullword wide
		$pat3 = "6(?:011|5[0-9]{2})[0-9]{12}$/C" fullword wide
		$pat4 = "Telegramprofiles^(6304|6706|6709|6771)[0-9]{12,15}$" fullword wide
		$pat5 = "host_key^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})$" fullword wide
		$pat6 = "^3(?:0[0-5]|[68][0-9])[0-9]{11}$" wide
		$pat7 = "settingsprotocol^(5018|5020|5038|6304|6759|6761|6763)[0-9]{8,15}$" wide
		$pat8 = "Opera GX4[0-9]{12}(?:[0-9]{3})?$cookies" wide
		$pat9 = "^9[0-9]{15}$Coinomi" wide
		$pat10 = "wallets^(62[0-9]{14,17})$" wide
		$pat11 = "hostpasswordUsername_value" wide
		$pat12 = "credit_cards^389[0-9]{11}$" wide
		$pat13 = "NWinordVWinpn.eWinxe*WinhostUsername_value" wide
		$pat14 = /(\/|,\s)CommandLine:/ wide
		$v2_1 = "ListOfProcesses" fullword ascii
		$v2_2 = /get_Scan(ned)?(Browsers|ChromeBrowsersPaths|Discord|FTP|GeckoBrowsersPaths|Screen|Steam|Telegram|VPN|Wallets)/ fullword ascii
		$v2_3 = "GetArguments" fullword ascii
		$v2_4 = "VerifyUpdate" fullword ascii
		$v2_5 = "VerifyScanRequest" fullword ascii
		$v2_6 = "GetUpdates" fullword ascii
		$v3_1 = "localhost.IUserServiceu" fullword ascii
		$v3_2 = "ParseNetworkInterfaces" fullword ascii
		$v3_3 = "ReplyAction0http://tempuri.org/IUserService/GetUsersResponse" fullword ascii
		$v3_4 = "Action(http://tempuri.org/IUserService/GetUsersT" fullword ascii
		$v3_5 = "basicCfg" fullword wide
		$vx4_1 = "C:\\\\Windows\\\\Microsoft.NET\\\\Framework\\\\v4.0.30319\\\\AddInProcess32.exe" fullword wide
		$v4_2 = "isWow64" fullword ascii
		$v4_3 = "base64str" fullword ascii
		$v4_4 = "stringKey" fullword ascii
		$v4_5 = "BytesToStringConverted" fullword ascii
		$v4_6 = "FromBase64" fullword ascii
		$v4_7 = "xoredString" fullword ascii
		$v4_8 = "procName" fullword ascii
		$v4_9 = "base64EncodedData" fullword ascii
		$v5_1 = "DownloadAndExecuteUpdate" fullword ascii
		$v5_2 = "ITaskProcessor" fullword ascii
		$v5_3 = "CommandLineUpdate" fullword ascii
		$v5_4 = "DownloadUpdate" fullword ascii
		$v5_5 = "FileScanning" fullword ascii
		$v5_6 = "GetLenToPosState" fullword ascii
		$v5_7 = "RecordHeaderField" fullword ascii
		$v5_8 = "EndpointConnection" fullword ascii
		$v5_9 = "BCRYPT_KEY_LENGTHS_STRUCT" fullword ascii
		$v6_1 = "%localappdata%\\" fullword wide
		$v6_2 = "GetDecoded" fullword ascii
		$v6_3 = "//settinString.Removeg[@name=\\PasswString.Removeord\\]/valuString.RemoveeROOT\\SecurityCenter" fullword wide
		$v6_4 = "AppData\\Roaming\\ //settString.Replaceing[@name=\\UString.Replacesername\\]/vaString.Replaceluemoz_cookies" wide
		$v6_5 = "<GetWindowsVersion>g__HKLM_GetString|11_0" fullword ascii
		$v6_6 = "net.tcp://" fullword wide
	condition:
		( uint16(0)==0x5a4d and 
			( all of ($s*) or 
				2 of ($x*) or 
				7 of ($u*) or 
				7 of ($pat*) or 
				(1 of ($x*) and 
					(5 of ($u*) or 
						2 of ($pat*))) or 
				5 of ($v2*) or 
				4 of ($v3*) or 
				(3 of ($v2*) and 
					(2 of ($pat*) or 
						2 of ($u*)) or 
					(1 of ($vx4*) and 
						5 of ($v4*)) or 
					5 of ($v4*) or 
					6 of ($v5*)) or 
				5 of ($v6*) or 
				(4 of ($v6*) and 
					3 of them ))) or 
		(( all of ($x*) and 
				4 of ($s*)) or 
			(4 of ($v6*) and 
				4 of them ))
}



rule MAL_Malware_Imphash_Mar23_1 : HIGHVOL {
    meta:
        description = "Detects malware by known bad imphash or rich_pe_header_hash"
        reference = "https://yaraify.abuse.ch/statistics/"
        license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
        author = "Arnim Rupp"
        date = "2023-03-20"
        modified = "2023-03-22"
        score = 75
        hash = "167dde6bd578cbfcc587d5853e7fc2904cda10e737ca74b31df52ba24db6e7bc"
        hash = "0a25a78c6b9df52e55455f5d52bcb3816460001cae3307b05e76ac70193b0636"
        hash = "d87a35decd0b81382e0c98f83c7f4bf25a2b25baac90c9dcff5b5a147e33bcc8"
        hash = "5783bf969c36f13f4365f4cae3ec4ee5d95694ff181aba74a33f4959f1f19e8b"
        hash = "4ca925b0feec851d787e7ee42d263f4c08b0f73f496049bdb5d967728ff91073"
        hash = "9c2d2fa9c32fdff1828854e8cc39160dae73a4f90fb89b82ef6d853b63035663"
        hash = "2c53d58f30b2ee1a2a7746e20f136c34d25d0214261783fc67e119329d457c2a"
        hash = "5e83747015b0589b4f04b0db981794adf53274076c1b4acf717e3ff45eca0249"
        hash = "ceaa0af90222ff3a899b9a360f6328cbda9ec0f5fbd18eb44bdc440470bb0247"
        hash = "82fb1ba998dfee806a513f125bb64c316989c36c805575914186a6b45da3b132"
        hash = "cb41d2520995abd9ba8ccd42e53d496a66da392007ea6aebd4cbc43f71ad461a"
        hash = "c7bd758506b72ee6db1cc2557baf745bf9e402127d8e49266cc91c90f3cf3ed5"
        hash = "e6e0d60f65a4ea6895ff97df340f6d90942bbfa402c01bf443ff5b4641ff849f"
        hash = "e8ddef9fa689e98ba2d48260aea3eb8fa41922ed718b7b9135df6426b3ddf126"
        hash = "ad57d77aba6f1bf82e0affe4c0ae95964be45fb3b7c2d6a0e08728e425ecd301"
        hash = "483df98eb489899bc89c6a0662ca8166c9b77af2f6bedebd17e61a69211843d9"
        hash = "a65ed85851d8751e6fe6a27ece7b3879b90866a10f272d8af46fb394b46b90a9"
        hash = "09081e04f3228d6ef2efc1108850958ed86026e4dfda199852046481f4711565"
        hash = "1b2c9054f44f7d08cffe7e2d9127dbd96206ab2c15b63ebf6120184950336ae1"
        hash = "257887d1c84eb15abb2c3c0d7eb9b753ca961d905f4979a10a094d0737d97138"
        hash = "1cbad8b58dbd1176e492e11f16954c3c254b5169dde52b5ad6d0d3c51930abf8"
        hash = "a9897fd2d5401071a8219b05a3e9b74b64ad67ab75044b3e41818e6305a8d7b9"
        hash = "aeac45fbc5d2a59c9669b9664400aeaf6699d76a57126d2f437833a3437a693e"
        hash = "7b4c4d4676fab6c009a40d370e6cb53ea4fd73b09c23426fbaccc66d652f2a00"
        hash = "b07f6873726276842686a6a6845b361068c3f5ce086811db05c1dc2250009cd0"
        hash = "d1b3afebcacf9dd87034f83d209b42b0d79e66e08c0a897942fbe5fbd6704a0e"
        hash = "074d52be060751cf213f6d0ead8e9ab1e63f055ae79b5fcbe4dd18469deea12b"
        hash = "84d1fdef484fa9f637ae3d6820c996f6c5cf455470e8717ad348a3d80d2fb8e0"
        hash = "437da123e80cfd10be5f08123cd63cfc0dc561e17b0bef861634d60c8a134eda"
        hash = "f76c36eb22777473b88c6a5fc150fd9d6b5fac5b2db093f0ccd101614c46c7e7"
        hash = "5498b7995669877a410e1c2b68575ca94e79014075ef5f89f0f1840c70ebf942"
        hash = "af4e633acfba903e7c92342b114c4af4e694c5cfaea3d9ea468a4d322b60aa85"
        hash = "d7d870f5afab8d4afa083ea7d7ce6407f88b0f08ca166df1a1d9bdc1a46a41b3"
        hash = "974209d88747fbba77069bb9afa9e8c09ee37ae233d94c82999d88dfcd297117"
        hash = "f2d99e7d3c59adf52afe0302b298c7d8ea023e9338c2870f74f11eaa0a332fc4"
        hash = "b32c93be9320146fc614fafd5e6f1bb8468be83628118a67eb01c878f941ee5d"
        hash = "bbd99acc750e6457e89acbc5da8b2a63b4ef01d4597d160e9cde5dc8bd04cf74"
        hash = "dbff5ca3d1e18902317ab9c50be4e172640a8141e09ec13dcca986f2ec1dc395"
        hash = "3ee1741a649f0b97bbeb05b6f9df97afda22c82e1e870177d8bdd34141ef163c"
        hash = "222096fc800c8ea2b0e530302306898b691858324dbe5b8357f90407e9665b85"
        hash = "b9995d1987c4e8b6fb30d255948322cfad9cc212c7f8f4c5db3ac80e23071533"
        hash = "a6a92ea0f27da1e678c15beb263647de43f68608afe82d6847450f16a11fe6c0"
        hash = "866e3ea86671a62b677214f07890ddf7e8153bec56455ad083c800e6ab51be37"
        id = "fb398c26-e9ac-55f9-b605-6b763021e96a"
    strings:
        $fp1 = "Win32 Cabinet Self-Extractor" wide
        $fp2 = "EXTRACTOPT" ascii fullword
    condition:
        uint16(0) == 0x5A4D and (
            // no size limit as some samples are 20MB+ (ceaa0af90222ff3a899b9a360f6328cbda9ec0f5fbd18eb44bdc440470bb0247) and the hash is calculated only on the header
            pe.imphash() == "9ee34731129f4801db97fd66adbfeaa0" or
            pe.imphash() == "f9e8597c55008e10a8cdc8a0764d5341" or
            pe.imphash() == "0a76016a514d8ed3124268734a31e2d2" or
            pe.imphash() == "d3cbd6e8f81da85f6bf0529e69de9251" or
            pe.imphash() == "d8b32e731e5438c6329455786e51ab4b" or
            pe.imphash() == "cdf5bbb8693f29ef22aef04d2a161dd7" or
            pe.imphash() == "890e522b31701e079a367b89393329e6" or
            pe.imphash() == "bf5a4aa99e5b160f8521cadd6bfe73b8" or
            pe.imphash() == "646167cce332c1c252cdcb1839e0cf48" or
            pe.imphash() == "9f4693fc0c511135129493f2161d1e86" or
            pe.imphash() == "b4c6fff030479aa3b12625be67bf4914" // or
            // these have lots of hits on abuse.ch but none on VT? (except for my one test upload) honeypot collected samples?
            //pe.imphash() == "2c2ad1dd2c57d1bd5795167a7236b045" or
            //pe.imphash() == "46f03ef2495b21d7ad3e8d36dc03315d" or
            //pe.imphash() == "6db997463de98ce64bf5b6b8b0f77a45" or
            //pe.imphash() == "c9246f292a6fdc22d70e6e581898a026" or
            //pe.imphash() == "c024c5b95884d2fe702af4f8984b369e" or
            //pe.imphash() == "4dcbc0931c6f88874a69f966c86889d9" or
            //pe.imphash() == "48521d8a9924bcb13fd7132e057b48e1" or
            // rich_pe_header_hash:b6321cd8142ea3954c1a27b162787f7d p:2+ has 238k hits on VT including many files without imphash (e.g. e193dadf0405a826b3455185bdd9293657f910e5976c59e960a0809b589ff9dc) due to being corrupted?
            // zero hits with p:0
            // disable bc it's killing performance
            //hash.md5(pe.rich_signature.clear_data) == "b6321cd8142ea3954c1a27b162787f7d"
        )
        and not 1 of ($fp*)
}



rule Suspicious_APIs_Registry_Hashes
{
    meta:
        description = "Detects suspicious use of API calls, a specific registry key, and hash values"
        author = "Dharmik Sanneganti"
		sample = "18c2ad1d4db2011971f1a67a82762cc48d3e6c4f2e5d27fbc719bff465f98933"
        date = "2024-11-28"
        version = "1.0"

    strings:
        $GetDC = "GetDC@user32.dll"
        $GetDIBits = "GetDIBits@gdi32.dll"
        $CreateCompatibleDC = "CreateCompatibleDC@gdi32.dll"
        $CreateCompatibleBitmap = "CreateCompatibleBitmap@gdi32.dll"
        $BitBlt = "BitBlt@gdi32.dll"
        $GetLogicalDriveStringsA = "GetLogicalDriveStringsA@kernel32.dll"
        $GetDriveTypeA = "GetDriveTypeA@kernel32.dll"
        $registry_key = "SOFTWARE\\Borland\\Delphi\\RTL"
        $sha256_hash1 = "fb176a7d735dd977472c70a0fcb12715d652a46701d6f7d7c0a6e378a4327c83"
        $sha256_hash2 = "6389684b4c4ad12dc53c8cbbce4cf65f283c8fb4d8b98d90df7485a9424873fa"
        $sha256_hash3 = "6304b3746165216f7526e9bba1e276a262bf71062579d84976e86a2488b7a713"

    condition:
        all of them
}




rule Avaddon
{
    meta:
        id = "gzIxctaiGZf4jXkwWO0BR"
        fingerprint = "ab5c7c5ea9d7d0587e8b2b327c138b2ba21ad6fbbef63f67935dab60f116088f"
        version = "1.0"
        creation_date = "2021-05-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Avaddon ransomware."
        category = "MALWARE"
        malware = "AVADDON"
        malware_type = "RANSOMWARE"
        mitre_att = "S0640"

    strings:
        $s1 = "\"ext\":" ascii wide
        $code = { 83 7f 14 10 8b c7 c7 4? ?? 00 00 00 00 72 ?? 8b 07 6a 00 6a 00 
    8d ?? f8 51 6a 00 6a 01 6a 00 50 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 56 
        8b 7? ?? ff 15 ?? ?? ?? ?? 56 6a 00 50 ff 15 ?? ?? ?? ?? 8b f0 85 
        f6 74 ?? 83 7f 14 10 72 ?? 8b 3f }
        

    condition:
        uint16(0)==0x5a4d and (5 of ($s*) or $code)
}

rule WbemLocator_toWMI {
	meta:
        author = "OPSWAT"
        description = "The file may use IWbemLocator interface to obtain the initial namespace pointer to the interface for WMI "
		score = 70
		//al-khaser_x64.exe_
		//al-khaser_x86.exe_
		//host-interaction/wmi/connect-to-wmi-namespace-via-wbemlocator.yml
	strings:
		$st0 = {11 F8 90 45 3A 1D D0 11 89 1F 00 AA 00 4B 2E 24} // CLSID_WbemLocator
		$st1 = {87 A6 12 DC 7F 73 CF 11 88 4D 00 AA 00 4B 2E 24} // IID_IWbemLocator
	condition:
		all of them and pe.imports("ole32.dll", "CoCreateInstance")
}

rule ITaskSrv_schedule {
	meta:
        author = "OPSWAT"
        description = "The file may set a scheduled task with ITaskService"
        mitre_attack = "T1053.005"
        score = 70
		//03b236b23b1ec37c663527c1f53af3fe.dll_
		//nursery/schedule-task-via-itaskservice.yml
	strings:
		$st0 = {9F 36 87 0F E5 A4 FC 4C BD 3E 73 E6 15 45 72 DD} // CLSID_TaskScheduler
		$st1 = {C7 A4 AB 2F A9 4D 13 40 96 97 20 CC 3F D4 0F 85} // IID_ITaskService
	condition:
		all of them and pe.imports("ole32.dll", "CoCreateInstance")
}

rule DebuggerCheck__RemoteAPI : AntiDebug DebuggerCheck {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="CheckRemoteDebuggerPresent"
	condition:
		any of them
		
}



rule a_1e24560100d010c27cc19c59f9fe1531e4286ecb21fe53763165f30c5f58dc90{
	meta:
	   score=100
	
	strings:
	   $str1 = "WNetGetConnectionW@MPR.dll"
	   $str2 = "OpenProcess@KERNEL32.dll"
	   $str3 = "CreateToolhelp32Snapshot@KERNEL32.dll"
	   $str4 = "Process32FirstW@KERNEL32.dll"
	   $str5 = "Process32NextW@KERNEL32.dll"
	   $str6 = "NetShareEnum@NETAPI32.dll"
	   $str7 = "WNetEnumResourceW@MPR.dll"
	
	condition: 
	   all of them
}
	
rule a_caa8e8a98ef7841c1b230c22f78b5c10aa9348a2bfd0dfe2670853b6d0ba92c
{
	meta:
	score=100
	
	strings:
	$str1 = "SetFileAttributesW@KERNEL32.dll"
	$str2 = "GetVolumePathNamesForVolumeNameW@KERNEL32.dll"
	$str3 = "GetDriveTypeW@KERNEL32.dll"
	$str4 = "FindVolumeClose@KERNEL32.dll"
	$str5 = "FindNextVolumeW@KERNEL32.dll"
	$str6 = "GetLogicalDrives@KERNEL32.dll"
	$str7 = "FindFirstVolumeW@KERNEL32.dll"
	$str8 = "Wow64DisableWow64FsRedirection"
	
	condition: all of them
}

rule x_9adkbdiaiub
{
	meta:
	score=100
	
	strings:
	$str1 = "CreateToolhelp32Snapshot@KERNEL32.dll"
	$str2 = "vssadmin.exe"
	
	condition: all of them
}

rule a2b37a372626063afce9e08199342a41bbe4183b0d5ba7864ff61eb6e6f7c4fdf
{
	meta:
	score=100
	
	strings:
	$str1 = "DuplicateToken@ADVAPI32.dll"
	$str2 = "OpenProcessToken@ADVAPI32.dll"
	$str3 = "GetIpNetTable@IPHLPAPI.DLL"
	$str4 = "vssadmin.exe Delete Shadows /All /Quiet"
	$str5 = "wmic.exe SHADOWCOPY DELETE /nointeractive"
	
	condition: all of them
}

rule e4d1b3c3907d6ad35f69899e5e8244e541e86e643c2628b61f254341ff95ecb52
{
	meta:
	score=100
	
	strings:
	$str1 = "GetComputerNameA@KERNEL32.dll"
	$str2 = "BCryptOpenAlgorithmProvider"
	$str3 = "BCryptDestroyKey"
	$str4 = "BCryptSetProperty"
	$str5 = "BCryptEncrypt"
	
	condition: all of them
}
rule command_and_control {
  meta:
    author = "CD_R0M_"
    description = "This rule searches for common strings found by malware using C2. Based on a sample used by a Ransomware group"
    HundredDaysofYara = "7"
    
  strings:
    $a1 = "WSACleanup" nocase
    $a2 = "WSAGetLastError" nocase
    $a3 = "WSAStartup" nocase
    
    $b1 = "accept" nocase
    $b2 = "bind" nocase
    $b3 = "closesocket" nocase
    $b4 = "connect" nocase
    $b5 = "listen" nocase
    $b6 = "recv" nocase
    $b7 = "send" nocase
    $b8 = "socket" nocase
    
    $c1 = "ws2_32.dll"
  
  condition:
   uint16(0) == 0x5a4d and 2 of ($a*) and 4 of ($b*) and $c1
}

