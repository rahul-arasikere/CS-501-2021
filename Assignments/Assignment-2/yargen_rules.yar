/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2021-10-19
   Identifier: bad
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule UpdateCheck {
   meta:
      description = "bad - file UpdateCheck.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-10-19"
      hash1 = "9d5a1eecd236d61e3242850d0487808091fc5d0db0a3e45be8970bdbf1fdff88"
   strings:
      $s1 = "http://ch0nky.chickenkiller.com/update.exe" fullword wide
      $s2 = "C:\\malware\\ch0nky.txt" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule bad_update {
   meta:
      description = "bad - file update.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-10-19"
      hash1 = "da7d6cebf27b080486d471f56b8145ba2a4ae862fae6e9a8ce0c7ed8ac9a6de1"
   strings:
      $s1 = "powershell.exe /c " fullword ascii
      $s2 = "ch0nky.chickenkiller.com" fullword wide
      $s3 = "C:\\malware\\ch0nky.txt" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule BU_IT_Support {
   meta:
      description = "bad - file BU-IT-Support.doc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-10-19"
      hash1 = "e1edd1835f00026da05761a0be84779ac6383b00872366ebdb8411a5eeb7792f"
   strings:
      $x1 = "powershell.exe kill -processname winword" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 2000KB and
      1 of ($x*)
}

/* Super Rules ------------------------------------------------------------- */

rule _UpdateCheck_update_0 {
   meta:
      description = "bad - from files UpdateCheck.exe, update.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-10-19"
      hash1 = "9d5a1eecd236d61e3242850d0487808091fc5d0db0a3e45be8970bdbf1fdff88"
   strings:
      $s1 = "C:\\malware\\ch0nky.txt" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

