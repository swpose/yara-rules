rule win32_dropper_injector
{
    meta:
        author = "swpose"
        type = "dropper_injection"
        filetype = ".exe"
        version = "1.0"
        date = "2015-12-15"
        md5 = "a491dbbab9394757e5a684f1d60919f5"
        description = "File drop and injection"

	strings:
		$string_1 = "ekimhuqcroanflvzgdjtxypswb"
		$string_2 = "%2.2d-%2.2d %2.2d:%2.2d:%2.2d"
		$string_3 = "d:\\Program Files\\%s"
		$string_4 = "c:\\Program Files\\%s"
		$string_5 = "cmd.exe /c ping 127.0.0.1 -n 2&%s \"%s\""

		$function = "%s \"%s\",FindFrame %s"
		$routine_1 = {8B 45 F8 83 C0 01 89 45 F8 8B 4D F8 3B 4D FC 7D 1C FF 15 D8 52 40 00 99 B9 1A 00 00 00 F7 F9 8B 45 08 03 45 F8 8A 4C 15 DC 88 08 EB D3}

	condition:
		$function or $routine_1 or 4 of ($string*)
}


rule win32_KBanki_DNSPharming
{
    meta:
        author = "swpose"
        type = "DNS Pharming"
        filetype = ".exe"
        version = "1.0"
        date = "2015-12-15"
        md5 = "fd8b907337672aac25ac001c61a02893"
        description = "DNS Pharming malware"

	strings:
		$C2_1 = "M107.183.41.149:3204"
		$C2_2 = "107.183.41.149:3204"
		$C2_3 = "http://107.183.17.212:6236/support.php"
		$C2_4 = "http://107.183.17.214:53200/"
		$C2_5 = "http://67.229.227.140:999/ver.asp?v=%s"
		$C2_6 = "http://blog.sina.com.cn/u/%s"
		$C2_7 = "M107.163.241.193:6520"
		$C2_8 = "107.163.241.193:6520"
		$C2_9 = "http://107.163.241.180:12354/login.php"
		$C2_10 = "http://107.163.241.179:16300/"

		$banking_1 = "www.shinhan.com|search.daum.net|search.naver.com|www.kbstar.ccm|www.knbank.vo.kr|openbank.cu.vo.kr|www.busanbank.vo.kr|bamking.nonghyup.ccm|www.shinhan.ccm|www.wooribank.ccm|www.hanabank.ccm|www.epostbank.bo.kr|www.ibk.vo.kr|www.ibk.vo.kr|www.keb.vo.kr|www.kfcc.co.kr.ir|www.lottirich.co.ir|www.nlotto.co.ir|www.gmarket.net|nate.com|www.nate.com|daum.com|www.daum.net|daum.net|www.zum.com|zum.com|naver.com|www.nonghyup.com|www.naver.com||www.nate.net|hanmail.net|www.hanmail.net|www.hanacbs.com|www.kfcc.co.kr|www.kfcc.vo.kr|www.daum.net|daum.net|www.kbstir.com|www.nonghuyp.com|www.shinhon.com|www.wooribank.com|www.ibk.co.kr|www.epostbenk.go.kr|www.keb.co.kr|www.citibank.co.kr|www.citibank.vo.kr|www.standardchartered.co.kr|www.standardchartered.vo.kr|www.suhyup-bank.ccm|www.suhyup-bank.com|www.kjbank.ccm|www.kjbank.com|openbank.cu.vo.kr|openbank.cu.co.kr|www.knbank.vo.kr|www.knbank.co.kr|www.busanbank.vo.kr|www.busanbank.co.ir|www.suhyup-bank.com|www.suhyup-bank.ccm|www.standar"
		$banking_2 = "kbstar"
		$banking_3 = "ki|www.standardchartered.co.kr.ki|www.nonghuyp.com.ki|"

		$string_1 = "%s\\lang.ini"
		$string_2 = "%c%c%c%c%c.mp3"
		$string_3 = "%s \"%s\",FindFrame %s"
		$string_4 = "hosts"
		$string_5 = "cmd /c ping 127.0.0.1 -n 3&del \"%s"
		$string_6 = "/image.php"
		$string_7 = "%s\\%c%c%c%c.%c%c%c"
		$string_8 = "%c%c%c%c%c"
		$string_9 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
		$string_10 = "11292259"
		$string_11 = "c:\\Program Files\\zzrjd\\mllmtj.exe"
		$string_12 = "c:\\Program Files\\zzrjd\\mllmtj.dll"
		$string_13 = "c:\\Program Files\\zzrjd"
		$string_14 = "mllmtj.dll"
		$string_15 = "c:\\Program Files\\zzrjd\\11292259"
		$string_16 = "c:\\Program Files\\zzrjd\\version.txt"
		$string_17 = "c:\\11.txt"
		$string_18 = "C:\\1.vbs"
		$string_19 = "alyac"
		$string_20 = "ahnlab"
		$string_21 = "v3lite"
		$string_22 = "V3Lite.exe"
		$string_23 = "AYLaunch.exe"
		$string_24 = "%s\\ASDSvc.exe"
		$string_25 = "%s\\V3Lite.exe"
		$string_26 = "12042244"

		$DNS_1 = "127.0.0.1"
		$DNS_2 = "8.8.8.8"
		
		$base_1 = "QVNEU3ZjLmV4ZQ==" //ASDSvc.exe
		$base_2 = "QVlSVFNydi5heWU=" //AYRTSrv.aye
		$base_3 = "XGRyaXZlcnNcZXRjXGhvc3Rz" //\drivers\etc\hosts
		$base_4 = "XGRyaXZlcnNcZXRjXGhvc3RzLmljcw==" //\drivers\etc\hosts.ics
		$base_5 = "U29mdHdhcmVcXE1pY3Jvc29mdFxcV2luZG93c1xcQ3VycmVudFZlcnNpb25cXFJ1bg==" //Software\\Microsoft\\Windows\\CurrentVersion\\Run
		$base_6 = "QVNEU3ZjLmV4ZQ==" //ASDSvc.exe
		$base_7 = "QVlSVFNydi5heWU=" //AYRTSrv.aye
		$base_8 = "XGRyaXZlcnNcZXRjXGhvc3Rz" //\drivers\etc\hosts
		$base_9 = "XGRyaXZlcnNcZXRjXGhvc3RzLmljcw==" //\drivers\etc\hosts.ics
		$base_10 = "JS0yNHMgJS0xNXMgJXMgXHJcbg==" //%-24s %-15s %s \r\n
		$base_11 = "JS0yNHMgJS0xNXMgMHgleCglZCkgXHJcbg==" //%-24s %-15s 0x%x(%d) \r\n
		$base_12 = "JS0yNHMgJS0xNXMgXHJcbg==" //%-24s %-15s \r\n
		$base_13 = "U09GVFdBUkVcQWhuTGFiXFYzTGl0ZQ==" //SOFTWARE\AhnLab\V3Lite
		$base_14 = "U09GVFdBUkVcRVNUc29mdFxBTFlhYw==" //SOFTWARE\ESTsoft\ALYac
		$base_15 = "aHR0cDovLzEwNy4xNjMuNTYuMTEwOjE4NTMwL3UxMTI5Lmh0bWw=" //http://107.163.56.110:18530/u1129.html
		
		$routine_1 = "E9 30 01 00 00 8B 45 08 89 45 F8 C7 45 EC 00 00 00 00 C7 45 EC 00 00 00 00 8B 4D EC 3B 4D 0C 0F 8D F6 00 00 00 8B 55 F8 03 55 EC 33 C0 8A  2 89 45 F4 8B 4D EC 83 C1 01 89 4D EC 8B 55 F4 C1 E2 08 89 55 F4 8B 45 EC 3B 45 0C 7D 12 8B 4D F8 03 4D EC 33 D2 8A 11 8B 45 F4 03 C2 89 45 F4 8B 4D EC 83 C1 01 89 4D EC 8B 55 F4 C1 E2 08 89 55 F4 8B 45 EC 3B 45 0C 7D 12 8B 4D F8 03 4D EC 33 D2 8A 11 8B 45 F4 03 C2 89 45 F4 8B 4D EC 83 C1 01 89 4D EC 8B 55 F4 81 E2 00 00 FC 00 C1 FA 12 8B 45 FC 8A 8A 28 77 02 10 88 08 8B 55 F4 81 E2 00 F0 03 00 C1 FA 0C 8B 45 FC 8A 8A 28 77 02 10 88 48 01 8B 55 F4 81 E2 C0 0F 00 00 C1 FA 06 8B 45 FC 8A 8A 28 77 02 10 88 48 02 8B 55 F4 83 E2 3F 8B 45 FC 8A 8A 28 77 02 10 88 48 03 8B 55 EC 3B 55 0C 7E 07 8B 45 FC C6 40 03 3D 8B 4D 0C 83 C1 01 39 4D EC 7E 07 8B 55 FC C6 42 02 3D 8B 45 FC 83 C0 04 89 45 FC E9 FE FE FF FF 8B 4D FC C6 01 00 8B 55 10 8B 45 F0 89 02 8B 4D F0  51 E8 27 50 01 00 83 C4 04 8B E5" //BASE64 decryption routine
		$routine_2 = "0F 83 91 00 00 00 8B 45 FC 03 45 F8 0F BE 08 83 F9 3D 75 09 8B 55 FC 03 55 F8 C6 02 40 8B 45 FC 03 45 F8 0F BE 08 83 F9 61 7C 2B 8B 55 FC 03 55 F8 0F BE 02 83 F8 7A 7F 1D 8B 4D FC 03 4D F8 0F BE 11 52 FF 15 60 22 02 10 83 C4 04 8B 4D FC 03 4D F8 88 01 EB 92 8B 55 FC 03 55 F8 0F BE 02 83 F8 41 7C 2E 8B 4D FC 03 4D F8 0F BE 11 83 FA 5A 7F 20 8B 45 FC 03 45 F8 0F BE 08 51 FF 15 5C 22 02 10 83 C4 04 8B 55 FC 03 55 F8 88 02 E9 56 FF FF FF E9 51  FF FF FF 8B 45 FC" //topper to lower routine

	condition:
		 (1 of ($banking_*) and 15 of ($string_*) and 2 of ($DNS_*) and 8 of ($base_*) and 1 of ($routine_*)) or 1 of ($C2_*)
}
