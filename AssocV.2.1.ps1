﻿<# Скрипт написан для текущего пользователя,
Механизм работы такой, cmd /c assoc создает ассоциацию расширения файла к типу в root,
далее ftype связывает его с программой для выполнения, то есть по сути названия типов могут быть любимыми.
Но есть случай в котором эти ассоциации не помогут, случай когда пользователь выбрал программу по умолчанию сам(открыть с помощью),
в этом случае начинает действовать ветка Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts в Сurrent user,
поэтому там тоже необходимо внести изменения, поскольку cmdlet не всегда хорошо отрабатывают в Powershell 2.0, когда работает с реестром, 
мы воспользовались сборкой Microsoft.Win32.Registry, небольшие нарекания есть, но в целом отрабатывает хорошо.
#>


[System.Text.Encoding]::GetEncoding("cp866") | Out-Null
Add-Type -Assembly PresentationCore


$Logfile = "$env:TEMP\assocscript_$env:computername.log"
[System.Windows.Clipboard]::SetText($Logfile)
$Version = ([environment]::OSVersion.Version).Major

function bitshift
{
	param (
		[Int64]$x,
		[int]$Left,
		[int]$Right)
	
	$shift = if ($PSCmdlet.ParameterSetName -eq 'Left')
	{
		$Left
	}
	else
	{
		-$Right
	}
	$result = [Int64]([math]::Floor($x * [math]::Pow(2, $shift)))
	return $result
}

function Get-UserExperience
{
	$userExperienceSearch = "User Choice set via Windows User Experience"
	$user32Path = [Environment]::GetFolderPath([Environment+SpecialFolder]::SystemX86) + "\Shell32.dll"
	$fileStream = [System.IO.File]::Open($user32Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
	$binaryReader = New-Object System.IO.BinaryReader($fileStream)
	[Byte[]]$bytesData = $binaryReader.ReadBytes(5mb)
	$fileStream.Close()
	$dataString = [Text.Encoding]::Unicode.GetString($bytesData)
	$position1 = $dataString.IndexOf($userExperienceSearch)
	$position2 = $dataString.IndexOf("}", $position1)
	
	Write-Output $dataString.Substring($position1, $position2 - $position1 + 1)
}

function Get-UserSid
{
	$userSid = ((New-Object System.Security.Principal.NTAccount([Environment]::UserName)).Translate([System.Security.Principal.SecurityIdentifier]).value).ToLower()
	Write-Output $userSid
}

function Get-HexDateTime
{
	$now = [DateTime]::Now
	$dateTime = [DateTime]::New($now.Year, $now.Month, $now.Day, $now.Hour, $now.Minute, 0)
	$fileTime = $dateTime.ToFileTime()
	$hi = bitshift -x $fileTime -Right 32
	$low = ($fileTime -band 0xFFFFFFFFL)
	$dateTimeHex = ($hi.ToString("X8") + $low.ToString("X8")).ToLower()
	Write-Output $dateTimeHex
}

function Get-Hash
{
	param (
		[Parameter(Position = 0, Mandatory = $True)]
		[string]$BaseInfo
	)
	
	
	function local:Get-ShiftRight
	{
		[CmdletBinding()]
		param (
			[Parameter(Position = 0, Mandatory = $true)]
			[long]$iValue,
			[Parameter(Position = 1, Mandatory = $true)]
			[int]$iCount
		)
		
		if ($iValue -band 0x80000000)
		{
			Write-Output ((bitshift -x $iValue -Right $iCount) -bxor 0xFFFF0000)
		}
		else
		{
			Write-Output  (bitshift -x $iValue -Right $iCount)
		}
	}
	
	
	function local:Get-Long
	{
		[CmdletBinding()]
		param (
			[Parameter(Position = 0, Mandatory = $true)]
			[byte[]]$Bytes,
			[Parameter(Position = 1)]
			[int]$Index = 0
		)
		
		Write-Output ([BitConverter]::ToInt32($Bytes, $Index))
	}
	
	
	function local:Convert-Int32
	{
		param (
			[Parameter(Position = 0, Mandatory = $true)]
			$Value
		)
		
		[byte[]]$bytes = [BitConverter]::GetBytes($Value)
		return [BitConverter]::ToInt32($bytes, 0)
	}
	
	[Byte[]]$bytesBaseInfo = [System.Text.Encoding]::Unicode.GetBytes($baseInfo)
	$bytesBaseInfo += 0x00, 0x00
	
	$MD5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
	[Byte[]]$bytesMD5 = $MD5.ComputeHash($bytesBaseInfo)
	
	$lengthBase = ($baseInfo.Length * 2) + 2
	$length = (($lengthBase -band 4) -le 1) + (Get-ShiftRight $lengthBase  2) - 1
	$base64Hash = ""
	
	if ($length -gt 1)
	{
		
		$map = @{
			PDATA = 0; CACHE = 0; COUNTER = 0; INDEX = 0; MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0;
			R0    = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0; R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0)
		}
		
		$map.CACHE = 0
		$map.OUTHASH1 = 0
		$map.PDATA = 0
		$map.MD51 = (((Get-Long $bytesMD5) -bor 1) + 0x69FB0000L)
		$map.MD52 = ((Get-Long $bytesMD5 4) -bor 1) + 0x13DB0000L
		$map.INDEX = Get-ShiftRight ($length - 2) 1
		$map.COUNTER = $map.INDEX + 1
		
		while ($map.COUNTER)
		{
			$map.R0 = Convert-Int32 ((Get-Long $bytesBaseInfo $map.PDATA) + [long]$map.OUTHASH1)
			$map.R1[0] = Convert-Int32 (Get-Long $bytesBaseInfo ($map.PDATA + 4))
			$map.PDATA = $map.PDATA + 8
			$map.R2[0] = Convert-Int32 (($map.R0 * ([long]$map.MD51)) - (0x10FA9605L * ((Get-ShiftRight $map.R0 16))))
			$map.R2[1] = Convert-Int32 ((0x79F8A395L * ([long]$map.R2[0])) + (0x689B6B9FL * (Get-ShiftRight $map.R2[0] 16)))
			$map.R3 = Convert-Int32 ((0xEA970001L * $map.R2[1]) - (0x3C101569L * (Get-ShiftRight $map.R2[1] 16)))
			$map.R4[0] = Convert-Int32 ($map.R3 + $map.R1[0])
			$map.R5[0] = Convert-Int32 ($map.CACHE + $map.R3)
			$map.R6[0] = Convert-Int32 (($map.R4[0] * [long]$map.MD52) - (0x3CE8EC25L * (Get-ShiftRight $map.R4[0] 16)))
			$map.R6[1] = Convert-Int32 ((0x59C3AF2DL * $map.R6[0]) - (0x2232E0F1L * (Get-ShiftRight $map.R6[0] 16)))
			$map.OUTHASH1 = Convert-Int32 ((0x1EC90001L * $map.R6[1]) + (0x35BD1EC9L * (Get-ShiftRight $map.R6[1] 16)))
			$map.OUTHASH2 = Convert-Int32 ([long]$map.R5[0] + [long]$map.OUTHASH1)
			$map.CACHE = ([long]$map.OUTHASH2)
			$map.COUNTER = $map.COUNTER - 1
		}
		
		[Byte[]]$outHash = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
		[byte[]]$buffer = [BitConverter]::GetBytes($map.OUTHASH1)
		$buffer.CopyTo($outHash, 0)
		$buffer = [BitConverter]::GetBytes($map.OUTHASH2)
		$buffer.CopyTo($outHash, 4)
		
		$map = @{
			PDATA = 0; CACHE = 0; COUNTER = 0; INDEX = 0; MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0;
			R0    = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0; R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0)
		}
		
		$map.CACHE = 0
		$map.OUTHASH1 = 0
		$map.PDATA = 0
		$map.MD51 = ((Get-Long $bytesMD5) -bor 1)
		$map.MD52 = ((Get-Long $bytesMD5 4) -bor 1)
		$map.INDEX = Get-ShiftRight ($length - 2) 1
		$map.COUNTER = $map.INDEX + 1
		
		while ($map.COUNTER)
		{
			$map.R0 = Convert-Int32 ((Get-Long $bytesBaseInfo $map.PDATA) + ([long]$map.OUTHASH1))
			$map.PDATA = $map.PDATA + 8
			$map.R1[0] = Convert-Int32 ($map.R0 * [long]$map.MD51)
			$map.R1[1] = Convert-Int32 ((0xB1110000L * $map.R1[0]) - (0x30674EEFL * (Get-ShiftRight $map.R1[0] 16)))
			$map.R2[0] = Convert-Int32 ((0x5B9F0000L * $map.R1[1]) - (0x78F7A461L * (Get-ShiftRight $map.R1[1] 16)))
			$map.R2[1] = Convert-Int32 ((0x12CEB96DL * (Get-ShiftRight $map.R2[0] 16)) - (0x46930000L * $map.R2[0]))
			$map.R3 = Convert-Int32 ((0x1D830000L * $map.R2[1]) + (0x257E1D83L * (Get-ShiftRight $map.R2[1] 16)))
			$map.R4[0] = Convert-Int32 ([long]$map.MD52 * ([long]$map.R3 + (Get-Long $bytesBaseInfo ($map.PDATA - 4))))
			$map.R4[1] = Convert-Int32 ((0x16F50000L * $map.R4[0]) - (0x5D8BE90BL * (Get-ShiftRight $map.R4[0] 16)))
			$map.R5[0] = Convert-Int32 ((0x96FF0000L * $map.R4[1]) - (0x2C7C6901L * (Get-ShiftRight $map.R4[1] 16)))
			$map.R5[1] = Convert-Int32 ((0x2B890000L * $map.R5[0]) + (0x7C932B89L * (Get-ShiftRight $map.R5[0] 16)))
			$map.OUTHASH1 = Convert-Int32 ((0x9F690000L * $map.R5[1]) - (0x405B6097L * (Get-ShiftRight ($map.R5[1]) 16)))
			$map.OUTHASH2 = Convert-Int32 ([long]$map.OUTHASH1 + $map.CACHE + $map.R3)
			$map.CACHE = ([long]$map.OUTHASH2)
			$map.COUNTER = $map.COUNTER - 1
		}
		
		$buffer = [BitConverter]::GetBytes($map.OUTHASH1)
		$buffer.CopyTo($outHash, 8)
		$buffer = [BitConverter]::GetBytes($map.OUTHASH2)
		$buffer.CopyTo($outHash, 12)
		
		[Byte[]]$outHashBase = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
		$hashValue1 = ((Get-Long $outHash 8) -bxor (Get-Long $outHash))
		$hashValue2 = ((Get-Long $outHash 12) -bxor (Get-Long $outHash 4))
		
		$buffer = [BitConverter]::GetBytes($hashValue1)
		$buffer.CopyTo($outHashBase, 0)
		$buffer = [BitConverter]::GetBytes($hashValue2)
		$buffer.CopyTo($outHashBase, 4)
		$base64Hash = [Convert]::ToBase64String($outHashBase)
	}
	
	Write-Output $base64Hash
}

$HKUpath = "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"
$HKUclass = "SOFTWARE\Classes"


function Update-RegistryChanges
{
	$code = @'
    [System.Runtime.InteropServices.DllImport("Shell32.dll")] 
    private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);
    public static void Refresh() {
        SHChangeNotify(0x8000000, 0, IntPtr.Zero, IntPtr.Zero);    
    }
'@
	
	try
	{
		Add-Type -MemberDefinition $code -Namespace SHChange -Name Notify
	}
	catch { }
	
	try
	{
		[SHChange.Notify]::Refresh()
	}
	catch { }
}

#Логирование по желанию.
function WriteLog
{
	Param ([string]$LogString)
	$Stamp = (Get-Date).toString("dd.MM.yyyy HH:mm:ss")
	$LogMessage = "{0}: {1}" -f $Stamp, $LogString
	Add-content $LogFile -value $LogMessage
}
#Работаем в HKEY_USERS, HKUpath, применяем команды ftype и assoc
function main
{
	param ($program)
	$hash_object = @{
		"МойОфис Текст" = @{ path = "$program\MyOffice\MyOffice Text.exe"; name = ("TextEditor.docx", "TextEditor.doc", "TextEditor.rtf") };
		"МойОфис Таблица" = @{ path = "$program\MyOffice\MyOffice Spreadsheet.exe"; name = ("SpreadsheetEditor.xls", "SpreadsheetEditor.xlsx", "SpreadsheetEditor.csv", "SpreadsheetEditor.xlsm") };
		"МойОфис Презентация" = @{ path = "$program\MyOffice\MyOffice Presentation.exe"; name = ("PresentationViewer.pptx", "PresentationViewer.ppt") };
	}
	$MyPSObject = New-Object -TypeName psobject -Property $hash_object
	$RegistryValueKind = [Microsoft.Win32.RegistryValueKind]::String
	$MyPSObject.PSObject.Properties | ForEach-Object {
		$name = $_.Name
		$_.Value | ForEach-Object {
			$path = $_.path
			if (-Not (Test-Path -Path $path))
			{
				throw ("Не существует пути: {0}" -f $path)
			}
			$_.name | ForEach-Object {
				$ftype = $_
				$Ext = $ftype.Split(".")[1]
				WriteLog -LogString "assoc .$Ext=$ftype"
				$cmdOutput = [string]::Join(" ", (cmd /c assoc `".$Ext`"=`""$ftype`"" 2>&1) + "`n")
				WriteLog -LogString "ftype $ftype=$path"
				$cmdOutput += [string]::Join(" ", (cmd /c ftype `"$ftype`"=`""$path`"" `""%1`"" 2>&1) + "`n")
				if ($LASTEXITCODE -ne 0)
				{
					throw ($cmdOutput)
				}
				<#$OpenWith = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("$HKUpath\.$Ext\OpenWithProgids", $true)
				$OpenWith.SetValue($ftype, ([byte[]]@()), [Microsoft.Win32.RegistryValueKind]::None)
				<#$OpenWith_class = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("$HKUclass\.$Ext\OpenWithProgids", $true)
				$OpenWith_class.SetValue($ftype, ([byte[]]@()), [Microsoft.Win32.RegistryValueKind]::None)#>
				$parent = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey($ftype, $true)
				$parent_Ext = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey(".$Ext", $true)
				$default = $parent_Ext.GetValue($null)
				WriteLog -LogString "Old default=$default"
				if (-not ($default) -or ($default -ne $ftype))
				{
					WriteLog -LogString "CreateSubKey default in $ftype"
					$parent_Ext.SetValue($null, $ftype, $RegistryValueKind)
					$parent_Ext.Close()
				}
				$appKey = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey("$ftype\Application")
				If (-not $appKey)
				{
					WriteLog -LogString "CreateSubKey Application"
					$parent.CreateSubKey("Application") | out-null
					$parent_user = $parent.OpenSubKey('Application', $true)
					WriteLog -LogString "SetValue ApplicationName $name"
					$parent_user.SetValue("ApplicationName", $name, $RegistryValueKind)
					$parent_user.Close()
				}
				$Icon = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey("$ftype\DefaultIcon")
				If (-not $Icon)
				{
					WriteLog -LogString "CreateSubKey DefaultIcon"
					$parent.CreateSubKey("DefaultIcon") | out-null
					$parent_user = $parent.OpenSubKey('DefaultIcon', $true)
					$ExtUP = $Ext.ToUpper()
					WriteLog -LogString "SetValue to DefaultIcon $program\MyOffice\$ExtUP.ico"
					$parent_user.SetValue($null, """$program\MyOffice\$ExtUP.ico""", $RegistryValueKind)
					$parent_user.Close()
					
				}
				$parent.Close()
				$parent = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("$HKUpath\.$Ext", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
				$userchoice = $parent.OpenSubKey("UserChoice")
				
				
				If ($userchoice)
				{
					$Progid = $userchoice.GetValue("Progid")
					If ($Progid -ne $ftype)
					{
						WriteLog -LogString "Progid was $Progid"
						WriteLog -LogString "DeleteSubKey UserChoice in $ftype type $Ext"
						$parent.DeleteSubKey('UserChoice', $true)
						WriteLog -LogString "CreateSubKey UserChoice  in $ftype type $Ext"
						$parent.CreateSubKey("UserChoice") | out-null
						$parent_user = $parent.OpenSubKey('UserChoice', $true)
						WriteLog -LogString "SetValue Progid $ftype type $Ext"
						$parent_user.SetValue("Progid", $ftype, $RegistryValueKind)
						WriteLog -LogString "Version is $Version"
						if ($Version -ge 8)
						{
							$userSid = Get-UserSid
							$userExperience = Get-UserExperience
							$userDateTime = Get-HexDateTime
							$baseInfo = "$Extension$userSid$ProgId$userDateTime$userExperience".ToLower()
							Write-Host $baseInfo
							$progHash = Get-Hash $baseInfo
							Write-Host "$progHash in $ftype type $Ext"
							WriteLog -LogString "SetValue Hash $progHash type $Ext"
							$parent_user.SetValue("Hash", "$progHash", $RegistryValueKind)
						}
						$parent_user.Close()
					}
				}
				$parent.Close()
			}
		}
	}
	
}
try
{
	if ([IntPtr]::Size -eq 8)
	{
		main -program $env:ProgramFiles
		
	}
	else
	{
		main -program ${env:ProgramFiles(x86)}
		
	}
	Update-RegistryChanges
}
catch
{
	$ErrorMessage = $_.Exception.Message
	$FailedItem = $_.Exception.ItemName
	Write-warning ("Ошибка! {0} - {1}" -f $ErrorMessage, $FailedItem)
	WriteLog -LogString ("Ошибка! {0} - {1}" -f $ErrorMessage, $FailedItem)
}
finally
{
	WriteLog -LogString "Finish work!"
}

