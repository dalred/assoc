<#Механизм работы такой, cmd /c assoc создает ассоциацию расширения файла к типу в root,
далее ftype связывает его с программой для выполнения, то есть по сути названия типов могут быть любимыми.
Но есть случай в котором эти ассоциации не помогут, случай когда пользователь выбрал программу по умолчанию сам(открыть с помощью),
в этом случае начинает действовать ветка Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts в Сurrent user,
поэтому там тоже необходимо внести изменения, поскольку cmdlet не всегда хорошо отрабатывают в Powershell 2.0, когда работает с реестром, 
мы воспользовались сборкой Microsoft.Win32.Registry, небольшие нарекания есть, но в целом отрабатывает хорошо.
#>


[System.Text.Encoding]::GetEncoding("cp866") | Out-Null
$HKUpath = "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"
$Logfile = "$env:TEMP\assocscript_$env:computername.log"
[System.Windows.Clipboard]::SetText($Logfile)

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
		"МойОфис Текст"	      = @{path="$program\MyOffice\MyOffice Text.exe"; name=("TextEditor.docx", "TextEditor.doc", "TextEditor.rtf")};
		"МойОфис Таблица"	  = @{path="$program\MyOffice\MyOffice Spreadsheet.exe"; name=("SpreadsheetEditor.xls", "SpreadsheetEditor.xlsx", "SpreadsheetEditor.csv", "SpreadsheetEditor.xlsm")};
		"МойОфис Презентация" = @{path="$program\MyOffice\MyOffice Presentation.exe"; name=("PresentationViewer.pptx", "PresentationViewer.ppt")};
	}
	$MyPSObject = New-Object -TypeName psobject -Property $hash_object
	$RegistryValueKind = [Microsoft.Win32.RegistryValueKind]::String
	
	$MyPSObject.PSObject.Properties | ForEach-Object {
		$name = $_.Name
		$_.Value | ForEach-Object {
        $path=$_.path
            if (-Not (Test-Path -Path $path))
    		{
    			throw ("Не существует пути: {0}" -f $path)
    		}
            $_.name| ForEach-Object {
                $ftype = $_
                $Ext = $ftype.Split(".")[1]
                WriteLog -LogString "assoc .$Ext=$ftype"
                $cmdOutput=cmd /c assoc `".$Ext`"=`""$ftype`"" 2>&1
                WriteLog -LogString "ftype $ftype=$path"
                $cmdOutput+=cmd /c ftype `"$ftype`"=`""$path`"" `""%1`"" 2>&1
                if ($LASTEXITCODE -ne 0) {
                    throw ($cmdOutput)
                }
			    $parent = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey($ftype, $true)
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
				    $RegistryValueKind = [Microsoft.Win32.RegistryValueKind]::String
				    WriteLog -LogString "CreateSubKey DefaultIcon"
				    $parent.CreateSubKey("DefaultIcon") | out-null
				    $parent_user = $parent.OpenSubKey('DefaultIcon', $true)
				    $ExtUP = $Ext.ToUpper()
				    WriteLog -LogString "SetValue to DefaultIcon $program\MyOffice\$ExtUP.ico"
				    $parent_user.SetValue($null, """$program\MyOffice\$ExtUP.ico""", $RegistryValueKind)
				    $parent_user.Close()
				
			    }
			    $parent.Close()
			    $parent = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("$HKUpath\.$Ext", $true)
			    $Progid = [Microsoft.Win32.Registry]::GetValue("HKEY_CURRENT_USER\$HKUpath\.$Ext\UserChoice", "Progid", $null)
			    $RegistryValueKind = [Microsoft.Win32.RegistryValueKind]::String
			    if ($Progid)
			    {
				    WriteLog -LogString "Progid was $Progid"
				    WriteLog -LogString "DeleteSubKey UserChoice in $ftype type $Ext"
				    $parent.DeleteSubKey('UserChoice', $true)
				    WriteLog -LogString "CreateSubKey UserChoice  in $ftype type $Ext"
				    $parent.CreateSubKey("UserChoice") | out-null
				    $parent_user = $parent.OpenSubKey('UserChoice', $true)
				    WriteLog -LogString "SetValue Progid $ftype type $Ext"
				    $parent_user.SetValue("Progid", $ftype, $RegistryValueKind)
				    $parent_user.Close()
			    }
			    $parent.Close()
		    }
	    }
    }
	
}

if (-Not (Test-Path -Path HKCR:\))
{
	New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR | Out-Null
}

if (-Not (Test-Path -Path HKU:\))
{
	New-PSDrive -PSProvider registry -Root HKEY_USERS -Name HKU | Out-Null
}


if ([IntPtr]::Size -eq 8)
{
	try
	{
		main -program $env:ProgramFiles
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
}
else
{
	try
	{
		main -program ${env:ProgramFiles(x86)}
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
}



