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

#Логирование по желанию.
function WriteLog
{
	Param ([string]$LogString)
	$Stamp = (Get-Date).toString("dd.MM.yyyy HH:mm:ss")
	$LogMessage = "{0}: {1}" -f $Stamp, $LogString
	Add-content $LogFile -value $LogMessage
}
#Работаем в HKEY_USERS, HKUpath
function set-items_reg
{
	param ($program)
	$hash_object = @{
		"МойОфис Текст"	      = ("TextEditor.docx", "TextEditor.doc", "TextEditor.rtf");
		"МойОфис Таблица"	  = ("SpreadsheetEditor.xls", "SpreadsheetEditor.xlsx", "SpreadsheetEditor.csv");
		"МойОфис Презентация" = ("PresentationViewer.pptx", "PresentationViewer.ppt")
	}
	$MyPSObject = New-Object -TypeName psobject -Property $hash_object
	$RegistryValueKind = [Microsoft.Win32.RegistryValueKind]::String
	
	$MyPSObject.PSObject.Properties | ForEach-Object {
		$name = $_.Name
		$_.Value | ForEach-Object {
			$ftype = $_
			$Ext = $_.Split(".")[1]
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
				WriteLog -LogString "DeleteSubKey UserChoice in $ftype"
				$parent.DeleteSubKey('UserChoice', $true)
				WriteLog -LogString "CreateSubKey UserChoice  in $ftype"
				$parent.CreateSubKey("UserChoice") | out-null
				$parent_user = $parent.OpenSubKey('UserChoice', $true)
				WriteLog -LogString "SetValue Progid $ftype"
				$parent_user.SetValue("Progid", $ftype, $RegistryValueKind)
				$parent_user.Close()
			}
			$parent.Close()
		}
	}
	
}


function set-assoc
{
	param ($program)
	$path_Spread = "$program\MyOffice\MyOffice Spreadsheet.exe"
	$path_text = "$program\MyOffice\MyOffice Text.exe"
	$path_Present = "$program\MyOffice\MyOffice Presentation.exe"
	
	$pathlist = ($path_Spread, $path_text, $path_Present)
	
	foreach ($i in $pathlist)
	{
		if (-Not (Test-Path -Path $i))
		{
			throw ("Ошибка! Не существует пути: {0}" -f $i)
		}
	}
	
	WriteLog -LogString "Start assoc"
    try {
	cmd /c assoc .xls=SpreadsheetEditor.xls | Out-Null
	cmd /c assoc .xlsx=SpreadsheetEditor.xlsx | Out-Null
	cmd /c assoc  .xlsm=SpreadsheetEditor.xlsx | Out-Null
	cmd /c assoc  .csv=SpreadsheetEditor.csv | Out-Null
	cmd /c assoc  .docx=TextEditor.docx | Out-Null
	cmd /c assoc  .doc=TextEditor.doc | Out-Null
	cmd /c assoc  .rtf=TextEditor.rtf | Out-Null
	cmd /c assoc  .pptx=PresentationViewer.pptx | Out-Null
	cmd /c assoc  .ppt=PresentationViewer.ppt | Out-Null
    } catch {
        throw ("$_.Exception.Message")
    }
	
	WriteLog -LogString "ftype .xls .xlsx .csv"
	cmd /c ftype `"SpreadsheetEditor.xls`"=`""$path_Spread`"" `""%1`"" | Out-Null
	cmd /c ftype `"SpreadsheetEditor.xlsx`"=`""$path_Spread`"" `""%1`"" | Out-Null
	cmd /c ftype `"SpreadsheetEditor.csv`"=`""$path_Spread`"" `""%1`"" | Out-Null
	
	WriteLog -LogString "ftype .docx .doc .rtf"
	cmd /c ftype `"TextEditor.docx`"=`""$path_text`"" `""%1`"" | Out-Null
	cmd /c ftype `"TextEditor.doc`"=`""$path_text`"" `""%1`"" | Out-Null
	cmd /c ftype `"TextEditor.rtf`"=`""$path_text`"" `""%1`"" | Out-Null
	
	WriteLog -LogString "ftype .pptx .ppt"
	cmd /c ftype `"PresentationViewer.pptx`"=`""$path_Present`"" `""%1`"" | Out-Null
	cmd /c ftype `"PresentationViewer.ppt`"=`""$path_Present`"" `""%1`"" | Out-Null
	
	WriteLog -LogString "set items_reg"
	set-items_reg -program $program
	
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
		set-assoc -program $env:ProgramFiles
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
		set-assoc -program ${env:ProgramFiles(x86)}
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



