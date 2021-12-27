[System.Text.Encoding]::GetEncoding("cp866") | Out-Null

$HKCRTextX = "HKCR:\TextEditor.docx"
$HKCRTextrtf = "HKCR:\TextEditor.rtf"
$HKCRText = "HKCR:\TextEditor.doc"

$HKCRSpreadX = "HKCR:\SpreadsheetEditor.xlsx"
$HKCRSpread = "HKCR:\SpreadsheetEditor.xls"
$HKCRSpreadcsv = "HKCR:\SpreadsheetEditor.csv"
$HKCRpptx = "HKCR:\PresentationViewer.pptx"
$HKCRppt = "HKCR:\PresentationViewer.ppt"

$HKUpath="Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"


$Logfile = "$env:TEMP\assocscript_$env:computername.log"
function WriteLog
{
	Param ([string]$LogString)
	$Stamp = (Get-Date).toString("dd.MM.yyyy HH:mm:ss")
	$LogMessage = "{0}: {1}" -f $Stamp, $LogString
	Add-content $LogFile -value $LogMessage
}

function set-userchoice {
    $type_list=("SpreadsheetEditor.xls",
    "SpreadsheetEditor.xlsx",
    "SpreadsheetEditor.csv",
    "TextEditor.docx",
    "TextEditor.doc",
    "TextEditor.rtf",
    "PresentationViewer.pptx",
    "PresentationViewer.ppt")

    foreach ($name in $type_list)
    {
    $Ext=$name.Split(".")[1]
    $parent = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("$HKUpath\.$Ext", $true)
    $RegistryValueKind = [Microsoft.Win32.RegistryValueKind]::String
        foreach ($SubKey in $parent.GetSubKeyNames()){
            if ($SubKey -eq 'UserChoice'){
                $parent.DeleteSubKey('UserChoice', $true)
                $parent.CreateSubKey("UserChoice")
                $parent_user=$parent.OpenSubKey('UserChoice', $true)
                $parent_user.SetValue("Progid", $name, $RegistryValueKind)
                $parent_user.Close()
            }
        }
    }
}

function set-items
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
			throw ("Не существует пути: {0}" -f $i)
		}
	}
	
	WriteLog -LogString "Start assoc"
	cmd /c assoc .xls=SpreadsheetEditor.xls | Out-Null
	cmd /c assoc .xlsx=SpreadsheetEditor.xlsx | Out-Null
	cmd /c assoc  .xlsm=SpreadsheetEditor.xlsx | Out-Null
	cmd /c assoc  .csv=SpreadsheetEditor.csv | Out-Null
	cmd /c assoc  .docx=TextEditor.docx | Out-Null
	cmd /c assoc  .doc=TextEditor.doc | Out-Null
	cmd /c assoc  .rtf=TextEditor.rtf | Out-Null
	cmd /c assoc  .pptx=PresentationViewer.pptx | Out-Null
	cmd /c assoc  .ppt=PresentationViewer.ppt | Out-Null
	
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
	
	WriteLog -LogString "New-Item DOCX.ico"
	New-Item -Path $HKCRTextX\DefaultIcon -Value `""$program\MyOffice\DOCX.ico`"" -Force -ErrorAction Stop | Out-Null
	New-Item -Path $HKCRTextX\Application -Force -ErrorAction Stop | Out-Null
	New-ItemProperty -Path $HKCRTextX\Application -Name ApplicationName -Value "МойОфис Текст" -Force -ErrorAction Stop | Out-Null
	
	WriteLog -LogString "New-Item DOC.ico"
	New-Item -Path $HKCRText\DefaultIcon -Value `""$program\MyOffice\DOC.ico`"" -Force -ErrorAction Stop | Out-Null
	New-Item -Path $HKCRText\Application -Force -ErrorAction Stop | Out-Null
	New-ItemProperty -Path $HKCRText\Application -Name ApplicationName -Value "МойОфис Текст" -Force -ErrorAction Stop | Out-Null
	
	WriteLog -LogString "New-Item RTF.ico"
	New-Item -Path $HKCRTextrtf\DefaultIcon -Value `""$program\MyOffice\RTF.ico`"" -Force -ErrorAction Stop | Out-Null
	New-Item -Path $HKCRTextrtf\Application -Force -ErrorAction Stop | Out-Null
	New-ItemProperty -Path $HKCRTextrtf\Application -Name ApplicationName -Value "МойОфис Текст" -Force -ErrorAction Stop | Out-Null
	
	WriteLog -LogString "New-Item XLSX.ico"
	New-Item -Path $HKCRSpreadX\Application -Force -ErrorAction Stop | Out-Null
	New-ItemProperty -Path $HKCRSpreadX\Application -Name ApplicationName -Value "МойОфис Таблица" -Force -ErrorAction Stop | Out-Null
	New-Item -Path $HKCRSpreadX\DefaultIcon -Value `""$program\MyOffice\XLSX.ico`"" -Force -ErrorAction Stop | Out-Null
	
	WriteLog -LogString "New-Item XLS.ico"
	New-Item -Path $HKCRSpread\Application -Force -ErrorAction Stop | Out-Null
	New-ItemProperty -Path $HKCRSpread\Application -Name ApplicationName -Value "МойОфис Таблица" -Force -ErrorAction Stop | Out-Null
	New-Item -Path $HKCRSpread\DefaultIcon -Value `""$program\MyOffice\XLS.ico`"" -Force -ErrorAction Stop | Out-Null
	
	WriteLog -LogString "New-Item CSV.ico"
	New-Item -Path $HKCRSpreadcsv\Application -Force -ErrorAction Stop | Out-Null
	New-ItemProperty -Path $HKCRSpreadcsv\Application -Name ApplicationName -Value "МойОфис Таблица" -Force -ErrorAction Stop | Out-Null
	New-Item -Path $HKCRSpreadcsv\DefaultIcon -Value `""$program\MyOffice\CSV.ico`"" -Force -ErrorAction Stop | Out-Null
	
	WriteLog -LogString "New-Item PPTX.ico"
	New-Item -Path $HKCRpptx\Application -Force -ErrorAction Stop | Out-Null
	New-ItemProperty -Path $HKCRpptx\Application -Name ApplicationName -Value "МойОфис Презентация" -Force -ErrorAction Stop | Out-Null
	New-Item -Path $HKCRpptx\DefaultIcon -Value `""$program\MyOffice\PPTX.ico`"" -Force -ErrorAction Stop | Out-Null
	
	WriteLog -LogString "New-Item PPT.ico"
	New-Item -Path $HKCRppt\Application -Force -ErrorAction Stop | Out-Null
	New-ItemProperty -Path $HKCRpptx\Application -Name ApplicationName -Value "МойОфис Презентация" -Force -ErrorAction Stop | Out-Null
	New-Item -Path $HKCRppt\DefaultIcon -Value `""$program\MyOffice\PPT.ico`"" -Force -ErrorAction Stop | Out-Null
    
    WriteLog -LogString "set userchoice"
    set-userchoice
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
		set-items -program $env:ProgramFiles
	}
	catch
	{
		$ErrorMessage = $_.Exception.Message
		$FailedItem = $_.Exception.ItemName
		Write-warning ("Ошибка {0} - {1}" -f $ErrorMessage, $FailedItem)
		WriteLog -LogString $ErrorMessage
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
		set-items -program ${env:ProgramFiles(x86)}
	}
	catch
	{
		$ErrorMessage = $_.Exception.Message
		$FailedItem = $_.Exception.ItemName
		Write-warning ("Ошибка {0} - {1}" -f $ErrorMessage, $FailedItem)
		WriteLog -LogString $ErrorMessage
	}
	finally
	{
		WriteLog -LogString "Finish work!"
	}
}



