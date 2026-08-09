Set WshShell = CreateObject("WScript.Shell")
Set FileSystem = CreateObject("Scripting.FileSystemObject")
WshShell.CurrentDirectory = FileSystem.GetParentFolderName(WScript.ScriptFullName)
WshShell.Run "cmd /k python app.py", 1, False
