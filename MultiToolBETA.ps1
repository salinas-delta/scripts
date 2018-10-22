###BETA for now###

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$Global:usrname = $null
$Global:enDer =  ''
$Global:dc = Get-ADDomainController -Discover | select -ExpandProperty name

#region begin GUI{ 

$Form                            = New-Object system.Windows.Forms.Form
$Form.ClientSize                 = '400,400'
$Form.text                       = "AD User Tool"
$Form.TopMost                    = $false
$Form.KeyPreview = $True
$Form.Add_KeyDown({if ($_.KeyCode -eq "Enter") {Invoke-Expression $Global:enDer}})
$Form.Add_KeyDown({if ($_.KeyCode -eq "Escape")
{$Form.Close()}})

$TextBox1                        = New-Object system.Windows.Forms.TextBox
$TextBox1.multiline              = $false
$TextBox1.width                  = 120
$TextBox1.height                 = 20
$TextBox1.location               = New-Object System.Drawing.Point(15,25)
$TextBox1.Font                   = 'Microsoft Sans Serif,10'

$Label1 = New-Object System.Windows.Forms.Label
$Label1.Text = "Type Username Below"
$Label1.AutoSize = $True
$Label1.Location = New-Object System.Drawing.Size(15,10)

$ShowDetails = New-Object System.Windows.Forms.Label
$ShowDetails.AutoSize = $True
$ShowDetails.Location = New-Object System.Drawing.Size(15,50)

$Status = New-Object System.Windows.Forms.Label
$Status.font = 'Microsoft Sans Serif,12'
$Status.AutoSize = $True
$Status.Location = New-Object System.Drawing.Size(15,360)
$Status.ForeColor = "red"

$Button1 = New-Object System.Windows.Forms.Button
$Button1.Text = "Check"
$Button1.AutoSize = $True
$Button1.Location = New-Object System.Drawing.Size(300,25)
$Button1.add_click({$global:usrname= $textbox1.text;get-userdetailz $global:usrname})

$ButtonUnlock = New-Object System.Windows.Forms.Button
#button text is generated in the userdetails function during $lckout variable creation
$ButtonUnlock.AutoSize = $True
$ButtonUnlock.Location = New-Object System.Drawing.Size(300,50)
$ButtonUnlock.BackColor = "green"
$ButtonUnlock.add_click({UnlockAccount $Global:usrname})

$ButtonLockAcc = New-Object System.Windows.Forms.Button
$ButtonLockAcc.AutoSize = $True
$ButtonLockAcc.Location = New-Object System.Drawing.Size(300,50)
$ButtonLockAcc.BackColor = "red"
$ButtonLockAcc.add_click({LockAccount $Global:usrname})

$ButtonReset = New-Object System.Windows.Forms.Button
$ButtonReset.AutoSize = $True
$ButtonReset.Location = New-Object System.Drawing.Size(300,75)
$ButtonReset.Text = "Reset"
$ButtonReset.add_click({ClearForm;MainForm})

$ButtonSetPSW = New-Object System.Windows.Forms.Button
$ButtonSetPSW.AutoSize = $True
$ButtonSetPSW.Location = New-Object System.Drawing.Size(300,100)
$ButtonSetPSW.Text = "SetPSW"
$ButtonSetPSW.add_click({SetPSW $Global:usrname})

$ButtonNUSER = New-Object System.Windows.Forms.Button
$ButtonNUSER.AutoSize = $True
$ButtonNUSER.Location = New-Object System.Drawing.Size(300,200)
$ButtonNUSER.Text = "NUSER"
$ButtonNUSER.add_click({ClearForm;MainNuserForm;$form.Controls.Remove($ButtonNUSER)})

$ButtonSetAttr = New-Object System.Windows.Forms.Button
$ButtonSetAttr.AutoSize = $True
$ButtonSetAttr.Location = New-Object System.Drawing.Size(300,125)
$ButtonSetAttr.Text = "SetAttr"
$ButtonSetAttr.add_click({SetAttributes})

$Provide1 = New-Object System.Windows.Forms.Label
$Provide1.Text = "Type Password"
$Provide1.AutoSize = $True
$Provide1.Location = New-Object System.Drawing.Size(15,10)

$Provide2 = New-Object System.Windows.Forms.Label
$Provide2.Text = "Verify Password"
$Provide2.AutoSize = $True
$Provide2.Location = New-Object System.Drawing.Size(15,60)

$Inpu1                        = New-Object System.Windows.Forms.TextBox
$Inpu1.PasswordChar = '*'
$Inpu1.multiline              = $false
$Inpu1.width                  = 120
$Inpu1.height                 = 20
$Inpu1.location               = New-Object System.Drawing.Size(15,35)
$Inpu1.Font                   = 'Microsoft Sans Serif,10'

$Inpu2                        = New-Object System.Windows.Forms.TextBox
$Inpu2.PasswordChar = '*'
$Inpu2.multiline              = $false
$Inpu2.width                  = 120
$Inpu2.height                 = 20
$Inpu2.location               = New-Object System.Drawing.Size(15,85)
$Inpu2.Font                   = 'Microsoft Sans Serif,10'

$ButtonExecSetPSW = New-Object System.Windows.Forms.Button
$ButtonExecSetPSW.AutoSize = $True
$ButtonExecSetPSW.Location = New-Object System.Drawing.Size(300,100)
$ButtonExecSetPSW.Text = "Confirm"
$ButtonExecSetPSW.add_click({InnerSetPSW})

#------------NUSER_GUI------------------
$TitleForm = New-Object System.Windows.Forms.Label
$TitleForm.Text = "NUser Form - Fill Details and Chose Options"
$TitleForm.AutoSize = $True
$TitleForm.Location = New-Object System.Drawing.Point(5,0)
$TitleForm.Font = 'Microsoft Sans Serif,13,style=Bold'

$Summary = New-Object System.Windows.Forms.Label
$Summary.Location = New-Object System.Drawing.Point(215,55)
$Summary.AutoSize = $True
$Summary.Text = ""

$LB_samname = New-Object System.Windows.Forms.Label
$LB_samname.Location = New-Object System.Drawing.Point(5,35)
$LB_samname.AutoSize = $True
$LB_samname.Text = "Account Name"
$LB_samname.Font = 'Microsoft Sans Serif,10'

$TB_samname = New-Object System.Windows.Forms.TextBox
$TB_samname.Location = New-Object System.Drawing.Point(5,55)
$TB_samname.Size = New-Object System.Drawing.Size(100,10)
$TB_samname.Multiline = $false
$TB_samname.Font = 'Microsoft Sans Serif,10'

$LB_password = New-Object System.Windows.Forms.Label
$LB_password.Location = New-Object System.Drawing.Point(110,35)
$LB_password.AutoSize = $True
$LB_password.Text = "Password"
$LB_password.Font = 'Microsoft Sans Serif,10'

$TB_password = New-Object System.Windows.Forms.TextBox
$TB_password.Location = New-Object System.Drawing.Point(110,55)
$TB_password.Size = New-Object System.Drawing.Size(100,10)
$TB_password.Multiline = $false
$TB_password.Font = 'Microsoft Sans Serif,10'

$LB_firstname = New-Object System.Windows.Forms.Label
$LB_firstname.Location = New-Object System.Drawing.Point(5,85)
$LB_firstname.AutoSize = $True
$LB_firstname.Text = "Firstname"
$LB_firstname.Font = 'Microsoft Sans Serif,10'

$TB_firstname = New-Object System.Windows.Forms.TextBox
$TB_firstname.Location = New-Object System.Drawing.Point(5,105)
$TB_firstname.Size = New-Object System.Drawing.Size(100,10)
$TB_firstname.Multiline = $false
$TB_firstname.Font = 'Microsoft Sans Serif,10'

$LB_lastname = New-Object System.Windows.Forms.Label
$LB_lastname.Location = New-Object System.Drawing.Point(110,85)
$LB_lastname.AutoSize = $True
$LB_lastname.Text = "Lastname"
$LB_lastname.Font = 'Microsoft Sans Serif,10'

$TB_lastname = New-Object System.Windows.Forms.TextBox
$TB_lastname.Location = New-Object System.Drawing.Point(110,105)
$TB_lastname.Size = New-Object System.Drawing.Size(100,10)
$TB_lastname.Multiline = $false
$TB_lastname.Font = 'Microsoft Sans Serif,10'

$LB_homedrive = New-Object System.Windows.Forms.Label
$LB_homedrive.Location = New-Object System.Drawing.Point(5,135)
$LB_homedrive.AutoSize = $True
$LB_homedrive.Text = "Home Drive"
$LB_homedrive.Font = 'Microsoft Sans Serif,10'

$TB_homedrive = New-Object System.Windows.Forms.TextBox
$TB_homedrive.Location = New-Object System.Drawing.Point(5,155)
$TB_homedrive.Size = New-Object System.Drawing.Size(100,10)
$TB_homedrive.Multiline = $false
$TB_homedrive.Font = 'Microsoft Sans Serif,10'

$LB_homedirectory = New-Object System.Windows.Forms.Label
$LB_homedirectory.Location = New-Object System.Drawing.Point(110,135)
$LB_homedirectory.AutoSize = $True
$LB_homedirectory.Text = "Home Directory"
$LB_homedirectory.Font = 'Microsoft Sans Serif,10'

$TB_homedirectory = New-Object System.Windows.Forms.TextBox
$TB_homedirectory.Location = New-Object System.Drawing.Point(110,155)
$TB_homedirectory.Size = New-Object System.Drawing.Size(100,10)
$TB_homedirectory.Multiline = $false
$TB_homedirectory.Font = 'Microsoft Sans Serif,10'

$LB_scriptpath = New-Object System.Windows.Forms.Label
$LB_scriptpath.Location = New-Object System.Drawing.Point(5,185)
$LB_scriptpath.AutoSize = $True
$LB_scriptpath.Text = "Script Name"
$LB_scriptpath.Font = 'Microsoft Sans Serif,10'

$TB_scriptpath = New-Object System.Windows.Forms.TextBox
$TB_scriptpath.Location = New-Object System.Drawing.Point(5,205)
$TB_scriptpath.Size = New-Object System.Drawing.Size(100,10)
$TB_scriptpath.Multiline = $false
$TB_scriptpath.Font = 'Microsoft Sans Serif,10'

$LB_mobilenumber = New-Object System.Windows.Forms.Label
$LB_mobilenumber.Location = New-Object System.Drawing.Point(110,185)
$LB_mobilenumber.AutoSize = $True
$LB_mobilenumber.Text = "Mobile Number"
$LB_mobilenumber.Font = 'Microsoft Sans Serif,10'

$TB_mobilenumber = New-Object System.Windows.Forms.TextBox
$TB_mobilenumber.Location = New-Object System.Drawing.Point(110,205)
$TB_mobilenumber.Size = New-Object System.Drawing.Size(100,10)
$TB_mobilenumber.Multiline = $false
$TB_mobilenumber.Font = 'Microsoft Sans Serif,10'

$CB_CannotChangePassword = New-Object system.Windows.Forms.CheckBox
$CB_CannotChangePassword.location  = New-Object System.Drawing.Point(5,258)
$CB_CannotChangePassword.text = "CannotChangePassword"
$CB_CannotChangePassword.AutoSize  = $True
$CB_CannotChangePassword.Font    = 'Microsoft Sans Serif,10'

$CB_ChangePasswordAtLogon        = New-Object system.Windows.Forms.CheckBox
$CB_ChangePasswordAtLogon.location  = New-Object System.Drawing.Point(5,285)
$CB_ChangePasswordAtLogon.text   = "ChangePasswordAtLogon"
$CB_ChangePasswordAtLogon.AutoSize  = $True
$CB_ChangePasswordAtLogon.Font   = 'Microsoft Sans Serif,10'

$CB_Enabled                      = New-Object system.Windows.Forms.CheckBox
$CB_Enabled.location             = New-Object System.Drawing.Point(5,312)
$CB_Enabled.text                 = "Enabled"
$CB_Enabled.AutoSize             = $True
$CB_Enabled.Font                 = 'Microsoft Sans Serif,10'

$CB_PasswordNeverExpires                      = New-Object system.Windows.Forms.CheckBox
$CB_PasswordNeverExpires.location             = New-Object System.Drawing.Point(5,339)
$CB_PasswordNeverExpires.text                 = "PasswordNeverExpires"
$CB_PasswordNeverExpires.AutoSize             = $True
$CB_PasswordNeverExpires.Font                 = 'Microsoft Sans Serif,10'

$BT_createuser = New-Object System.Windows.Forms.Button
$BT_createuser.Location = New-Object System.Drawing.Point(215,339)
$BT_createuser.Text = "Create"
$BT_createuser.add_click({CreateNuser})

$BT_reset_nuserform = New-Object System.Windows.Forms.Button
$BT_reset_nuserform.Location = New-Object System.Drawing.Point(290,339)
$BT_reset_nuserform.Text = "Reset Form"
$BT_reset_nuserform.add_click({ClearNuserForm;ClearNuserTextBoxes;ClearCheckBoxes;MainForm})




#-----Functions------
function CheckAttributes {
ClearCheckBoxes
$UserAttribs = Get-ADUser -filter "samaccountname -eq '$Global:usrname'" –Properties  "CannotChangePassword","Enabled","PasswordNeverExpires" | select –Property  "CannotChangePassword","Enabled","PasswordNeverExpires"
$CB_CannotChangePassword.Checked = [bool]$UserAttribs.CannotChangePassword
$CB_PasswordNeverExpires.Checked = [bool]$UserAttribs.PasswordNeverExpires
$CB_Enabled.Checked = [bool]$UserAttribs.Enabled
$Form.Controls.AddRange(@($CB_CannotChangePassword,$CB_PasswordNeverExpires,$CB_Enabled,$CB_ChangePasswordAtLogon))
}

function SetAttributes {
$Command = $null
$Command = "Set-ADUser "+$usrname+" -CannotChangePassword "+"$"+[bool]$CB_CannotChangePassword.CheckState+" -ChangePasswordAtLogon "+"$"+[bool]$CB_ChangePasswordAtLogon.CheckState+" -Enabled "+"$"+[bool]$CB_Enabled.CheckState+" -PasswordNeverExpires "+"$"+[bool]$CB_PasswordNeverExpires.CheckState
try {
Write-Host $Command
Invoke-Expression $Command -ErrorAction Stop 
Write-Host "Command seems to be executed"
$Status.Text = "Attributes set"
}
catch {
Write-Host "In catch of set attributes"
$Status.Text = $_.exception.message
}
$form.Controls.Add($Status)
}


function SetPSW ($usrname){
ClearForm
$Global:enDer =  'innersetpsw'
$form.Controls.Addrange(@($Provide1,$Provide2,$Inpu1,$Inpu2,$ButtonExecSetPSW))
$ERR = $false
}

Function InnerSetPSW {
if (![string]::IsNullOrWhiteSpace($Inpu1.Text)) {
Write-Host "NOT NULL"

if ($Inpu1.Text -eq $Inpu2.Text)  {
Write-Host "A match!"
$PSW = $Inpu1.Text | ConvertTo-SecureString -AsPlainText -Force
try {
Set-ADAccountPassword -Identity $usrname -NewPassword $PSW -Reset
}
catch  {
$Status.Text = $_.exception.message
$ERR = $true
}
if (!$ERR) {
ClearForm
$Inpu1.Text,$Inpu2.Text = $null
$Status.ForeColor= "green"
$Status.Text = "$usrname Password reset successfull"
$Global:enDer =  'clearform;mainform'
$form.Controls.Add($ButtonReset)
}


}

else {
$Status.ForeColor= "red"
$Status.Text="No mach! Try again"
}
$form.Controls.Add($Status)
}
else {Write-Host "NULL";$status.text="NULL is not COOL";$Status.ForeColor="red";$form.controls.add($status)}
}

function ClearForm {
$form.Controls.Remove($TextBox1)
$form.Controls.Remove($Button1)
$form.Controls.Remove($Status)
$form.Controls.Remove($ShowDetails)
$form.Controls.Remove($Label1)
$form.Controls.Remove($ButtonReset)
$form.Controls.Remove($buttonSetPSW)
$form.Controls.Remove($ButtonLockAcc)
$form.Controls.Remove($ButtonUnlock)
$form.Controls.Remove($ButtonExecSetPSW)
$form.Controls.Remove($Provide1)
$form.Controls.Remove($Provide2)
$form.Controls.Remove($Inpu1)
$form.Controls.Remove($Inpu2)
$form.Controls.Remove($ButtonNUSER)
$form.Controls.Remove($CB_CannotChangePassword)
$form.Controls.Remove($CB_ChangePasswordAtLogon)
$form.Controls.Remove($CB_Enabled)
$form.Controls.Remove($CB_PasswordNeverExpires)
$form.Controls.Remove($ButtonSetAttr)
$Status.Text=$null
$textbox1.text=$null
$ShowDetails.text=$null
}
#++++++++++++++++++++++++++Below NOT USED+++++++++++++++++++
function up-status ($meggase) {
$form.Controls.Remove($Status)
$Status.Text = $meggase
$form.Controls.Add($Status)
}
#+++++++++++++++++++++++Above NOT USED++++++++++++++++++++++

# get user information #
function get-userdetailz ($usrname){
$Status.Text=$null
$ShowDetails.text=$null
$form.Controls.Remove($ButtonUnlock)
$form.Controls.Remove($ButtonLockAcc)
$usrexist = Get-ADUser -Filter {samaccountname -eq $usrname}
if ($usrexist -eq $null) {$Status.ForeColor= "red" ; $Status.Text="User "+$Global:usrname+" not found"} else {
$UserDetails = Get-ADUser -filter "samaccountname -eq '$Global:usrname'" –Properties “DisplayName”,"enabled","PasswordNeverExpires", “msDS-UserPasswordExpiryTimeComputed”,"emailaddress","lockedout", "PasswordExpired", `
"LastBadPasswordAttempt", "LastLogonDate" | Select-Object -Property “Displayname”,"enabled","PasswordNeverExpires","PasswordExpired", "LastBadPasswordAttempt","emailaddress", "LastLogonDate", "lockedout",@{Name=“ExpiryDate”;Expression={[datetime]::FromFileTime($_.“msDS-UserPasswordExpiryTimeComputed”)}}
$dspln = $UserDetails.Displayname
$enbld = if ($UserDetails.enabled -eq $true) {"Yes"} else {"No"}
$pswne = if ($UserDetails.PasswordNeverExpires -eq $true) {"Never"} else {"Yes"}
$lbpa = $UserDetails.LastBadPasswordAttempt
$lld = $UserDetails.LastLogonDate
$emailadd = $UserDetails.emailaddress
$lckdout = if ($UserDetails.lockedout -eq $true) {"Yes";$ButtonUnlock.text = ("Unlock "+$Global:usrname);$Form.Controls.Add($ButtonUnlock)} else {"No"; $ButtonLockAcc.text = ("Lock "+$Global:usrname);$form.Controls.Add($ButtonLockAcc)}
$pswexp = $UserDetails.ExpiryDate
$ShowDetails.Text="Displayname: "+$dspln+"`n"+"Enabled: "+$enbld+"`n"+"Account Locked: "+$lckdout+"`n"+"PSW Expires:"+$pswne+"`n"+"PSW Expiration date: "+$pswexp+"`n"+ `
"Last Login On: "+$lld+"`n"+"Last Bad Attempt: "+$lbpa+"`n"+"Email Address: "+$emailadd
$form.Controls.Add($ButtonSetPSW)
$form.Controls.Add($ButtonSetAttr)
CheckAttributes
}}

function UnlockAccount ($usrname){
Unlock-ADAccount -Identity $usrname
$form.Controls.Remove($ButtonUnlock)
get-userdetailz $usrname
$Status.ForeColor= "green"
$Status.Text = "Unlocked "+$usrname

}

function LockAccount ($usrname) {
$LockAttempts = 10
$LockCount =0
$Password = ConvertTo-SecureString 'NotMyPassword' -AsPlainText -Force
Do {
Write-Host $LockCount
Invoke-Command -ComputerName $dc {Get-Process} -Credential (New-Object System.Management.Automation.PSCredential ($Global:usrname, $Password)) -ErrorAction SilentlyContinue
$LockCount++
}
Until (($LockCount -ge $LockAttempts) -or ((Get-ADUser -Identity $Global:usrname -Properties LockedOut).LockedOut))

if ((Get-ADUser -Identity $Global:usrname -Properties LockedOut).LockedOut) {
$form.Controls.Remove($ButtonLockAcc)
get-userdetailz $usrname
$Status.ForeColor= "red"
$Status.Text = "Locked "+$usrname
}

else {
$form.Controls.Remove($ButtonLockAcc)
get-userdetailz $usrname
$Status.ForeColor= "Black"
$Status.Text = "Couldn't Lock "+$usrname
}
}

function MainForm (){
$Global:enDer =  '$global:usrname= $textbox1.text;get-userdetailz $global:usrname'
$form.Controls.Addrange(@($TextBox1,$Label1,$Button1,$Status,$ShowDetails,$ButtonReset,$ButtonNUSER))

}

# NUSER_Functions #


function CreateNuser {
Write-Host "entered Createnuser"
$NL = "`n"
$ERR = $false
$samname = $TB_samname.Text
$password = $TB_password.Text

if ([string]::IsNullOrWhiteSpace($samname)) {
Write-Host "SAMName is empty"
$ERR = $True
$Status.Text = "Enter Username"
$form.Controls.Add($Status)
}

elseif  ([bool] (Get-ADUser -Filter {samaccountname -eq $samname} ) -eq $True) {

Write-Host "User already exists!"
$ERR = $True
$Status.Text = "User already exists!"
$form.Controls.Add($Status)
}

elseif ([string]::IsNullOrWhiteSpace($password)) {
Write-Host "Enter Password"
$ERR = $True
$Status.Text = "Password is Empty"
$form.Controls.Add($Status)

}

else {
$displayname = $TB_firstname.Text,$TB_lastname.Text
$homedrive = $TB_homedrive.Text
$homefolder = $TB_homedirectory.Text
$scriptpath = $TB_scriptpath.Text
$mobilenumber = $TB_mobilenumber.Text
$CannotChangePassword = $CB_CannotChangePassword.CheckState
$ChangePasswordAtLogon = $CB_ChangePasswordAtLogon.CheckState
$Enabled = $CB_Enabled.CheckState
$PasswordNeverExpires = $CB_PasswordNeverExpires.CheckState
}


 if (!$ERR) {



 $UserPrincipalName = $samname+'@'+(Get-ADDomain | select -ExpandProperty forest)
 $Command = "New-ADUser "+$samname+" -Accountpassword "+ "(ConvertTo-SecureString -AsPlainText -Force '$password')"  +" -UserPrincipalName "+$UserPrincipalName+" -CannotChangePassword "+"$"+[bool]$CannotChangePassword+" -ChangePasswordAtLogon "+"$"+[bool]$ChangePasswordAtLogon+" -Enabled "+"$"+[bool]$Enabled+" -PasswordNeverExpires "+"$"+[bool]$PasswordNeverExpires
 Write-Host $ERR
 if (![string]::IsNullOrWhiteSpace($TB_firstname.Text)) {
 $Command += " -Givenname "+$TB_firstname.Text
 }

  if (![string]::IsNullOrWhiteSpace($TB_lastname.Text)) {
 $Command += " -Surname "+$TB_lastname.Text
 }

   if (![string]::IsNullOrWhiteSpace($displayname)) {
 $Command += " -DisplayName "+"'$displayname'"
 }

    if (![string]::IsNullOrWhiteSpace($homedrive)) {
 $Command += " -HomeDrive "+"'$homedrive'"
 }

    if (![string]::IsNullOrWhiteSpace($homefolder)) {
 $Command += " -HomeDirectory "+$homefolder+$samname
 }

    if (![string]::IsNullOrWhiteSpace($scriptpath)) {
 $Command += " -ScriptPath "+$scriptpath
 }

    if (![string]::IsNullOrWhiteSpace($mobilenumber)) {
 $Command += " -OfficePhone "+$mobilenumber
 }

 try {
 Write-Host $Command
 Invoke-Expression $Command -ErrorAction "Stop"
 if (![String]::IsNullOrWhiteSpace($TB_homedirectory)) { 

$FullHomeDir = $TB_homedirectory.Text+$samname
$Domain = Get-ADDomain | select -ExpandProperty netbiosname
$IdentityReference=$Domain+’\’+$samname
# Create user folder on the share drive
New-Item -Path $FullHomeDir -type Directory -Force -ErrorAction Stop
# Set parameters for Access rule
$HomeFolderACL = Get-Acl $FullHomeDir
$FileSystemAccessRights=[System.Security.AccessControl.FileSystemRights]”FullControl”
$InheritanceFlags=[System.Security.AccessControl.InheritanceFlags]”ContainerInherit, ObjectInherit”
$PropagationFlags=[System.Security.AccessControl.PropagationFlags]”None”
$AccessControl=[System.Security.AccessControl.AccessControlType]”Allow”
# Build Access Rule from parameters
$AccessRule=NEW-OBJECT System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($IdentityReference,$FileSystemAccessRights,$InheritanceFlags,$PropagationFlags,$AccessControl)
$HomeFolderACL.AddAccessRule($AccessRule)
# Remove inheritance from home foler
$HomeFolderACL.SetAccessRuleProtection($true,$true)
Set-Acl -Path $FullHomeDir -AclObject $HomeFolderACL
$HomeFolderACL = Get-Acl $FullHomeDir
# Remove DOMAIN USERS from User Homefolder ACL
$HomeFolderACL | select -ExpandProperty access | where { $_.identityreference -like "*Domain Users"} | foreach {$HomeFolderACL.RemoveAccessRule($_)} 
Set-Acl -Path $FullHomeDir -AclObject $HomeFolderACL
Write-Host "done"

 } 
 $Status.Text = "User Created Successfully"+"`n"+"Home Folder Created Successfully"
 $form.controls.remove($BT_createuser)
 }

 catch [Microsoft.ActiveDirectory.Management.ADPasswordComplexityException] {
 write-Host "in catch of password complexity"
 $Status.Text = "User Created but the password is BAD, reset password"
 $form.controls.remove($BT_createuser)
 }

catch [System.IO.IOException] {
write-host "Homefolder path does not exists"
$Status.Text = "User Created Successfully"+"`n"+"Home Folder path was not found"

}
 catch {
Write-Host "in catch of invoke"
$Status.Text = $_.exception.message
$ERR = $True
Write-Host "catch section"+$Status.Text

 }


$Summary.Text = "SamName: "+$samname+$NL+"Display Name: "+$displayname+$NL+"Home Folder: "+$FullHomeDir+$NL+"Logon Script: "+$scriptpath+$NL+"CantChangePass: "+$CannotChangePassword+$NL+"ChangePass@Logon: "+$ChangePasswordAtLogon+$NL+"Account Enabled: "+$Enabled+$NL+"PassNeverExp: "+$PasswordNeverExpires+$NL+"Mobile: "+$mobilenumber
$form.Controls.Add($Status)
$form.Controls.Add($Summary)
}


}

function ClearNuserTextBoxes {
Get-Variable TB_* |  ForEach-Object { $_.value.text = $null}
}

function ClearCheckBoxes {
Get-Variable cb* | ForEach-Object {$_.value.checked = $false}
}

function ClearNuserForm {
$form.Controls.Remove($TitleForm)
$form.Controls.Remove($Status)
$form.Controls.Remove($Summary)
$form.Controls.Remove($TB_samname)
$form.Controls.Remove($LB_samname)
$form.Controls.Remove($TB_firstname)
$form.Controls.Remove($LB_firstname)
$form.Controls.Remove($TB_lastname)
$form.Controls.Remove($LB_lastname)
$form.Controls.Remove($TB_password)
$form.Controls.Remove($LB_password)
$form.Controls.Remove($TB_homedrive)
$form.Controls.Remove($LB_homedrive)
$form.Controls.Remove($TB_homedirectory)
$form.Controls.Remove($LB_homedirectory)
$form.Controls.Remove($TB_scriptpath)
$form.Controls.Remove($LB_scriptpath)
$form.Controls.Remove($TB_mobilenumber)
$form.Controls.Remove($LB_mobilenumber)
$form.Controls.Remove($CB_CannotChangePassword)
$form.Controls.Remove($CB_ChangePasswordAtLogon)
$form.Controls.Remove($CB_Enabled)
$form.Controls.Remove($CB_PasswordNeverExpires)
$form.Controls.Remove($BT_createuser)
$form.Controls.Remove($BT_reset_nuserform)

$Summary.Text = $null
$Status.Text=$null
#$textbox1.text=$null
#$ShowDetails.text=$null
}


function MainNuserForm (){
$Global:enDer =  ''
$TB_homedrive.Text = "Edit_script_2_AutoFill"
$TB_homedirectory.Text = "Edit_script_2_AutoFill"
$TB_scriptpath.Text = "Edit_script_2_AutoFill"

$form.Controls.Addrange(@(
$TitleForm,$Status,$Summary,
$TB_samname,$LB_samname,
$TB_firstname,$LB_firstname,
$TB_lastname,$LB_lastname,
$TB_password,$LB_password,
$TB_homedrive,$LB_homedrive,
$TB_homedirectory,$LB_homedirectory,
$TB_scriptpath,$LB_scriptpath,
$TB_mobilenumber,$LB_mobilenumber,
$CB_CannotChangePassword,$CB_ChangePasswordAtLogon,$CB_Enabled,$CB_PasswordNeverExpires,
$BT_createuser,$BT_reset_nuserform
))
}


MainForm

[void]$Form.ShowDialog()