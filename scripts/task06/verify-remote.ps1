param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('vpn-ru', 'vpn-fr')]
    [string]$Server
)

# Pass fixed commands directly to SSH. PowerShell here-strings piped to
# `bash -s` can add CR to numeric shell arguments (for example `400\r`).
$ssh = 'C:\Windows\System32\OpenSSH\ssh.exe'
$options = @('-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
             '-o', 'UpdateHostKeys=no', '-o', 'ConnectTimeout=10',
             '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes')
& $ssh @options $Server 'sudo -n /usr/local/sbin/vpn-task06 wait-ready'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $ssh @options $Server 'sudo -n /usr/local/sbin/vpn-task06 status'
exit $LASTEXITCODE
