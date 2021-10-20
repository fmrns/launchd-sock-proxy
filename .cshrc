#

setenv SSH_AUTH_SOCK `launchctl getenv SSH_AUTH_SOCK_METHOD1`
setenv SSH_AGENT_PID `launchctl getenv SSH_AGENT_PID_METHOD1`
foreach c (scp sftp slogin ssh ssh-add ssh-agent ssh-keygen ssh-keyscan)
  alias $c "/usr/local/bin/$c"
end

# end of file
