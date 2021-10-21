#

setenv SSH_AUTH_SOCK_METHOD1 `/bin/launchctl getenv SSH_AUTH_SOCK_METHOD1`
setenv SSH_AUTH_SOCK $SSH_AUTH_SOCK_METHOD1
foreach c (scp sftp slogin ssh ssh-add ssh-agent ssh-keygen ssh-keyscan)
  alias $c "/usr/local/bin/$c"
end

# end of file
