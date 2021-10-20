# launchd-sock-proxy(lsp)

The proxy between launchd sockets, and genuine, non-Apple'ified
ssh-agent.

Since ssh-agent comes with macOS is old, customized by
Apple[^apple-ssh-agent] and protected by SIP, using ed25519-sk (or
ecdsa-sk) is a little annoying. I tried two methods and
succeeded. This is the first method. That is, I have made a proxy.

## outline

After setup, launchd invokes this proxy(lsp) when data arrives via
unix domain socket. lsp invokes ssh-agent and get the information of a
socket created by ssh-agent. lsp does not designate the socket for
ssh-agent by -a option, so the place of the socket is hidden from ps
-ell. You can kill ssh-agent if you wish, such as by killall
ssh-agent. lsp invokes new ssh-agent automatically, and you do not
need to reset SSH_AUTH_SOCK environmental variable, since the socket
created by launchd is stable.

## setup

1. Install a C++ compiler with c++20 functionality, and compile lsp.

```
brew install gcc@11
g++ -std=c++20 -o launchd-sock-proxy launchd-sock-proxy.c++
```

2. Put files. These are configurable.

```
mkdir -p ~/bin ~/tmp ~/Library/LaunchAgent
cp -p launchd-sock-proxy ~/bin/
cp -p local.method1.plist ~/Library/LaunchAgent
```

3. Edit ~/Library/LaunchAgent/local.method1.plist as suitable to
you. Especially change '/Users/est/' to your user name, and enable it.

```
plutil ~/Library/LaunchAgent/local.method1.plist
launchctl unload -w ~/Library/LaunchAgent/local.method1.plist
launchctl   load -w ~/Library/LaunchAgent/local.method1.plist
```

4. Refer to .*x*shrc files to put initialization of environmental
variables. Re-login or `source` the script to apply them.

``` e.g.
echo $SSH_AUTH_SOCK
source ~/.zshrc
echo $SSH_AUTH_SOCK
alias
```

5. (optional) Confirm that ssh-agent is not running.

```
ps -ell | fgrep ssh-
killall ssh-agent
```

6. That's it. Confirm that genuine /usr/local/bin/ssh-agent is
running, after executing ssh-add.

```
ssh-add -L
ps -ell | fgrep ssh-
```

## diagnostic

launchd: /var/log/system.log

lsp: Set key and value of *StandardErrorPath* in .plist, and reload it.

```
plutil ~/Library/LaunchAgent/local.method1.plist
launchctl unload -w ~/Library/LaunchAgent/local.method1.plist
launchctl   load -w ~/Library/LaunchAgent/local.method1.plist
```

Do not forget to disable and remove it when you are done.

[^apple-ssh-agent]: for example: [ssh-agent](https://opensource.apple.com/source/OpenSSH/OpenSSH-240.40.1/openssh/ssh-agent.c.auto.html)
