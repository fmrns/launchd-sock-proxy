/**
 * -*- coding: utf-8 -*-
 *
 * Copyright (c) 2021 Fumiyuki Shimizu
 * Copyright (c) 2021 Abacus Technologies, Inc.
 *
 * The MIT License: https://opensource.org/licenses/MIT
 */

#include <array>
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

#include <cerrno>
#include <climits>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <launch.h>

namespace {

// XXX cerr -> syslog

static inline std::string rtrim(const std::string &s) {
  return std::string(s.begin(), std::find_if(s.rbegin(), s.rend(), [](char c) {
                                  return !std::isspace(c);
                                }).base());
}

class SecurityException : public std::runtime_error {
public:
  SecurityException(const std::string &message) : std::runtime_error(message){};
};

class FD {
private:
  int fd_;

public:
  FD(int fd) : fd_(fd) {
    if (fd_ == -1) {
      std::cerr << "fd: " << std::strerror(errno) << std::endl;
    } else {
      std::cerr << "new fd: " << fd_ << std::endl;
    }
  }
  FD(const FD &) = delete;
  ~FD() {
    if (fd_ != -1) {
      std::cerr << "closing fd: " + std::to_string(fd_) + '\n' << std::flush;
      ::close(fd_);
    }
  }
  int fd() { return fd_; }
};

class Proxy {
private:
  std::atomic_bool done1_2_ = false;
  std::atomic_bool done2_1_ = false;
  std::unique_ptr<FD> fd1_;
  std::unique_ptr<FD> fd2_;
  std::unique_ptr<std::jthread> proxy1_2_;
  std::unique_ptr<std::jthread> proxy2_1_;

  static void proxy(std::stop_token stop, std::unique_ptr<FD> &fd_org,
                    std::unique_ptr<FD> &fd_dst, std::atomic_bool &done,
                    std::atomic_bool const &done_other) {
    using namespace std::literals::chrono_literals;
    std::array<std::byte, 8096> buffer;
    std::array<struct ::pollfd, 2> poll_fd;

    std::string prefix{std::to_string(fd_org->fd()) + "->" +
                       std::to_string(fd_dst->fd())};

    while (!stop.stop_requested()) {
      poll_fd[0].fd = fd_org->fd();
      poll_fd[0].events = POLLIN;
      poll_fd[0].revents = 0;
      poll_fd[1].fd = fd_dst->fd();
      poll_fd[1].events = 0;
      poll_fd[1].revents = 0;

      std::cerr << prefix + ": poll()\n" << std::flush;
      auto status = poll(poll_fd.begin(), poll_fd.size(),
                         std::chrono::milliseconds(5s).count());
      if (status == -1 || status == 0) {
        if (done_other) {
          break;
        }
        if (status == 0) {
          continue;
        }

        std::cerr << prefix + ": poll(): " + std::strerror(errno) + '\n'
                  << std::flush;
        if ((status & (EAGAIN | EWOULDBLOCK)) != 0) {
          continue;
        }
        // try recv() anywway
      } else if ((poll_fd[0].revents & (POLLERR | POLLNVAL)) != 0) {
        std::cerr << prefix + ": poll(): " + std::to_string(poll_fd[0].fd) +
                         ": POLLERR: " + std::to_string(poll_fd[0].revents) +
                         '\n'
                  << std::flush;
        break;
      } else if ((poll_fd[1].revents & (POLLERR | POLLNVAL)) != 0) {
        std::cerr << prefix + ": poll(): " + std::to_string(poll_fd[1].fd) +
                         ": POLLERR: " + std::to_string(poll_fd[1].revents) +
                         '\n'
                  << std::flush;
        break;
      } else if ((poll_fd[0].revents & POLLIN) == 0) {
        if (done_other) {
          break;
        }
        continue;
      }

      std::cerr << prefix + "recv(): " + std::to_string(fd_org->fd()) + '\n'
                << std::flush;
      auto received_size =
          recv(fd_org->fd(), buffer.begin(), buffer.size(), MSG_NOSIGNAL);
      if (received_size == 0) {
        std::cerr << prefix + ": " + std::to_string(fd_org->fd()) +
                         " is closed\n"
                  << std::flush;
        break;
      } else if (received_size == -1) {
        done = true;
        throw std::runtime_error(std::string("recv(): ") +
                                 std::strerror(errno));
      }
      std::cerr << prefix + "send(): " + std::to_string(fd_dst->fd()) + '\n'
                << std::flush;
      auto sent_size =
          send(fd_dst->fd(), buffer.begin(), received_size, MSG_NOSIGNAL);
      if (sent_size == -1) {
        done = true;
        throw std::runtime_error(prefix + "send(): " + std::strerror(errno));
      } else if (received_size != sent_size) {
        std::cerr << prefix +
                         "received_size: " + std::to_string(received_size) +
                         " != sent_size: " + std::to_string(sent_size) + '\n'
                  << std::flush;
        break;
      }
    }
    done = true;
    fd_org.reset(nullptr);
    fd_dst.reset(nullptr);
  }

public:
  Proxy(std::unique_ptr<FD> &fd1, std::unique_ptr<FD> &fd2)
      : fd1_(std::move(fd1)), fd2_(std::move(fd2)),
        proxy1_2_(std::make_unique<std::jthread>(
            proxy, std::ref(fd1_), std::ref(fd2_), std::ref(done1_2_),
            std::ref(done2_1_))),
        proxy2_1_(std::make_unique<std::jthread>(
            proxy, std::ref(fd2_), std::ref(fd1_), std::ref(done2_1_),
            std::ref(done1_2_))) {}
  Proxy(Proxy const &) = delete;
  ~Proxy() {
    proxy1_2_.reset(nullptr);
    proxy2_1_.reset(nullptr);
    fd1_.reset(nullptr);
    fd2_.reset(nullptr);
  }

  std::atomic_bool done() { return done1_2_ && done2_1_; }

  void join() {
    proxy1_2_->join();
    proxy2_1_->join();
  }
};

class SSHAgent {
private:
  std::mutex agent_mutex;
  volatile ::pid_t pid_ = -1;
  std::string sock_name_;

  void kill() {
    std::lock_guard<std::mutex> lock(agent_mutex);
    if (pid_ == -1) {
      return;
    }
    std::cerr << "killing ssh-agent[" + std::to_string(pid_) + "]\n"
              << std::flush;
    try {
      ::kill(pid_, SIGTERM);
    } catch (...) {
    }
    std::cerr << "killed ssh-agent[" + std::to_string(pid_) + "]\n"
              << std::flush;
    pid_ = -1;
  }

  void spawn_SSHAgent(std::string const& ssh_agent_cmd_) {
    std::lock_guard<std::mutex> lock(agent_mutex);
    if (pid_ != -1) {
      if (::kill(pid_, 0) == 0) {
        return;
      }
      std::cerr << "ssh-agent[" + std::to_string(pid_) +
                       "]: " + std::strerror(errno) + '\n'
                << std::flush;
    }

    std::cerr << "start ssh-agent..." << std::endl;
    std::string cmd = "eval $(" + ssh_agent_cmd_ +
                      ") >/dev/null 2>&1;"
                      "echo \"$SSH_AUTH_SOCK\";echo \"$SSH_AGENT_PID\";";
    std::unique_ptr<FILE, decltype(&::pclose)> pipe(::popen(cmd.c_str(), "r"),
                                                    ::pclose);
    if (pipe == nullptr) {
      throw std::runtime_error(std::string("invoking ssh-agent failed: ") +
                               std::strerror(errno));
    }

    std::array<char, PATH_MAX> buffer;
    if (std::fgets(buffer.begin(), buffer.size(), pipe.get()) != nullptr) {
      sock_name_ = rtrim(std::string{buffer.data()});
      if (std::fgets(buffer.begin(), buffer.size(), pipe.get()) != nullptr) {
        pid_ = std::atoi(buffer.data());
      }
    }
    std::cerr << "sock name: [" << sock_name_ << "]" << std::endl;
    std::cerr << "pid: " << pid_ << std::endl;
    if (1 > sock_name_.length()) {
      throw std::runtime_error("empty socket name.");
    }
    if (0 >= pid_) {
      throw std::runtime_error("cannot get pid of ssh-agent.");
    }
  }

public:
  ~SSHAgent() { kill(); }

  std::unique_ptr<FD> connect(std::string const& ssh_agent_cmd) {
    spawn_SSHAgent(ssh_agent_cmd);

    struct ::sockaddr_un addr_unixsock;
    if (sizeof(addr_unixsock.sun_path) < sock_name_.length() + 1) {
      throw std::runtime_error(std::string("socket name too long: [") +
                               sock_name_ + "]");
    }
    std::memset(&addr_unixsock, 0, sizeof(addr_unixsock));
    addr_unixsock.sun_family = AF_UNIX;
    ::strlcpy(addr_unixsock.sun_path, sock_name_.c_str(),
              sizeof(addr_unixsock.sun_path));

    auto rc = std::make_unique<FD>(::socket(AF_LOCAL, SOCK_STREAM, 0));
    if (rc.get()->fd() == -1) {
      throw std::runtime_error(std::string("cannot create socket: ") +
                               std::strerror(errno));
    }
    int result =
        ::connect(rc.get()->fd(), (const struct ::sockaddr *)&addr_unixsock,
                  sizeof(addr_unixsock));
    if (result == -1) {
      throw std::runtime_error(std::string("cannot connect to: ") + sock_name_ +
                               ": " + std::strerror(errno));
    }

    std::cerr << "connected to ssh-agent: " << rc->fd() << std::endl;

    return rc;
  }
};

class LaunchDSockets {
private:
  std::vector<std::unique_ptr<FD>> fds_{};

  std::vector<std::unique_ptr<Proxy>> proxies{};
  std::unique_ptr<SSHAgent> ssh_agent{new SSHAgent()};

  void cleanup() {
    std::cerr << "clearing launchd sockets..." << std::endl;
    for (auto it = fds_.begin(); it != fds_.end(); ++it) {
      it->reset(nullptr);
    }
    fds_.clear();
    std::cerr << "terminating proxies..." << std::endl;
    for (auto it = proxies.begin(); it != proxies.end(); ++it) {
      it->reset(nullptr);
    }
    proxies.clear();
    std::cerr << "terminating ssh-agent..." << std::endl;
    ssh_agent.reset(nullptr);
    std::cerr << "accept() shall be interrupted: ";
  }

  std::unique_ptr<FD> accept() {
    struct ::sockaddr_un addr_unixsock;
    while (true) {
      ::socklen_t addr_len = sizeof(addr_unixsock);
      auto rc = std::make_unique<FD>(::accept(
          fds_[0]->fd(), (struct ::sockaddr *)&addr_unixsock, &addr_len));
      if (rc->fd() == -1) {
        fds_.erase(fds_.begin());
        if (fds_.size() < 1) {
          throw std::runtime_error(
              std::string("in accept'ing launchd socket: ") +
              std::strerror(errno));
        }
        continue;
      }

      ::uid_t euid;
      ::gid_t egid;
      if (::getpeereid(rc->fd(), &euid, &egid) == -1) {
        throw std::runtime_error(std::string("getpeerid of launchd socket: ") +
                                 std::strerror(errno));
      }
      ::uid_t me = ::getuid();
      if (me != euid) {
        throw new SecurityException(std::string("uid mismatch: peer euid ") +
                                    std::to_string(euid) + " != uid ");
      }

      std::cerr << "accepted launchd: " << rc->fd() << std::endl;

      return rc;
    }
  }

public:
  LaunchDSockets() {
    int *fds = nullptr;
    size_t count = 0;
    int result = launch_activate_socket("Listeners", &fds, &count);
    int num_socket = (result == 0 && fds != nullptr ? count : 0);
    if (fds != nullptr) {
      std::cerr << count << " launchd socket(s) activated." << std::endl;
      // fds_.insert(fds_.begin(), fds, fds + count);
      for (size_t i = 0; i < count; ++i) {
        fds_.push_back(std::unique_ptr<FD>(new FD(fds[i])));
      }
      free(fds);
    }
    if (num_socket < 1) {
      cleanup();
      throw std::runtime_error(std::string("launch_activate_socket(): ") +
                               std::strerror(result));
    }
  }
  ~LaunchDSockets() { cleanup(); }

  void proxyToSSHAgent(std::string const& ssh_agent_cmd) {
    while (true) {
      try {
        std::cerr << "accepting launchd socket.\n" << std::flush;
        auto launchdSock = accept();
        std::cerr << "done. conneting to ssh_agent.\n" << std::flush;
        auto ssh_agentSock = ssh_agent->connect(ssh_agent_cmd); // delayed launch.
        std::cerr << "done. proxying...\n" << std::flush;
        proxies.push_back(std::make_unique<Proxy>(launchdSock, ssh_agentSock));
      } catch (const SecurityException &e) {
        // connected by an unknown user.
        std::cerr << e.what() << std::endl;
        continue;
      }
      for (auto it = proxies.begin(); it != proxies.end();) {
        if ((*it)->done()) {
          it->reset(nullptr);
          proxies.erase(it);
        } else {
          ++it;
        }
      }
      std::cerr << "number of proxies: " + std::to_string(proxies.size()) + '\n'
                << std::flush;
    }
  }
};

}; // namespace

static std::unique_ptr<LaunchDSockets> launchdSocks;

static void cleanup(int) { launchdSocks.reset(nullptr); }

int main(int argc, char *argv[]) {
  std::signal(SIGINT, SIG_IGN);
  std::signal(SIGHUP, SIG_IGN);
  std::string ssh_agent_cmd{argc >= 2 ? argv[1] : "/usr/local/bin/ssh-agent"};
  try {
    if (::access(ssh_agent_cmd.c_str(), X_OK) != 0) {
      throw std::runtime_error(
          ssh_agent_cmd +
          " is not executable. Check if it exsists and is executable.");
    }
    std::cerr << "creating launch socket object." << std::endl;
    launchdSocks = std::make_unique<LaunchDSockets>();
    std::signal(SIGTERM, cleanup);
    std::cerr << "done creating launch socket object." << std::endl;
    launchdSocks->proxyToSSHAgent(ssh_agent_cmd);
    return EXIT_SUCCESS;
  } catch (const std::exception &e) {
    std::cerr << "caught exception: " << e.what() << std::endl;
  } catch (...) {
    std::cerr << "caught unkown exception." << std::endl;
  }
  return EXIT_FAILURE;
}

// end of file
