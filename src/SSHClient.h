#ifndef SSHCLIENT_H
#define SSHCLIENT_H

#include <libssh/libssh.h>
#include <string>

class SSHClient {
public:
    SSHClient(const std::string &host, const std::string &user);
    ~SSHClient();

    bool connect(const std::string &password, int timeoutSec = 10);
    int executeCommand(const std::string &command);
    void disconnect();
    bool isConnected() const;

private:
    std::string host_;
    std::string user_;
    ssh_session my_ssh_session;
    bool is_connected_;
};

#endif // SSHCLIENT_H