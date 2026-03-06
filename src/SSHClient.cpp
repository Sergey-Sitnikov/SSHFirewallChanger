#include "SSHClient.h"
#include <iostream>

SSHClient::SSHClient(const std::string &host, const std::string &user)
    : host_(host), user_(user), my_ssh_session(nullptr), is_connected_(false) {
    my_ssh_session = ssh_new();
}

SSHClient::~SSHClient() {
    disconnect();
}

bool SSHClient::connect(const std::string &password, int timeoutSec) {
    if (my_ssh_session == nullptr) return false;

    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, host_.c_str());
    ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, user_.c_str());
    ssh_options_set(my_ssh_session, SSH_OPTIONS_TIMEOUT, &timeoutSec);

    if (ssh_connect(my_ssh_session) != SSH_OK) {
        return false;
    }

    if (ssh_userauth_password(my_ssh_session, nullptr, password.c_str()) != SSH_AUTH_SUCCESS) {
        ssh_disconnect(my_ssh_session);
        return false;
    }

    is_connected_ = true;
    return true;
}

int SSHClient::executeCommand(const std::string &command) {
    if (!is_connected_) return SSH_ERROR;

    ssh_channel channel = ssh_channel_new(my_ssh_session);
    if (channel == nullptr) return SSH_ERROR;

    if (ssh_channel_open_session(channel) != SSH_OK) {
        ssh_channel_free(channel);
        return SSH_ERROR;
    }

    int rc = ssh_channel_request_exec(channel, command.c_str());
    if (rc != SSH_OK) {
        ssh_channel_free(channel);
        return rc;
    }
    
    
    char buffer[1024];
    int nbytes;
    while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0)) > 0) {
    
    }
    
    
    while (ssh_channel_is_open(channel) && 
           ssh_channel_get_exit_status(channel) == -1) {
           ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);

    return rc;
}

void SSHClient::disconnect() {
    if (is_connected_ && my_ssh_session) {
        ssh_disconnect(my_ssh_session);
        is_connected_ = false;
    }
    if (my_ssh_session) {
        ssh_free(my_ssh_session);
        my_ssh_session = nullptr;
    }
}

bool SSHClient::isConnected() const {
    return is_connected_;
}