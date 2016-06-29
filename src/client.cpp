/*! \file client.cpp
 *
 * \brief Implements a class that stores client SMTP session information.
 *
 * The main purpose of this class is to store all kind of SMTP session
 * information that come in while a client runs through all the callbacks.
 * The data itself is organized in a list. An instance of this class is
 * carried with the smfi_getpriv() routine.
 *
 * \author Christian Rößner <c@roessner.co>
 * \version 1606.1.0
 * \date 2016-06-10
  * \copyright Copyright 2016 Christian Roessner <c@roessner.co>
*/

#include "client.h"

#include <mutex>
#include <iostream>
#include <string>

namespace mlt {
    //! \brief This lock is for the unique identifier
    static std::mutex uniqueIdLock;

    // Public

    Client::Client(const std::string &hostname, struct sockaddr *hostaddr)
            : fcontent(nullptr),
              hostname(hostname),
              ipAndPort(Client::prepareIPandPort(hostaddr)),
              // Increase uniqueId and initialize member id
              id([]() -> decltype(uniqueId) {
                  uniqueIdLock.lock();
                  ++uniqueId;
                  uniqueIdLock.unlock();

                  return uniqueId;
              }()),
              mailflags(mailflags::TYPE_NONE),
              optionalPreamble(true),
              genericError(false),
              fcontentStatus(false) { /* empty */ }

    Client::~Client() {
        try {
            cleanup();

            // Clear session data
            std::map<std::string, char *>::iterator mit;
            for (mit=sessionData.begin(); mit!=sessionData.end(); mit++)
                if (mit->second != nullptr)
                    free(mit->second);

            // Clear list of marked headers
            std::vector<char *>::iterator vit;
            for (vit=markedHeaders.begin(); vit!=markedHeaders.end(); vit++)
                if (*vit != nullptr)
                    free(*vit);
        }
        catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }

    bool Client::createContentFile(const std::string &tmpdir) {
        try {
            cleanup();
        }
        catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return false;
        }

        if (!fs::exists(fs::path(tmpdir))
            && !fs::is_directory(fs::path(tmpdir))) {
            std::cerr << "Error: Can not access temporary directory"
                      << std::endl;
            return false;
        }

        // Create a temporary file for the email content
        temp = fs::unique_path(tmpdir + "/%%%%-%%%%-%%%%-%%%%.eml");
        try {
            fcontent = fopen(temp.string().c_str(), "w+");
            fcontentStatus = true;
        }
        catch (const std::exception &e) {
            fcontent = nullptr;
            std::cerr << "Error: " << e.what() << std::endl;
        }

        return fcontent != nullptr;
    }

    void Client::reset() {
        // Clear session data
        std::map<std::string, char *>::iterator mit;
        for (mit=sessionData.begin(); mit!=sessionData.end(); mit++)
            if (mit->second != nullptr) {
                free(mit->second);
                mit->second = nullptr;
            }
        sessionData.clear();

        // Clear list of marked headers
        std::vector<char *>::iterator vit;
        for (vit=markedHeaders.begin(); vit!=markedHeaders.end(); vit++)
            if (*vit != nullptr) {
                free(*vit);
                *vit = nullptr;
            }
        markedHeaders.clear();

        this->mailflags = mailflags::TYPE_NONE;
        optionalPreamble = true;
        genericError = false;
        fcontentStatus = false;
    }

    // Private

    const std::string Client::prepareIPandPort(struct sockaddr *hostaddr) {
        assert(hostaddr != nullptr);

        std::string ipport;
        char clienthost[NI_MAXHOST];
        char clientport[NI_MAXSERV];
        int result = getnameinfo(hostaddr, sizeof(*hostaddr),
                                 clienthost, sizeof(clienthost),
                                 clientport, sizeof(clientport),
                                 NI_NUMERICHOST | NI_NUMERICSERV);

        if (result != 0) {
            std::cerr << "Error: " << gai_strerror(result) << std::endl;
            ipport = "unknown";
        } else {
            switch (hostaddr->sa_family) {
                case AF_INET:
                    ipport = std::string {clienthost} + ":"
                             + std::string {clientport};
                    break;
                case AF_INET6:
                    ipport = "[" + std::string {clienthost} + "]:"
                             + std::string {clientport};
                    break;
                default:
                    ipport = "unknown";
            }
        }

        return ipport;
    }

    void Client::cleanup(void) {
        if (getFcontentStatus() || fcontent != nullptr) {
            fclose(fcontent);
            fcontent = nullptr;
        }
#if !defined _KEEP_TEMPFILES
        // Remove temporary file
        try {
            if (fs::exists(temp) && fs::is_regular(temp))
                fs::remove(temp);
        }
        catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }
#endif  // ! defined _KEEP_TEMPFILES
    }

// Init static

    counter_t Client::uniqueId = 0UL;

}  // namespace mlt
