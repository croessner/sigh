/*! @file client.cpp
 *
 * @brief Implements a class that stores client SMTP session information.
 *
 * The main purpose of this class is to store all kind of SMTP session
 * information that come in while a client runs through all the callbacks.
 * The data itself is organized in a list. An instance of this class is
 * carried with the smfi_getpriv() routine.
 *
 * @author Christian Roessner <c@roessner.co>
 * @version 1607.1.3
 * @date 2016-06-10
 * @copyright Copyright 2016 Christian Roessner <c@roessner.co>
*/

#include "client.h"

#include <mutex>
#include <iostream>
#include <string>

namespace mlt {
    //! @brief This lock is for the unique identifier
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
              mailflags(mlt::mailflags::TYPE_NONE),
              optionalPreamble(true),
              genericError(false),
              fcontentStatus(false) { /* empty */ }

    Client::~Client() {
        try {
            cleanup();
        } catch (const std::exception &e) {
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
        sessionData.clear();
        markedHeaders.clear();
        mailflags = mlt::mailflags::TYPE_NONE;
        optionalPreamble = true;
        genericError = false;
        fcontentStatus = false;
    }

    // Private

    const std::string Client::prepareIPandPort(struct sockaddr *hostaddr) {
        assert(hostaddr != nullptr);

        socklen_t hostaddrlen;

        switch (hostaddr->sa_family) {
            case AF_INET:
                hostaddrlen = sizeof(sockaddr_in);
                break;
            case AF_INET6:
                hostaddrlen = sizeof(sockaddr_in6);
                break;
            default:
                std::cerr << "Error: " << gai_strerror(EAI_FAMILY) << std::endl;
                return "unknown";
        }

        std::string ipport;
        char clienthost[NI_MAXHOST];
        char clientport[NI_MAXSERV];
        int result = getnameinfo(hostaddr, hostaddrlen,
                                 clienthost, sizeof(clienthost),
                                 clientport, sizeof(clientport),
                                 NI_NUMERICHOST | NI_NUMERICSERV);

        if (result != 0) {
            std::cerr << "Error: " << gai_strerror(result) << std::endl;
            ipport = "unknown";
        } else {
            switch (hostaddr->sa_family) {
                case AF_INET:
                    ipport = std::string(clienthost) + ":"
                             + std::string(clientport);
                    break;
                case AF_INET6:
                    ipport = "[" + std::string(clienthost) + "]:"
                             + std::string(clientport);
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
