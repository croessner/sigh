/*! \file client.h
 *
 * \brief Declare the class Client that is used to store SMTP session data
 *
 * \author Christian Rößner <c@roessner.co>
 * \version 1606.1.0
 * \date 2016-06-10
  * \copyright Copyright 2016 Christian Roessner <c@roessner.co>
 */

#ifndef SRC_CLIENT_H_
#define SRC_CLIENT_H_

#include <libnet.h>

#include <string>
#include <map>
#include <cstdio>
#include <fstream>
#include <memory>

#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;

extern bool debug;

namespace mlt {
    typedef u_long counter_t;

    /*!
     * \brief This class stores SMTP session data
     */
    class Client {
    public:
        /*!
         * \brief Constructor
         */
        Client(const std::string &, struct sockaddr *);

        /*!
         * \brief Destructor
         *
         * On client disconnect, a temporary file will be removed
         */
        virtual ~Client();

        /*!
         * \brief Create a new temporary file for each email
         *
         * Whenever a connected client sends a message, a new temporary file
         * gets created. If the file cannot be created, the internal pointer
         * is set to nullptr.
         */
        bool createContentFile(const std::string &);

        //! \brief SMTP session data map
        std::map<std::string, char *> sessionData;

        //! \brief Email content gets stored in a temp file
        FILE *fcontent;

        //! \brief Hostname of a connected client
        const std::string hostname;

        //! \brief IPv4/IPv6:port of a connected client
        const std::string ipAndPort;

        //! \brief Identifier that a client got after a connect
        const counter_t id;

    private:
        /*!
         * \brief Convert struct sockaddr to a string representation
         *
         * Take a struct hostaddr and convert it to a string address:port for
         * IPv4 addresses and [address]:port for IPv6. If the string can not be
         * constructed, set its value to "unknown".
         *
         * \return String representation of a struct sockaddr
         */
        static const std::string prepareIPandPort(struct sockaddr *);

        /*!
         * \brief Close remaining content file and remove it safely
         */
        void cleanup(void);

        /*!
         * \brief Unique identifier
         *
         * A global unique identifier that gets incremented for each new
         * client connection.
         */
        static counter_t uniqueId;

        //! \brief Name of a temporary file for email content
        fs::path temp;
    };
}  // namespace mlt

#endif  // SRC_CLIENT_H_
