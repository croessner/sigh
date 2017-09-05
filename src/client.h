/*! @file client.h
 *
 * @brief Declare the class Client that is used to store SMTP session data
 *
 * @author Christian Roessner <c@roessner.co>
 * @version 1607.1.4
 * @date 2016-06-10
 * @copyright Copyright 2016 Christian Roessner <c@roessner.co>
 */

#ifndef SRC_CLIENT_H_
#define SRC_CLIENT_H_

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <string>
#include <map>
#include <cstdio>
#include <fstream>
#include <memory>
#include <vector>
#include <utility>

#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;

extern bool debug;

namespace mlt {
    using counter_t = u_long;
    using sessionData_t = std::map<std::string, std::string>;
    using markedHeaders_t = std::vector<std::pair<std::string, std::string>>;

    /*!
     * @brief Internal detecting flags
     *
     * We check for certain headers. ANDing and ORing makes processing faster
     */
    enum mailflags {
        TYPE_NONE        = 0x0,
        TYPE_MIME        = 0x1,
        TYPE_MULTIPART   = 0x2
    };

    /*!
     * @brief This class stores SMTP session data
     */
    class Client {
    public:
        /*!
         * @brief Constructor
         */
        Client(const std::string &, struct sockaddr *);

        /*!
         * @brief Destructor
         *
         * On client disconnect, a temporary file will be removed
         */
        virtual ~Client(void);

        /*!
         * @brief Create a new temporary file for each email
         *
         * Whenever a connected client sends a message, a new temporary file
         * gets created. If the file cannot be created, the internal pointer
         * is set to nullptr.
         */
        bool createContentFile(const std::string &);

        /*!
         * @brief The path to a temp file for a connected client
         */
        inline const std::string & getTempFile() const {
            return temp.string();
        }

        /*!
         * @brief Status of the temp file
         */
        inline bool getFcontentStatus(void) { return fcontentStatus; }

        /*!
         * @brief Clear existing data structures for a client
         *
         * We mus always clear data structures at the end of each message,
         * as a connected client might send more than one message in a SMTP
         * session.
         */
        void reset(void);

        //! @brief SMTP session data map
        sessionData_t sessionData;

        /*!
         * @brief List of headers to be removed from original message
         *
         * First element is a mail header key, second its header value
         */
        markedHeaders_t markedHeaders;

        //! @brief Email content gets stored in a temp file
        FILE *fcontent;

        //! @brief Hostname of a connected client
        const std::string hostname;

        //! @brief IPv4/IPv6:port of a connected client
        const std::string ipAndPort;

        //! @brief Identifier that a client got after a connect
        const counter_t id;

        //! @brief Current detected header flags ORed together
        u_int8_t mailflags;

        //! @brief Flag that signals an existing MIME preamble
        bool optionalPreamble;

        //! @brief If an error occurs while signing the mail, this flag is set
        bool genericError;

    private:
        /*!
         * @brief Convert struct sockaddr to a string representation
         *
         * Take a struct hostaddr and convert it to a string address:port for
         * IPv4 addresses and [address]:port for IPv6. If the string can not be
         * constructed, set its value to "unknown".
         *
         * @return String representation of a struct sockaddr
         */
        static const std::string prepareIPandPort(struct sockaddr *);

        /*!
         * @brief Close remaining content file and remove it safely
         */
        void cleanup(void);

        /*!
         * @brief Unique identifier
         *
         * A global unique identifier that gets incremented for each new
         * client connection.
         */
        static counter_t uniqueId;

        //! @brief Name of a temporary file for email content
        fs::path temp;

        //! @brief The status of the tem file. Closed (false), open (true)
        bool fcontentStatus;
    };
}  // namespace mlt

#endif  // SRC_CLIENT_H_
