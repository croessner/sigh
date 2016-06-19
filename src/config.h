/*! \file config.h
 *
 * \brief Handle a milter configuration file
 *
 * \author Christian Rößner <c@roessner.co>
 * \version 1606.1.0
 * \date 2016-06-10
  * \copyright Copyright 2016 Christian Roessner <c@roessner.co>
 */

#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_

#include <map>
#include <string>

#include <boost/any.hpp>
#include <boost/program_options/variables_map.hpp>

namespace po = boost::program_options;

extern bool debug;

namespace conf {
    using boost::any_cast;

    typedef std::map<std::string, boost::any> config_t;

    /*!
     * \brief Read a configuration file and store settings
     *
     * All milter settings may be stored in a configuration file. This class
     * reads a default configuration file, if not given as command line
     * argument and extracts all keys and values. For each key that is not
     * found, but requested my the milter, a default value is defined in a
     * local data structure.
     */
    class MilterCfg {
    public:
        MilterCfg(const po::variables_map &);

        virtual ~MilterCfg() = default;

        /*!
         * \brief The milter socket
         *
         * The socket may have one of three formats. First is
         * inet:portnumber\@host, second is inet6:portnumber\@host6 or a unix
         * socket like unix:/pat/to/socket. host and host6 may be a hostname
         * or a valid IP address. IPv6 addresses must be written in squared
         * braces.
         */
        inline std::string getSocket(void) {
            return any_cast<std::string>(param["socket"]);
        }

        /*!
         * The milter will drop its privileges to this user
         */
        inline std::string getUser(void) {
            return any_cast<std::string>(param["user"]);
        }

        /*!
         * The milter will drop its privileges to this group
         */
        inline std::string getGroup(void) {
            return any_cast<std::string>(param["group"]);
        }

        /*!
         * \brief An optional PID file
         *
         * If desired, a PID file may be created on startup. It will be
         * automatically removed, when the milter gets stopped again.
         */
        inline std::string getPidFile(void) {
            return any_cast<std::string>(param["pidfile"]);
        }

#if !__APPLE__ && !defined _NOT_DAEMONIZE
        /*!
         * \brief Bring the milter to background
         *
         * The milter gets a daemon. The root path is set to '/' and the
         * standard in and out channels are closed
         */
        inline bool getDaemon(void) {
            return any_cast<bool>(param["daemon"]);
        }
#endif  // !__APPLE__ && !defined _NOT_DAEMONIZE

    private:
        /*!
         * \brief Data store for configuration settings
         */
        config_t param;

        /*!
         * \brief Default settings for the milter
         *
         * If a required setting could not be read from the configuration, a
         * default setting will be used from this data structure.
         */
        struct {
            //! \brief Milter socket
            std::string socket  = "inet:4000@127.0.0.1";
            //! \brief Milter system user
            std::string user    = "milter";
            //! \brief Milter system group
            std::string group   = "milter";
            //! \brief Optional PID file
            std::string pidfile = std::string();
#if !__APPLE__ && !defined _NOT_DAEMONIZE
            //! \brief Run the milter as a daemon process
            bool daemon         = false;
#endif  // !__APPLE__ && !defined _NOT_DAEMONIZE
        } defaults;
    };
}  // namespace conf

#endif  // SRC_CONFIG_H_