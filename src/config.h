/*! @file config.h
 *
 * @brief Handle a milter configuration file
 *
 * @author Christian Roessner <c@roessner.co>
 * @version 1607.1.4
 * @date 2016-06-10
 * @copyright Copyright 2016 Christian Roessner <c@roessner.co>
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

    using config_t = std::map<std::string, boost::any>;

    /*!
     * @brief Read a configuration file and store settings
     *
     * All milter settings may be stored in a configuration file. This class
     * reads a default configuration file, if not given as command line
     * argument and extracts all keys and values. For each key that is not
     * found, but requested my the milter, a default value is defined in a
     * local data structure.
     */
    class MilterCfg {
    public:
        /*!
         * @brief Constructor
         */
        MilterCfg(const po::variables_map &);

        /*!
         * @brief Destructor
         */
        virtual ~MilterCfg(void) = default;

        /*!
         * @brief A configuration value
         */
        template <typename T=std::string, typename R=T>
        R getValue(const std::string &);

    private:
        /*!
         * @brief Data store for configuration settings
         */
        config_t param;

        /*!
         * @brief Default settings for the milter
         *
         * If a required setting could not be read from the configuration, a
         * default setting will be used from this data structure.
         */
        struct {
            //! @brief Milter socket
            std::string socket  = "inet:4000@127.0.0.1";
            //! @brief Milter system user
            std::string user    = "milter";
            //! @brief Milter system group
            std::string group   = "milter";
            //! @brief Optional PID file
            std::string pidfile = std::string();
#if !__APPLE__ && !defined _NOT_DAEMONIZE
            //! @brief Run the milter as a daemon process
            bool daemon         = false;
#endif  // !__APPLE__ && !defined _NOT_DAEMONIZE
            //! @brief Location for the map file
            std::string mapfile = std::string();
            //! @brief Location for temporary files
            std::string tmpdir = "/tmp";
        } defaults;
    };

    // Public

    template <typename T, typename R>
    R MilterCfg::getValue(const std::string &key) {
        if (param.count(key) == 0)
            return "";
        return any_cast<T>(param[key]);
    }
}  // namespace conf

#endif  // SRC_CONFIG_H_