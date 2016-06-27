/*! \file config.cpp
 *
 * \brief Handle a milter configuration file
 *
 * \author Christian Rößner <c@roessner.co>
 * \version 1606.1.0
 * \date 2016-06-10
  * \copyright Copyright 2016 Christian Roessner <c@roessner.co>
 */

#include "config.h"

#include <iostream>

#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>

namespace fs = boost::filesystem;

namespace conf {
    using boost::any_cast;

    // Public

    MilterCfg::MilterCfg(const po::variables_map &vm) {
        std::string conffile = vm["config"].as<std::string>();

        boost::property_tree::ptree pt;
        try {
            if (fs::exists(fs::path(conffile))
                && fs::is_regular(fs::path(conffile))) {
                boost::property_tree::ini_parser::read_ini(conffile, pt);
            } else {
                std::cerr << "Error: Unable to read config file "
                          << conffile << std::endl;
            }
        }
        catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }

        try {
            param["socket"] = pt.get<std::string>("Milter.socket");
        }
        catch (...) {
            param["socket"] = defaults.socket;
        }

        try {
            param["user"] = pt.get<std::string>("Milter.user");
        }
        catch (...) {
            param["user"] = defaults.user;
        }

        try {
            param["group"] = pt.get<std::string>("Milter.group");
        }
        catch (...) {
            param["group"] = defaults.group;
        }

        try {
            param["pidfile"] = pt.get<std::string>("Milter.pidfile");
        }
        catch (...) {
            param["pidfile"] = defaults.pidfile;
        }

        try {
            param["mapfile"] = pt.get<std::string>("Milter.mapfile");
        }
        catch (...) {
            param["mapfile"] = defaults.mapfile;
        }

        try {
            param["tmpdir"] = pt.get<std::string>("Milter.tmpdir");
        }
        catch (...) {
            param["tmpdir"] = defaults.tmpdir;
        }

#if !__APPLE__ && !defined _NOT_DAEMONIZE
        try {
            param["daemon"] = pt.get<bool>("Milter.daemon");
        }
        catch (...) {
            param["daemon"] = defaults.daemon;
        }
#endif  // !__APPLE__ && !defined _NOT_DAEMONIZE

        if (::debug) {
            std::cout << "Configuration file values:" << std::endl;

            std::cout << "user="
                << any_cast<std::string>(param["user"])
                << std::endl;
            std::cout << "group="
                << any_cast<std::string>(param["group"])
                << std::endl;
            std::cout << "socket="
                << any_cast<std::string>(param["socket"])
                << std::endl;
            std::cout << "pidfile="
                << any_cast<std::string>(param["pidfile"])
                << std::endl;
#if !__APPLE__ && !defined _NOT_DAEMONIZE
            std::cout << "daemon="
                << std::boolalpha << any_cast<bool>(param["daemon"])
                << std::endl;
#endif  // !__APPLE__ && !defined _NOT_DAEMONIZE
            std::cout << "mapfile="
                << any_cast<std::string>(param["mapfile"])
                << std::endl;
            std::cout << "tmpdir="
                << any_cast<std::string>(param["tmpdir"])
                << std::endl;
        }
    }
}  // namespace conf