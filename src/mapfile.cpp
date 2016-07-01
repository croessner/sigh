/*! \file mapfile.cpp
 *
 * \brief Read a map file
 *
 * \author Christian Roessner <c@roessner.co>
 * \version 1606.1.0
 * \date 2016-06-10
  * \copyright Copyright 2016 Christian Roessner <c@roessner.co>
 */

#include <fstream>
#include <iostream>
#include <sstream>
#include <mutex>
#include <boost/filesystem.hpp>

#include "mapfile.h"

namespace fs = boost::filesystem;

namespace mapfile {
    static std::mutex confLock;

    // Public

    Map::Map(const std::string &envfrom)
            : mailFrom(envfrom),
              smimeCert(std::string()),
              smimeKey(std::string()) { /* empty */ }

    void Map::readMap(const std::string &mapfile) {
        if (!fs::exists(fs::path(mapfile))
            && !fs::is_regular(fs::path(mapfile))) {
            std::cerr << "Error: Can not read mapfile " << mapfile << std::endl;
            return;
        }

        try {
            std::ifstream store(mapfile);
            std::string line;
            std::string keycol, valuecol;

            while (std::getline(store, line)) {
                if (line.empty() || line.front() == '#')
                    continue;
                std::stringstream record(line);
                record >> keycol >> valuecol;
                if (valuecol.empty()) {
                    std::cerr << "Error: Wrong table format in mapfile "
                              << mapfile << std::endl;
                    return;
                }
                if (::debug)
                    std::cout << "keycol=" << keycol
                              << " valuecol=" << valuecol << std::endl;

                confLock.lock();
                certStore[keycol] = valuecol;
                confLock.unlock();
            }

            store.close();
            loaded = true;
        }
        catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return;
        }
    }

    // Private

    certstore_t Map::certStore = {};

    bool Map::loaded = false;

}  // namespace mapfile