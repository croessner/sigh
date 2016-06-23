/*! \file mapfile.cpp
 *
 * \brief Read a map file
 *
 * \author Christian Rößner <c@roessner.co>
 * \version 1606.1.0
 * \date 2016-06-10
  * \copyright Copyright 2016 Christian Roessner <c@roessner.co>
 */

#include <fstream>
#include <iostream>
#include <sstream>
#include <boost/filesystem.hpp>

#include "mapfile.h"

namespace fs = boost::filesystem;

namespace mapfile {
    Map::Map(const std::string &mailfrom) { }

    void Map::readMap(const std::string &mapfile) {
        if (!fs::exists(fs::path(mapfile))
            && !fs::is_regular(fs::path(mapfile))) {
            std::cerr << "Error: Can not read mapfile " << mapfile << std::endl;
            return;
        }

        try {
            std::ifstream store {mapfile};
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
                certstore[keycol] = valuecol;
            }

            store.close();
            mapLoaded = true;
        }
        catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return;
        }
    }

    std::string Map::getCert(const std::string &mailfrom) const { }

    std::string Map::getKey(const std::string &mailfrom) const { }

    certstore_t Map::certstore = {};

    bool Map::mapLoaded = false;

}  // namespace mapfile