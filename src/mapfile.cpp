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
#include <mutex>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>

#include "mapfile.h"

namespace fs = boost::filesystem;

namespace mapfile {
    static std::mutex confLock;

    using boost::split;
    using boost::is_any_of;
    using boost::token_compress_on;

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

    const std::string & Map::getCert(void) {
        if (loaded && certStore.count(mailFrom) == 1)
            getSmimeParts(Smime::CERT);

        return smimeCert;
    }

    const std::string & Map::getKey(void) {
        if (loaded && certStore.count(mailFrom) == 1)
            getSmimeParts(Smime::KEY);

        return smimeKey;
    }

    // Private

    void Map::setSmimeFiles(
            const Smime &component,
            const split_t &src,
            const std::string &what,
            size_t pos = 0) {
        split_t parts;
        std::size_t found;

        found = src.at(pos).find(what);
        if (found != std::string::npos) {
            split(parts, src.at(pos), is_any_of(":"), token_compress_on);
            if (parts.size() != 2)
                return;
            switch (component) {
                case Smime::CERT:
                    smimeCert = parts.at(1);
                    break;
                case Smime::KEY:
                    smimeKey = parts.at(1);
                    break;
            }
        } else {
            if (pos == 1)
                return;
            setSmimeFiles(component, src, what, ++pos);
        }
    }

    void Map::getSmimeParts(const Smime &component) {
        std::string raw = certStore[mailFrom];
        split_t parts;

        // Split the value in two pieces
        split(parts, raw, is_any_of(","), token_compress_on);

        if (parts.size() != 2)
            return;

        switch (component) {
            case Smime::CERT:
                setSmimeFiles(component, parts, "cert:");
                break;
            case Smime::KEY:
                setSmimeFiles(component, parts, "key:");
                break;
        }
    }

    certstore_t Map::certStore = {};

    bool Map::loaded = false;

}  // namespace mapfile