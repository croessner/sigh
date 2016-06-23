/*! \file mapfile.h
 *
 * \brief Read a map file
 *
 * \author Christian Rößner <c@roessner.co>
 * \version 1606.1.0
 * \date 2016-06-10
  * \copyright Copyright 2016 Christian Roessner <c@roessner.co>
 */

#ifndef SRC_MAP_H_
#define SRC_MAP_H_

#include <string>
#include <map>

extern bool debug;

namespace mapfile {
    typedef std::map<std::string, std::string> certstore_t;

    class Map {
    public:
        Map(const std::string &);

        virtual ~Map() = default;

        static void readMap(const std::string&);

        std::string getCert(const std::string &) const;

        std::string getKey(const std::string &) const;

    private:
        static certstore_t certstore;

        static bool mapLoaded;

        std::string mailfrom;

        std::string cert;

        std::string key;
    };
}  // namespace mapfile

#endif  // SRC_MAP_H_
