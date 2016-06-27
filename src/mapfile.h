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
#include <vector>
#include <boost/algorithm/string.hpp>

extern bool debug;

namespace mapfile {
    using boost::split;
    using boost::is_any_of;
    using boost::token_compress_on;

    typedef std::map<std::string, std::string> certstore_t;

    typedef std::vector<std::string> split_t;

    enum class Smime {CERT, KEY};

    class Map {
    public:
        Map(const std::string &);

        virtual ~Map() = default;

        static void readMap(const std::string&);

        template <Smime>
        const std::string & getSmimeFilename(void);

    private:
        template <Smime, size_t pos=0>
        void setSmimeFile(const split_t &);

        static certstore_t certStore;

        static bool loaded;

        const std::string mailFrom;

        std::string smimeCert;

        std::string smimeKey;
    };

    // Public

    template <Smime component>
    const std::string & Map::getSmimeFilename() {
        if (loaded && certStore.count(mailFrom) == 1) {
            std::string raw = certStore[mailFrom];
            split_t parts;

            // Split the value in two pieces
            split(parts, raw, is_any_of(","), token_compress_on);

            if (parts.size() == 2)
                setSmimeFile<component>(parts);
        }

        return (component == Smime::CERT) ? smimeCert : smimeKey;
    }

    // Private

    template <Smime component, size_t pos>
    void Map::setSmimeFile(const split_t &src) {
        split_t parts;
        std::size_t found;
        std::string what;

        what = (component == Smime::CERT) ? "cert:" : "key:";

        found = src.at(pos).find(what);
        if (found != std::string::npos) {
            split(parts, src.at(pos), is_any_of(":"), token_compress_on);
            if (parts.size() != 2)
                return;
            if (component == Smime::CERT)
                smimeCert = parts.at(1);
            else
                smimeKey = parts.at(1);
        } else {
            if (pos == 1)
                return;
            setSmimeFile<component, 1>(src);
        }
    }
}  // namespace mapfile

#endif  // SRC_MAP_H_
