/*! @file mapfile.h
 *
 * @brief Read a map file
 *
 * @author Christian Roessner <c@roessner.co>
 * @version 1607.1.4
 * @date 2016-06-10
 * @copyright Copyright 2016 Christian Roessner <c@roessner.co>
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

    using certstore_t =  std::map<std::string, std::string>;
    using split_t =  std::vector<std::string>;

    /*!
     * @brief Type selector. S/MIME certificate or key
     */
    enum class Smime {CERT, KEY};

    /*!
     * @brief Load a map file
     *
     * Load a map file containing email addresses as keys and certificate
     * paths as value. It is loaded on startup and can be reloaded by
     * signaling the milter with SIGHUP.
     */
    class Map {
    public:
        /*!
         * @brief Constructor
         *
         * Find S/MIME cert and key based on an email address
         */
        Map(const std::string &);

        /*!
         * @brief Destructor
         */
        virtual ~Map(void) = default;

        /*!
         * @brief Read a map file and store data internally in certStore
         */
        static void readMap(const std::string&);

        /*!
         * @brief Reset the certificate table
         */
        static void resetCertStore(void);

        /*!
         * @brief A certificate or key
         */
        template <Smime>
        const std::string & getSmimeFilename(void);

    private:
        /*!
         * @brief Setter which checks for a cert and key
         *
         * Prepare internal attributes smimeCert and smimeKey
         */
        template <Smime, size_t pos=0>
        void setSmimeFile(const split_t &);

        /*!
         * @brief System wide certificate store
         *
         * When data gets read by readMap(), all recognized table records are
         * stored into this map. No further splitting or testing is done here.
         */
        static certstore_t certStore;

        /*!
         * @brief Flag to signal, if a map file could be loaded
         */
        static bool loaded;

        /*!
         * @brief The MAIL FROM address as used as a key for the certStore
         */
        const std::string mailFrom;

        /*!
         * @brief S/MIME certificate of a user
         */
        std::string smimeCert;

        /*!
         * @brief S/MIME key of a user
         */
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
