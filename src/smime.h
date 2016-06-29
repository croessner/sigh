/*! \file smime.h
 *
 * \brief Handle S/MIME messages
 *
 * \author Christian Rößner <c@roessner.co>
 * \version 1606.1.0
 * \date 2016-06-10
  * \copyright Copyright 2016 Christian Roessner <c@roessner.co>
 */

#ifndef SRC_SMIME_H_
#define SRC_SMIME_H_

#include <libmilter/mfapi.h>

#include <string>
#include <iostream>
#include <fstream>
#include <memory>
#include <vector>
#include <boost/algorithm/string.hpp>

namespace smime {
    using boost::split;
    using boost::trim;
    using boost::is_any_of;
    using boost::token_compress_on;

    typedef std::vector<std::string> split_t;

    class Smime {
    public:
        Smime(SMFICTX *);

        ~Smime(void) = default;

        inline bool isLoaded(void) const { return loaded; }

        inline bool isSmimeSigned(void) const { return smimeSigned; }

        void sign(void);

    private:
        int addHeader(const std::string &, const std::string &);

        int removeHeader(const std::string &);

        SMFICTX *ctx;

        bool loaded;

        bool smimeSigned;

        std::string mailFrom;
    };
}  // namespace smime

#endif  // SRC_SMIME_H_
