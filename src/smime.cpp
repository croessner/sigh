/*! \file smime.cpp
 *
 * \brief Handle S/MIME messages
 *
 * \author Christian Rößner <c@roessner.co>
 * \version 1606.1.0
 * \date 2016-06-10
  * \copyright Copyright 2016 Christian Roessner <c@roessner.co>
 */

#include "smime.h"

#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>

#include "util.h"

namespace smime {
    // Public

    std::ostream & operator<<(std::ostream &out, const Smime &sm) {
        out << *sm.toString(sm.me);

        return out;
    }

    Smime::Smime() : me(nullptr), loaded(false) { /* empty */ }

    Smime::Smime(std::ifstream &msg, const std::string &mailfrom)
            : me(std::make_shared<mimetic::MimeEntity>(msg)),
              loaded(true),
              mailfrom(mailfrom) { /* empty */ }

    void Smime::loadMimeEntity(
            std::ifstream &msg, const std::string &mailfrom) {
        if (!isLoaded()) {
            me = std::make_shared<mimetic::MimeEntity>(msg);
            this->mailfrom = mailfrom;
            loaded = true;
        }
    }

    void Smime::sign() {
        if (isLoaded()) {

        }
    }

    const std::unique_ptr<std::string> Smime::toString(
            const std::shared_ptr<mimetic::MimeEntity> msg) const {
        if (!isLoaded())
            return std::make_unique<std::string>("");

        /*
         * stringstream uses an internal line separator "\n", so our "\r\n"
         * becomes just a single "\r". We repair this while assigning string
         * "s" to the final destination string "dst".
         */

        std::stringstream src;
        std::string s, dst;
        bool first_blank_line = false;

        src << *msg;

        while (std::getline(src, s)) {
            if (!first_blank_line) {
                if (s.at(0) == '\r' || s.empty()) {
                    first_blank_line = true;
                    continue;
                } else
                    continue;
            }

            if (s.at(s.size() - 1) == '\r')
                dst += s + '\n';
            else
                dst += s;
        }

        auto body = std::make_unique<std::string>(dst);

        return body;
    }

    // Private

    void Smime::changeHeader(SMFICTX *ctx,
                             const std::string &headerk,
                             const std::string &headerv) {
        int result = smfi_chgheader(ctx,
                                    util::ccp(headerk.c_str()),
                                    1,
                                    util::ccp(headerv.c_str()));
        if (result == MI_FAILURE)
            std::cerr << "Error: Could not change header " << headerk
                      << " to value " << headerv
                      << std::endl;
    }
}  // namespace smime