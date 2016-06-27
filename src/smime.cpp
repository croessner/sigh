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
#include <syslog.h>

#include <sstream>
#include <boost/filesystem.hpp>

#include "util.h"
#include "mapfile.h"

namespace fs = boost::filesystem;

namespace smime {
    // Public

    std::ostream & operator<<(std::ostream &out, const Smime &sm) {
        out << *sm.bodyAsString();

        return out;
    }

    Smime::Smime(FILE *msg, const std::string &envfrom)
            : fcontent(msg),
              loaded(true),
              smimeSigned(false),
              mailFrom([&]() -> decltype(mailFrom) {
                  if (envfrom.front() == '<' && envfrom.back() == '>')
                      return envfrom.substr(1, envfrom.size()-2);
                  else
                      return envfrom;
              }()) { /* empty */ }

    void Smime::sign() {
        if (!isLoaded())
            return;

        // Null-mailer
        if (mailFrom.empty())
            return;

        /*
        const mimetic::ContentType &ct = me->header().contentType();

        bool signedOrEncrypted = false;

        // S/MIME and OpenPGP: multipart/signed
        if (ct.isMultipart() && ct.subtype() == "signed")
            signedOrEncrypted = true;

        // OpenPGP: multipart/encrypted
        if (ct.isMultipart() && ct.subtype() == "encrypted")
            signedOrEncrypted = true;

        // S/MIME: application/pkcs7-mime
        if (ct.type() == "application" && ct.subtype() == "pkcs7-mime")
            signedOrEncrypted = true;

        if (signedOrEncrypted) {
            const char logmsg[] = "Message already signed or encrypted";
            syslog(LOG_NOTICE, "%s", logmsg);
            return;
        }
        */

        /*
         * TODO:
         * Catch more cases, where an email already could have been encrypted
         * or signed elsewhere.
         */

        mapfile::Map email {mailFrom};

        auto cert = fs::path(email.getSmimeFilename<mapfile::Smime::CERT>());
        auto key = fs::path(email.getSmimeFilename<mapfile::Smime::KEY>());

        if (!fs::exists(cert) && !fs::is_regular(cert))
            return;
        if (!fs::exists(key) && !fs::is_regular(key))
            return;

        smimeSigned = true;
    }

    const std::unique_ptr<std::string> Smime::bodyAsString() const {
        if (!isLoaded() || !smimeSigned)
            return std::make_unique<std::string>("");

        char line[MAX_BODY_LINE_LENGTH];
        char eol[] = "\r\n";
        std::string dst = std::string();
        bool first_blank_line = false;

        while (fgets(line, sizeof(line), fcontent)) {
            if (!first_blank_line) {
                if (strncmp(line, eol, 1) == 0) {
                    first_blank_line = true;
                    continue;
                } else
                    continue;
            }
            dst += std::string(line);
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