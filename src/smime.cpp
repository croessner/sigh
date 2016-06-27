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
#include "client.h"
#include "mapfile.h"

namespace fs = boost::filesystem;

namespace smime {
    // Public

    std::ostream & operator<<(std::ostream &out, const Smime &sm) {
        out << *sm.bodyAsString();

        return out;
    }

    Smime::Smime(SMFICTX *ctx, FILE *msg, const std::string &envfrom)
            : ctx(ctx),
              fcontent(msg),
              loaded(true),
              smimeSigned(false),
              mailFrom([&]() -> decltype(mailFrom) {
                  if (envfrom.front() == '<' && envfrom.back() == '>')
                      return envfrom.substr(1, envfrom.size()-2);
                  else
                      return envfrom;
              }()) {
        assert(ctx != nullptr);
    }

    void Smime::sign() {
        if (!isLoaded())
            return;

        // Null-mailer
        if (mailFrom.empty())
            return;

        auto *client = util::mlfipriv(ctx);
        bool signedOrEncrypted = false;
        std::vector<std::string> contentType;

        contentType.push_back("multipart/signed");
        contentType.push_back("multipart/encrypted");
        contentType.push_back("application/pkcs7-mime");

        if (client->sessionData.count("Content-Type") == 1) {
            std::string value {client->sessionData["Content-Type"]};
            std::size_t found;

            for (int i=0; i<contentType.size(); i++) {
                found = value.find(contentType.at(i));
                if (found != std::string::npos) {
                    signedOrEncrypted = true;
                    break;
                }
            }
        }

        if (signedOrEncrypted) {
            const char logmsg[] = "Message already signed or encrypted";
            syslog(LOG_NOTICE, "%s", logmsg);
            return;
        }

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
            return std::make_unique<std::string>(std::string());

        char line[MAX_BODY_LINE_LENGTH];
        char eol[] = "\r\n";
        std::string dst = std::string();
        bool first_blank_line = false;

        clearerr(fcontent);

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

        if (ferror(fcontent) != 0) {
            perror("Error: Unable to read from temp file");
            return std::make_unique<std::string>(std::string());
        }

        auto body = std::make_unique<std::string>(dst);

        return body;
    }

    // Private

    void Smime::changeHeader(const std::string &headerk,
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