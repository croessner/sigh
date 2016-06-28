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

    Smime::Smime(SMFICTX *ctx)
            : ctx(ctx),
              loaded(true),
              smimeSigned(false),
              mailFrom([&]() {
                  auto *client = util::mlfipriv(ctx);
                  if (client->sessionData.count("envfrom") == 1) {
                      std::string envfrom = client->sessionData["envfrom"];
                      if (envfrom.front() == '<' && envfrom.back() == '>')
                          return envfrom.substr(1, envfrom.size() - 2);
                      else
                          return envfrom;
                  }
                  else
                      return std::string();
              }()) { /* empty */ };

    void Smime::sign() {
        if (!isLoaded())
            return;

        // Null-mailer or unknown
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

        /*
         * Signing starts here
         *
         * This code block is based on an example from openssl/demos/smime
         */

        BIO *in = nullptr, *out = nullptr, *tbio = nullptr;
        X509 *scert = nullptr;
        EVP_PKEY *skey = nullptr;
        PKCS7 *p7 = nullptr;
        bool done = false;

        int flags = PKCS7_DETACHED | PKCS7_STREAM;

        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        // S/MIME certificate
        tbio = BIO_new_file(cert.string().c_str(), "r");

        if (!tbio)
            goto end;

        scert = PEM_read_bio_X509(tbio, nullptr, 0, nullptr);

        // S/MIME key
        tbio = BIO_new_file(key.string().c_str(), "r");

        if (!tbio)
            goto end;

        skey = PEM_read_bio_PrivateKey(tbio, nullptr, 0, nullptr);

        if (!scert || !skey)
            goto end;

        // Loading mail content from temp file
        in = BIO_new_file(client->getTempFile().c_str(), "r");

        if (!in)
            goto end;

        // Signing
        p7 = PKCS7_sign(scert, skey, nullptr, in, flags);

        if (!p7)
            goto end;

        // Successfully signed an email
        smimeSigned = done = true;

        end:

        if (!done) {
            std::cerr << "Error: Signing data" << std::endl;
            u_long e = ERR_get_error();
            char buf[120];
            (void) ERR_error_string(e, buf);
            std::cerr << buf << std::endl;
            syslog(LOG_ERR, "%s", buf);
        }

        // Cleanup
        if (p7)
            PKCS7_free(p7);
        if (scert)
            X509_free(scert);
        if (skey)
            EVP_PKEY_free(skey);

        if (in)
            BIO_free(in);
        if (out)
            BIO_free(out);
        if (tbio)
            BIO_free(tbio);
    }

    const std::unique_ptr<std::string> Smime::bodyAsString() const {
        if (!isLoaded() || !smimeSigned)
            return std::make_unique<std::string>(std::string());

        auto *client = util::mlfipriv(ctx);
        char line[MAX_BODY_LINE_LENGTH];
        char eol[] = "\r\n";
        std::string dst = std::string();
        bool first_blank_line = false;

        if (client->getFcontentStatus()) {
            if (fseek(client->fcontent, 0L, SEEK_SET) == -1) {
                perror("Error: Unwilling to rewind temp file");
                return std::make_unique<std::string>(std::string());
            }

            clearerr(client->fcontent);

            while (fgets(line, sizeof(line), client->fcontent)) {
                if (!first_blank_line) {
                    if (strncmp(line, eol, 1) == 0) {
                        first_blank_line = true;
                        continue;
                    } else
                        continue;
                }
                dst += std::string(line);
            }

            if (ferror(client->fcontent) != 0) {
                perror("Error: Unable to read from temp file");
                return std::make_unique<std::string>(std::string());
            }
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