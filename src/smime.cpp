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

#include "common.h"
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
        bool noerror = true;

        int flags = PKCS7_DETACHED | PKCS7_STREAM;

        // Header iterator for marked headers
        std::vector<char *>::iterator hit;

        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        // S/MIME certificate
        tbio = BIO_new_file(cert.string().c_str(), "r");
        if (!tbio)
            noerror = false;

        if (noerror) {
            scert = PEM_read_bio_X509(tbio, nullptr, 0, nullptr);
            if (!scert)
                noerror = false;
        }

        // S/MIME key
        if (noerror) {
            tbio = BIO_new_file(key.string().c_str(), "r");
            if (!tbio)
                noerror = false;
        }

        if (noerror) {
            skey = PEM_read_bio_PrivateKey(tbio, nullptr, 0, nullptr);
            if (!skey)
                noerror = false;
        }

        // Loading mail content from temp file
        if (noerror) {
            in = BIO_new_file(client->getTempFile().c_str(), "r");
            if (!in)
                noerror = false;
        }

        // Signing
        if (noerror) {
            p7 = PKCS7_sign(scert, skey, nullptr, in, flags);
            if (!p7)
                noerror = false;
        }

        if (noerror) {
            out = BIO_new(BIO_s_mem());
            if (!out)
                noerror = false;
        }

        // Write out S/MIME message
        if (noerror) {
            if (!SMIME_write_PKCS7(out, p7, in, flags))
                noerror = false;
        }

        // Remove original headers
        if (noerror) {
            for (hit = client->markedHeaders.begin();
                 hit != client->markedHeaders.end();
                 hit++) {
                if (removeHeader(*hit) == MI_FAILURE) {
                    std::cerr << "Error: Unable to remove header " << *hit
                               << std::endl;
                    noerror = false;
                }
            }
        }

        if (noerror) {
            // Successfully signed an email
            smimeSigned = true;
        } else {
            std::cerr << "Error: Signing data" << std::endl;
            u_long e = ERR_get_error();
            char buf[120];
            (void) ERR_error_string(e, buf);
            std::cerr << buf << std::endl;
            syslog(LOG_ERR, "%s", buf);
            client->genericError = true;
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

    int Smime::addHeader(const std::string &headerk,
                         const std::string &headerv) {
        int result = smfi_chgheader(ctx,
                                    util::ccp(headerk.c_str()),
                                    1,
                                    util::ccp(headerv.c_str()));

        return result;
    }

    int Smime::removeHeader(const std::string &headerk) {
        int result = smfi_chgheader(ctx,
                                    util::ccp(headerk.c_str()),
                                    1,
                                    nullptr);

        return result;
    }
}  // namespace smime