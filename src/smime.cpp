/*! \file smime.cpp
 *
 * \brief Handle S/MIME messages
 *
 * \author Christian Roessner <c@roessner.co>
 * \version 1606.1.0
 * \date 2016-06-10
  * \copyright Copyright 2016 Christian Roessner <c@roessner.co>
 */

#include "smime.h"

#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <syslog.h>

#include <string>
#include <sstream>
#include <utility>
#include <boost/filesystem.hpp>

#include "common.h"
#include "client.h"
#include "mapfile.h"

namespace fs = boost::filesystem;

namespace smime {
    // Public

    Smime::Smime(SMFICTX *ctx)
            : ctx(ctx),
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
              }()) { /* empty */ }

    void Smime::sign() {
        // Null-mailer or unknown
        if (mailFrom.empty())
            return;

        auto *client = util::mlfipriv(ctx);
        bool signedOrEncrypted = false;
        std::vector<std::string> contentType;

        contentType.push_back("multipart/signed");
        contentType.push_back("multipart/encrypted");
        contentType.push_back("application/pkcs7-mime");

        for (auto &it : client->markedHeaders) {
            if (it.first == "Content-Type") {
                std::size_t found;
                for (std::size_t i=0; i<contentType.size(); i++) {
                    found = it.second.find(contentType.at(i));
                    if (found != std::string::npos) {
                        signedOrEncrypted = true;
                        break;
                    }
                }
                break;
            }
        }

        if (signedOrEncrypted) {
            std::string logmsg = "Message already signed or encrypted for ";
            logmsg += "email address <" + mailFrom + ">";

            syslog(LOG_INFO, "%s", logmsg.c_str());
            return;
        }

        /*
         * TODO:
         * Catch more cases, where an email already could have been encrypted
         * or signed elsewhere.
         */

        mapfile::Map email(mailFrom);

        auto cert = fs::path(email.getSmimeFilename<mapfile::Smime::CERT>());
        auto key = fs::path(email.getSmimeFilename<mapfile::Smime::KEY>());

        if (!fs::exists(cert) && !fs::is_regular(cert))
            return;
        if (!fs::exists(key) && !fs::is_regular(key))
            return;

        /*
         * Signing starts here
         */

        using BIO_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;
        using X509_ptr = std::unique_ptr<X509, decltype(&::X509_free)>;
        using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY,
                                             decltype(&::EVP_PKEY_free)>;
        using PKCS7_ptr = std::unique_ptr<PKCS7, decltype(&::PKCS7_free)>;

        int flags = PKCS7_DETACHED | PKCS7_STREAM;

        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        // S/MIME certificate
        BIO_ptr tbio1(BIO_new_file(cert.string().c_str(), "r"), ::BIO_free);
        if (!tbio1) {
            handleSSLError();
            return;
        }

        X509_ptr scert(PEM_read_bio_X509(tbio1.get(), nullptr, 0, nullptr),
                       ::X509_free);
        if (!scert) {
            handleSSLError();
            return;
        }

        // S/MIME key
        BIO_ptr tbio2(BIO_new_file(key.string().c_str(), "r"), ::BIO_free);
        if (!tbio2) {
            handleSSLError();
            return;
        }

        EVP_PKEY_ptr skey(
                PEM_read_bio_PrivateKey(tbio2.get(), nullptr, 0, nullptr),
                ::EVP_PKEY_free);
        if (!skey) {
            handleSSLError();
            return;
        }

        // Loading mail content from temp file
        BIO_ptr in(BIO_new_file(client->getTempFile().c_str(), "r"),
                   ::BIO_free);
        if (!in) {
            handleSSLError();
            return;
        }

        // Signing
        PKCS7_ptr p7(PKCS7_sign(scert.get(), skey.get(), nullptr, in.get(),
                                flags),
                     ::PKCS7_free);
        if (!p7) {
            handleSSLError();
            return;
        }

        BIO_ptr out(BIO_new(BIO_s_mem()), ::BIO_free);
        if (!out) {
            handleSSLError();
            return;
        }

        // Write out S/MIME message
        if (!SMIME_write_PKCS7(out.get(), p7.get(), in.get(), flags)) {
            handleSSLError();
            return;
        }

        // Remove original headers
        for (auto &it : client->markedHeaders) {
            if (removeHeader(it.first) == MI_FAILURE) {
                std::cerr << "Error: Unable to remove header " << it.first
                           << std::endl;
                client->genericError = true;
                return;
            }
        }

        while (true) {
            char line[max_header_length];
            split_t header;

            if (BIO_gets(out.get(), line, max_header_length) < 0) {
                std::cerr << "Error: Reading header line from BIO"
                          << std::endl;
                handleSSLError();
                return;
            }

            /*
             * Found empty line
             *
             * Normally we would expect CRLF, but the BIO currently only
             * contains a LF at the end of header lines.
             */
            if ((strcmp(line, "\n") == 0) || (strcmp(line, "\r\n")) == 0)
                break;

            // Add PKCS#7 header to message
            split(header, line, is_any_of(":"), token_compress_on);
            if (header.size() != 2) {
                std::cerr << "Error: Broken header line in PKCS#7"
                          << std::endl;
                client->genericError = true;
                return;
            }
            // Remove white space
            trim(header.at(1));
            if (addHeader(header.at(0), header.at(1)) == MI_FAILURE) {
                std::cerr << "Error: Unable to add header " << header.at(0)
                          << std::endl;
                client->genericError = true;
                return;
            }
        }

        // Finally replace the body
        BUF_MEM *outmem = nullptr;
        BIO_get_mem_ptr(out.get(), &outmem);
        if (outmem == nullptr) {
            std::cerr << "Error: Unable to get body from PKCS#7"
                      << std::endl;
            handleSSLError();
            return;
        } else
            (void) BIO_set_close(out.get(), BIO_NOCLOSE);

        if (smfi_replacebody(
                ctx,
                (unsigned char *) (outmem->data),
                (int) outmem->length) != MI_SUCCESS) {
            std::cerr << "Error: Could not replace message body"
                      << std::endl;
            return;
        }

        // Successfully signed an email
        smimeSigned = true;

        // Cleanup
        if (outmem)
            BUF_MEM_free(outmem);
    }

    // Private

    int Smime::addHeader(const std::string &headerk,
                         const std::string &headerv) {
        return smfi_chgheader(ctx,
                              util::ccp(headerk.c_str()),
                              0,
                              util::ccp(headerv.c_str()));
    }

    int Smime::removeHeader(const std::string &headerk) {
        return smfi_chgheader(ctx, util::ccp(headerk.c_str()), 1, nullptr);
    }

    void Smime::handleSSLError() {
        auto *client = util::mlfipriv(ctx);
        u_long e = ERR_get_error();
        char buf[120];
        (void) ERR_error_string(e, buf);

        std::cerr << "Error: Signing data: " << buf << std::endl;
        syslog(LOG_ERR, "%s", buf);

        client->genericError = true;
    }
}  // namespace smime