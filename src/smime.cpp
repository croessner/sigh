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
        BUF_MEM *outmem = nullptr;

        // If an error occurs, we directly abort further processing
        bool noerror = true;

        // This flag indicates, if we can grab error messages provided by
        // OpenSSL and lg these to syslog
        bool cryptoerror = false;

        int flags = PKCS7_DETACHED | PKCS7_STREAM;

        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        // S/MIME certificate
        tbio = BIO_new_file(cert.string().c_str(), "r");
        if (!tbio) {
            noerror = false;
            cryptoerror = true;
        }

        if (noerror) {
            scert = PEM_read_bio_X509(tbio, nullptr, 0, nullptr);
            if (!scert) {
                noerror = false;
                cryptoerror = true;
            }
        }

        // S/MIME key
        if (noerror) {
            tbio = BIO_new_file(key.string().c_str(), "r");
            if (!tbio) {
                noerror = false;
                cryptoerror = true;
            }
        }

        if (noerror) {
            skey = PEM_read_bio_PrivateKey(tbio, nullptr, 0, nullptr);
            if (!skey) {
                noerror = false;
                cryptoerror = true;
            }
        }

        // Loading mail content from temp file
        if (noerror) {
            in = BIO_new_file(client->getTempFile().c_str(), "r");
            if (!in) {
                noerror = false;
                cryptoerror = true;
            }
        }

        // Signing
        if (noerror) {
            p7 = PKCS7_sign(scert, skey, nullptr, in, flags);
            if (!p7) {
                noerror = false;
                cryptoerror = true;
            }
        }

        if (noerror) {
            out = BIO_new(BIO_s_mem());
            if (!out) {
                noerror = false;
                cryptoerror = true;
            }
        }

        // Write out S/MIME message
        if (noerror) {
            if (!SMIME_write_PKCS7(out, p7, in, flags)) {
                noerror = false;
                cryptoerror = true;
            }
        }

        // Remove original headers
        if (noerror) {
            for (auto &it : client->markedHeaders) {
                if (removeHeader(it.first) == MI_FAILURE) {
                    std::cerr << "Error: Unable to remove header " << it.first
                               << std::endl;
                    noerror = false;
                }
            }
        }

        if (noerror) {
            while (true) {
                char line[max_header_length];
                split_t header;

                if (BIO_gets(out, line, max_header_length) < 0) {
                    std::cerr << "Error: Reading header line from BIO"
                              << std::endl;
                    noerror = false;
                    cryptoerror = true;
                    break;
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
                    noerror = false;
                    break;
                }
                // Remove white space
                trim(header.at(1));
                if (addHeader(header.at(0), header.at(1)) == MI_FAILURE) {
                    std::cerr << "Error: Unable to add header " << header.at(0)
                              << std::endl;
                    noerror = false;
                    break;
                }
            }
        }

        // Finally replace the body
        if (noerror) {
            BIO_get_mem_ptr(out, &outmem);
            if (outmem == nullptr) {
                std::cerr << "Error: Unable to get body from PKCS#7"
                          << std::endl;
                noerror = false;
                cryptoerror = true;
            } else
                (void) BIO_set_close(out, BIO_NOCLOSE);
        }

        if (noerror) {
            if (smfi_replacebody(
                    ctx,
                    (unsigned char *) (outmem->data),
                    (int) outmem->length) != MI_SUCCESS) {
                std::cerr << "Error: Could not replace message body"
                          << std::endl;
                noerror = false;
            }
        }

        if (noerror) {
            // Successfully signed an email
            smimeSigned = true;
        }

        if (cryptoerror) {
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

        if (outmem)
            BUF_MEM_free(outmem);
    }

    // Private

    int Smime::addHeader(const std::string &headerk,
                         const std::string &headerv) {
        int result = smfi_chgheader(ctx,
                                    util::ccp(headerk.c_str()),
                                    0,
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