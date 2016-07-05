/*! @file smime.cpp
 *
 * @brief Handle S/MIME messages
 *
 * @author Christian Roessner <c@roessner.co>
 * @version 1606.1.0
 * @date 2016-06-10
 * @copyright Copyright 2016 Christian Roessner <c@roessner.co>
 */

#include "smime.h"

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

        int flags = PKCS7_DETACHED | PKCS7_STREAM;

        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        /* S/MIME certificate
         *
         * Open a certificate file and create a source BIO for further
         * processing
         */
        BIO_ptr tbio1(BIO_new_file(cert.string().c_str(), "r"), bioDeleter);
        if (!tbio1) {
            handleSSLError();
            return;
        }

        /*
         * Use the tbio1 BIO and read in a PEM formated x509 certificate
         */
        X509_ptr scert(PEM_read_bio_X509(tbio1.get(), nullptr, 0, nullptr),
                       x509Deleter);
        if (!scert) {
            handleSSLError();
            return;
        }

        /* S/MIME key
         *
         * Open another BIO source for the key file
         */
        BIO_ptr tbio2(BIO_new_file(key.string().c_str(), "r"), bioDeleter);
        if (!tbio2) {
            handleSSLError();
            return;
        }

        /*
         * Use the tbio2 BIO and read in a PEM formated key
         */
        EVP_PKEY_ptr skey(
                PEM_read_bio_PrivateKey(tbio2.get(), nullptr, 0, nullptr),
                evpPkeyDeleter);
        if (!skey) {
            handleSSLError();
            return;
        }

        /*
         * Load intermediate certificates if available
         */
        if (::debug)
            std::cout << "-> loadIntermediate()" << std::endl;
        STACK_OF_X509_ptr chain(loadIntermediate(cert.string()));
        if (::debug)
            std::cout << "<- loadIntermediate()" << std::endl;

        /*
         * Create a source BIO with the mail content stored earlier in a
         * temporary file
         */
        BIO_ptr in(BIO_new_file(client->getTempFile().c_str(), "r"),
                   bioDeleter);
        if (!in) {
            handleSSLError();
            return;
        }

        /*
         * Use all the source BIOs and generate a signed PKCS#7 data structure
         */
        PKCS7_ptr p7(PKCS7_sign(scert.get(), skey.get(), chain.get(), in.get(),
                                flags),
                     pkcs7Deleter);
        if (!p7) {
            handleSSLError();
            return;
        }

        /*
         * Create a new memory BIO sink
         */
        BIO_ptr out(BIO_new(BIO_s_mem()), bioDeleter);
        if (!out) {
            handleSSLError();
            return;
        }

        /*
         * Adds the appropriate MIME headers to a PKCS#7 structure to produce
         * an S/MIME message. The result is placed in the BIO sink 'out'
         */
        if (!SMIME_write_PKCS7(out.get(), p7.get(), in.get(), flags)) {
            handleSSLError();
            return;
        }

        /*
         * Remove original headers
         */
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

        /*
         * Set the BIO sink to a character array 'outmem'. Close the sink
         * afterwards. The result is now stored in the character array
         */
        BUF_MEM *outmem = nullptr;
        BIO_get_mem_ptr(out.get(), &outmem);
        if (outmem == nullptr) {
            std::cerr << "Error: Unable to get body from PKCS#7"
                      << std::endl;
            handleSSLError();
            return;
        } else
            (void) BIO_set_close(out.get(), BIO_NOCLOSE);

        // Finally replace the body
        if (smfi_replacebody(
                ctx,
                (unsigned char *) (outmem->data),
                (int) outmem->length) == MI_FAILURE) {
            std::cerr << "Error: Could not replace message body"
                      << std::endl;
            client->genericError = true;
        } else {
            // Successfully signed an email
            smimeSigned = true;
        }

        // Cleanup
        if (outmem) {
            BUF_MEM_free(outmem);
            if (::debug)
                std::cout << "\tBUF_MEM_free() called" << std::endl;
        }
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

    void Smime::handleSSLError(void) {
        auto *client = util::mlfipriv(ctx);
        u_long e = ERR_get_error();
        char buf[120];
        (void) ERR_error_string(e, buf);

        std::cerr << "Error: Signing data: " << buf << std::endl;
        syslog(LOG_ERR, "%s", buf);

        client->genericError = true;
    }

    STACK_OF_X509_ptr Smime::loadIntermediate(const std::string &file) {
        int num;
        int numCerts;

        // Dummy return statement aka nullptr
        STACK_OF_X509_ptr empty(nullptr, stackOfX509Deleter);

        /*
         * Create a BIO source for the chain file
         */
        BIO_ptr bio(BIO_new_file(file.c_str(), "r"), bioDeleter);
        if (!bio) {
            handleSSLError();
            if (::debug)
                std::cout << "\t!bio" << std::endl;
            return empty;
        }

        /*
         * Load the certificates from the source BIO 'bio' onto the stack
         */
        STACK_OF_X509_INFO_ptr stackInfo(PEM_X509_INFO_read_bio(
                bio.get(), nullptr, nullptr, nullptr), stackOfX509InfoDeleter);
        if (!stackInfo) {
            handleSSLError();
            if (::debug)
                std::cout << "\t!stackInfo" << std::endl;
            return empty;
        }

        /*
         * Count the number of certificates that are on the stack
         */
        num = sk_X509_INFO_num(stackInfo.get());
        if(num < 0) {
            if (::debug)
                std::cout << "\tnum<0" << std::endl;
            return empty;
        }

        /*
         * Create empty stack of x509 certificates
         */
        STACK_OF_X509_ptr stack(sk_X509_new_null(), stackOfX509Deleter);
        if (!stack) {
            handleSSLError();
            if (::debug)
                std::cout << "\t!stack" << std::endl;
            return empty;
        }

        /*
         * Load each certificate from the info stack onto our x509 stack. We
         * skip the first certificate, because we only want intermediate
         * certificates and we must prevent the PKCS#7 call from loading a
         * duplicate S/MIME certificate, as this leads to a segmentation
         * fault. We expect a correct sorted certificate order!
         */
        bool first_cert_in_file = true;
        while (sk_X509_INFO_num(stackInfo.get())) {
            X509_INFO_ptr xi(sk_X509_INFO_shift(stackInfo.get()),
                             x509InfoDeleter);
            if (first_cert_in_file) {
                first_cert_in_file = false;
                continue;  // Never load the main certificate onto the stack!
            }
            if (xi->x509 != nullptr) {
                sk_X509_push(stack.get(), xi->x509);
                xi->x509 = nullptr;
            }
        }

        /*
         * Only return the stack, if there were any certificates in the chain.
         * Otherwise use our empty stack dummy
         */
        numCerts = sk_X509_num(stack.get());
        if(numCerts == 0) {
            if (::debug)
                std::cout << "\tstack empty" << std::endl;
            stack = std::move(empty);
        }

        return stack;
    }

    // Wrapper functions

    void bioDeleter(BIO *ptr) {
        if (ptr != nullptr) {
            BIO_free(ptr);
            if (::debug)
                std::cout << "\tBIO_free() called" << std::endl;
        }
    }

    void x509Deleter(X509 *ptr) {
        if (ptr != nullptr) {
            X509_free(ptr);
            if (::debug)
                std::cout << "\tX509_free() called" << std::endl;
        }
    }

    void x509InfoDeleter(X509_INFO *ptr) {
        if (ptr != nullptr) {
            X509_INFO_free(ptr);
            if (::debug)
                std::cout << "\tX509_INFO_free() called" << std::endl;
        }
    }

    void evpPkeyDeleter(EVP_PKEY *ptr) {
        if (ptr != nullptr) {
            EVP_PKEY_free(ptr);
            if (::debug)
                std::cout << "\tEVP_PKEY_free() called" << std::endl;
        }
    }

    void pkcs7Deleter(PKCS7 *ptr) {
        if (ptr != nullptr) {
            PKCS7_free(ptr);
            if (::debug)
                std::cout << "\tPKCS7_free() called" << std::endl;
        }
    }

    void stackOfX509Deleter(STACK_OF(X509) *ptr) {
        if (ptr != nullptr) {
            sk_X509_free(ptr);
            if (::debug)
                std::cout << "\tsk_X509_free() called" << std::endl;
        }
    }

    void stackOfX509InfoDeleter(STACK_OF(X509_INFO) *ptr) {
        if (ptr != nullptr) {
            sk_X509_INFO_free(ptr);
            if (::debug)
                std::cout << "\tsk_X509_INFO_free() called" << std::endl;
        }
    }
}  // namespace smime