/*! \file smime.h
 *
 * \brief Handle S/MIME messages
 *
 * \author Christian Roessner <c@roessner.co>
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
    typedef std::vector<std::pair<char *, char*>> markedHeaders_t;

    /*!
     * \brief S/MIME handling
     *
     * This class creates a S/MIME signed mail if possible and directly talks
     * to the milter to add, modify headers and finally replace the body.
     */
    class Smime {
    public:
        /*!
         * \brief Constructor
         */
        Smime(SMFICTX *);

        /*!
         * \brief Destructor
         */
        ~Smime(void) = default;

        inline bool isSmimeSigned(void) const { return smimeSigned; }

        /*!
         * \brief Sign a mail
         */
        void sign(void);

    private:
        /*!
         * \brief Add headers that were generated in sign()
         *
         * When a message was signed, new headers need to be added to the
         * message.
         */
        int addHeader(const std::string &, const std::string &);

        /*!
         * \brief Remove headers from original mail
         *
         * When signing, new headers are generated and existing ones are
         * embedded inside the new message body.
         */
        int removeHeader(const std::string &);

        /*!
         * \brief The current client context that was created on connect
         *
         * This class works directly on the original message.
         */
        SMFICTX *ctx;

        /*!
         * \brief Flag that indicates, if signing was possible
         *
         * If a certificate and key was provided and signing was successful,
         * this flag is used in mlfi_eom to evaluate a reply message.
         */
        bool smimeSigned;

        /*!
         * \brief A normalized version of the MAIL FROM address
         *
         * We strip away '<' and '>' to easily lookup required information in
         * our cert store, which is provided by the map class.
         */
        std::string mailFrom;
    };
}  // namespace smime

#endif  // SRC_SMIME_H_
