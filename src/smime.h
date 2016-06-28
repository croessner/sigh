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

#include <string>
#include <iostream>
#include <fstream>
#include <memory>
#include <libmilter/mfapi.h>

#define MAX_BODY_LINE_LENGTH    80

namespace smime {
    class Smime {
    public:
        friend std::ostream & operator<<(std::ostream &, const Smime &);

        Smime(SMFICTX *);

        ~Smime(void) = default;

        inline bool isLoaded(void) const { return loaded; }

        inline bool isSmimeSigned(void) const { return smimeSigned; }

        const std::unique_ptr<std::string> bodyAsString() const;

        void sign(void);

    private:
        void changeHeader(const std::string &, const std::string &);

        SMFICTX *ctx;

        bool loaded;

        bool smimeSigned;

        std::string mailFrom;
    };
}  // namespace smime

#endif  // SRC_SMIME_H_
