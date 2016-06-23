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
#include <mimetic/mimetic.h>
#include <libmilter/mfapi.h>

namespace smime {
    class Smime {
    public:
        friend std::ostream & operator<<(std::ostream &, const Smime &);

        Smime(std::ifstream &, const std::string &);

        ~Smime(void) = default;

        inline bool isLoaded(void) const { return loaded; }

        inline bool isSmimeSigned(void) const { return smimesigned; }

        const std::unique_ptr<std::string> toString(
                const std::shared_ptr<mimetic::MimeEntity>) const;

        void sign(void);

    private:
        void changeHeader(SMFICTX *, const std::string &, const std::string &);

        std::shared_ptr<mimetic::MimeEntity> me;

        bool loaded;

        bool smimesigned;

        std::string mailfrom;
    };
}  // namespace smime

#endif  // SRC_SMIME_H_
