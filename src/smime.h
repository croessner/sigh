/*! \file smime.h
 *
 * \brief Handle S/MIME messages
 *
 * \author Christian Rößner <c@roessner.co>
 * \version 1606.1.0
 * \date 2016-06-10
  * \copyright Copyright 2016 Christian Roessner <c@roessner.co>
 */

#ifndef MYMILTER_SMIME_H
#define MYMILTER_SMIME_H

#include <string>
#include <iostream>
#include <fstream>
#include <mimetic/mimetic.h>
#include <libmilter/mfapi.h>

namespace smime {
    class Smime {
    public:
        friend std::ostream & operator<<(std::ostream &, const Smime &);

        Smime(void);

        Smime(std::ifstream &, const std::string &);

        ~Smime(void) = default;

        inline bool isLoaded(void) const { return loaded; }

        void loadMimeEntity(std::ifstream &, const std::string &);

        const std::unique_ptr<std::string> toString(
                const std::shared_ptr<mimetic::MimeEntity>) const;

        void sign(void);

    private:
        void changeHeader(SMFICTX *, const std::string &, const std::string &);

        std::shared_ptr<mimetic::MimeEntity> me;

        bool loaded;

        std::string mailfrom;
    };
}  // namespace smime

#endif //MYMILTER_SMIME_H
