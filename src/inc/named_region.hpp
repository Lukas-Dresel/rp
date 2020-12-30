/*
    This file is part of rp++.

    Copyright (C) 2013, Axel "0vercl0k" Souchet <0vercl0k at tuxfamily.org>
    All rights reserved.

    rp++ is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    rp++ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with rp++.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef NAMED_REGION_HPP
#define NAMED_REGION_HPP

#include <string>
#include <list>
#include <fstream>

/*! \class NamedRegion
 *
 *   Binaries can have named regions contained within, e.g. ELF file sections (see .text, .data, .rodata, etc.).
 */
class NamedRegion
{
    public:

        /*!
         *  \brief The constructor will make a copy of the memory in its own buffer
         *   
         *  \param name: The name of the region
         *  \param offset: The file offset of the region's contents
         *  \param vaddr: Virtual address of the region
         *  \param size: The size of the region
         */
        explicit NamedRegion(const char *name, const unsigned long long offset, const unsigned long long vaddr, const unsigned long long size);
        
        ~NamedRegion(void);
        
        /*!
         *  \brief Get the name of the named region
         *   
         *  \return the name of the named region
         */
        std::string get_name(void) const;

        /*!
         *  \brief Get the size of the named region
         *   
         *  \return the size of the named region
         */
        unsigned long long get_size(void) const;

        /*!
         *  \brief Get the content of the named region (it's the internal copy)
         *   
         *  \return a pointer on the buffer
         */
        unsigned char *get_named_region_buffer(void) const;

        /*!
         *  \brief Get the (raw) offset of the named region ; in other word, where it was found in the binary
         *   
         *  \return the offset where the named region was found in the binary
         */
        unsigned long long get_offset(void) const;

        /*!
         *  \brief Dump the raw named region of your file
         *   
         *  \param file: The file
         */
        void dump(std::ifstream &file);

        unsigned long long get_vaddr(void) const;

    private:

        std::string m_name; /*!< the name of the named region*/
        
        const unsigned long long m_offset; /*!< the raw offset of the named region */
        
        const unsigned long long m_size; /*!< the size of the named region of the named region */
        
        unsigned char *m_named_region; /*!< the pointer on the named region content */

        unsigned long long m_vaddr; /* !< the virtual address of the named region */
};

#endif
