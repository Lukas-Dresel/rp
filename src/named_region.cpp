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
#include "named_region.hpp"
#include "toolbox.hpp"
#include "rpexception.hpp"
#include "safeint.hpp"

#include <cstring>

NamedRegion::NamedRegion(const char *name, const unsigned long long offset, const unsigned long long vaddr, const unsigned long long size)
: m_name(name), m_offset(offset), m_size(size), m_named_region(NULL), m_vaddr(vaddr)
{
}

NamedRegion::~NamedRegion(void)
{
    if(m_named_region != NULL)
        delete [] m_named_region;
}

std::string NamedRegion::get_name(void) const
{
    return m_name;
}

unsigned long long NamedRegion::get_size(void) const
{
    return m_size;
}

unsigned char* NamedRegion::get_named_region_buffer(void) const
{
    return m_named_region;
}

unsigned long long NamedRegion::get_offset(void) const
{
    return m_offset;
}

void NamedRegion::dump(std::ifstream &file)
{
    /* NB: std::streampos performs unsigned check */
    unsigned long long fsize = get_file_size(file);
    if(SafeAddU64(m_offset, m_size) > fsize)
        RAISE_EXCEPTION("Your file seems to be fucked up");

    std::streampos backup = file.tellg();

    file.seekg((unsigned int)m_offset, std::ios::beg);
    m_named_region = new (std::nothrow) unsigned char[(unsigned int)m_size];
    if(m_named_region == NULL)
        RAISE_EXCEPTION("Cannote allocate memory to load the contents of the named region.");

    file.read((char*)m_named_region, (unsigned int)m_size);

    file.seekg(backup);
}

unsigned long long NamedRegion::get_vaddr(void) const
{
    return m_vaddr;
}
