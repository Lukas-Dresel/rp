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
#include "program.hpp"

#include <iostream>
#include <map>
#include <sstream>
#include <algorithm>
#include <assert.h>

#include "executable_format.hpp"
#include "raw.hpp"
#include "x86.hpp"
#include "x64.hpp"
#include "section.hpp"
#include "named_region.hpp"

#include "coloshell.hpp"
#include "rpexception.hpp"
#include "toolbox.hpp"

Program::Program(const std::string & program_path, CPU::E_CPU arch)
: m_cpu(NULL), m_exformat(NULL)
{
    unsigned int magic_dword = 0;

    std::cout << "Trying to open '" << program_path << "'.." << std::endl;
    m_file.open(program_path.c_str(), std::ios::binary);
    if(m_file.is_open() == false)
        RAISE_EXCEPTION("Cannot open the file");

    /* If we know the CPU in the constructor, it is a raw file */
    if(arch != CPU::CPU_UNKNOWN)
    {
        m_exformat = new (std::nothrow) Raw();
        if(m_exformat == NULL)
            RAISE_EXCEPTION("Cannot allocate raw");
        
        switch(arch)
        {
            case CPU::CPU_x86:
                m_cpu = new (std::nothrow) x86();
                break;

            case CPU::CPU_x64:
                m_cpu = new (std::nothrow) x64();
                break;

            default:
                RAISE_EXCEPTION("Don't know your architecture");
        }

        if(m_cpu == NULL)
            RAISE_EXCEPTION("Cannot allocate m_cpu");
 
    }
    /* This isn't a raw file, we have to determine the executable format and the cpu */
    else
    {
        m_file.read((char*)&magic_dword, sizeof(magic_dword));

        m_exformat = ExecutableFormat::GetExecutableFormat(magic_dword);
        if(m_exformat == NULL)
            RAISE_EXCEPTION("GetExecutableFormat fails");

        m_cpu = m_exformat->get_cpu(m_file);
        if(m_cpu == NULL)
            RAISE_EXCEPTION("get_cpu fails");
    }


    std::cout << "FileFormat: " << m_exformat->get_class_name() << ", Arch: " << m_cpu->get_class_name() << std::endl;
}

Program::~Program(void)
{
    if(m_file.is_open())
        m_file.close();
    
    if(m_exformat != NULL)
        delete m_exformat;

    if(m_cpu != NULL)
        delete m_cpu;
}

void Program::display_information(VerbosityLevel lvl)
{
    m_exformat->display_information(lvl);
}

std::multiset<Gadget*, Gadget::Sort> Program::find_gadgets(unsigned int depth, unsigned int engine_display_option)
{
    std::multiset<Gadget*, Gadget::Sort> gadgets_found;

    /* To do a ROP gadget research, we need to know the executable section */
    std::vector<Section*> executable_sections = m_exformat->get_executables_section(m_file);
    if(executable_sections.size() == 0)
        std::cout << "It seems your binary haven't executable sections." << std::endl;

    /* Walk the executable sections */
    for(std::vector<Section*>::iterator it_sec = executable_sections.begin(); it_sec != executable_sections.end(); ++it_sec)
    {
        std::cout << "in " << (*it_sec)->get_name() << std::endl;
        unsigned long long va_section = (*it_sec)->get_vaddr();

        /* Let the cpu research */
        std::multiset<Gadget*> gadgets = m_cpu->find_gadget_in_memory(
            (*it_sec)->get_section_buffer(),
            (*it_sec)->get_size(),
            va_section,
            depth,
            engine_display_option
        );

        std::cout << gadgets.size() << " found." << std::endl << std::endl;

        /* 
            XXX: 
                If at&t syntax is enabled, BeaEngine doesn't seem to handle the prefix:
                \xf0\x00\x00 => addb %al, (%eax) ; -- and in intel -- lock add byte [eax], al ; ret  ;

                It will introduce differences between the number of unique gadgets found!
        */

        /* Mergin'! */
        for(std::multiset<Gadget*>::iterator it_g = gadgets.begin(); it_g != gadgets.end(); ++it_g)
            gadgets_found.insert(*it_g);
    }

    return gadgets_found;
}

std::multiset<Gadget*, Gadget::Sort> Program::find_fgkaslr_compatible_gadgets(unsigned int depth, unsigned int engine_display_option)
{
    std::multiset<Gadget*, Gadget::Sort> gadgets_found;

    /* To do a ROP gadget research, we need to know the executable section */
    std::vector<Section*> executable_sections = m_exformat->get_executables_section(m_file);
    if(executable_sections.size() == 0)
        std::cout << "It seems your binary haven't executable sections." << std::endl;

    std::vector<NamedRegion*> named_regions = m_exformat->get_named_regions(m_file);
    if (named_regions.size() == 0)
    {
        std::cout << "No named regions => filtering for FGKASLR is not possible. Either implement named regions for"
            " your file format or disable FGKASLR filtering." << std::endl;
        return gadgets_found;
    }

    std::map<unsigned long long, bool> address_is_blocked;
    for (auto nr : named_regions)
    {
        // std::cout << "Found named region " << nr->get_name() << " @ " << std::hex << nr->get_vaddr() << " of size " << nr->get_size() << std::endl;
        if (nr->get_name().substr(0, 6) == ".text.") // not a -ffunction-sections section
        {
            auto base = nr->get_vaddr();
            for (size_t i = 0; i < nr->get_size(); i++)
            {
                address_is_blocked[base + i] = true;
            }
        }
    }

    /* Walk the executable sections */
    for(std::vector<Section*>::iterator it_sec = executable_sections.begin(); it_sec != executable_sections.end(); ++it_sec)
    {
        std::cout << "in " << (*it_sec)->get_name() << std::endl;
        unsigned long long va_section = (*it_sec)->get_vaddr();

        /* Let the cpu research */
        std::multiset<Gadget*> gadgets = m_cpu->find_gadget_in_memory(
            (*it_sec)->get_section_buffer(),
            (*it_sec)->get_size(),
            va_section,
            depth,
            engine_display_option
        );

        std::cout << gadgets.size() << " found." << std::endl << std::endl;

        /*
            XXX:
                If at&t syntax is enabled, BeaEngine doesn't seem to handle the prefix:
                \xf0\x00\x00 => addb %al, (%eax) ; -- and in intel -- lock add byte [eax], al ; ret  ;

                It will introduce differences between the number of unique gadgets found!
        */

        /* Mergin'! */
        for(std::multiset<Gadget*>::iterator it_g = gadgets.begin(); it_g != gadgets.end(); ++it_g)
        {
            Gadget* g = *it_g;
            size_t num_ocurrences = g->m_offsets.size();
            assert(num_ocurrences == g->m_va_sections.size());

            std::vector<size_t> invalid_gadget_indices;
            for (size_t i = 0; i < num_ocurrences; i++)
            {
                auto gadget_addr = g->m_va_sections[i] + g->m_offsets[i];
                if (address_is_blocked[gadget_addr])
                {
                    // std::cout << "IGNORING gadget @ " << std::hex << gadget_addr << "!!" << std::endl;
                    invalid_gadget_indices.push_back(i);
                }
            }
            std::for_each(invalid_gadget_indices.crbegin(), invalid_gadget_indices.crend(), [&g] (auto index) {
                g->m_offsets.erase(begin(g->m_offsets) + index);
                g->m_va_sections.erase(begin(g->m_va_sections) + index);
            });
            if (g->m_offsets.size() > 0)
            {
                gadgets_found.insert(g);
            }
        }
    }

    return gadgets_found;
}

void Program::search_and_display(const unsigned char* hex_values, unsigned int size)
{
    std::vector<Section*> executable_sections = m_exformat->get_executables_section(m_file);
    if(executable_sections.size() == 0)
        std::cout << "It seems your binary haven't executable sections." << std::endl;

    for(std::vector<Section*>::iterator it = executable_sections.begin(); it != executable_sections.end(); ++it)
    {
        std::list<unsigned long long> ret = (*it)->search_in_memory(hex_values, size);
        for(std::list<unsigned long long>::iterator it2 = ret.begin(); it2 != ret.end(); ++it2)
        {
            unsigned long long va_section = (*it)->get_vaddr();
            unsigned long long va = va_section + *it2;
            
            display_offset_lf(va, hex_values, size); 
        }
    }
}
