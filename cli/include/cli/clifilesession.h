/*******************************************************************************
 * CLI - A simple command line interface.
 * Copyright (C) 2016-2021 Daniele Pallastrelli
 *
 * Boost Software License - Version 1.0 - August 17th, 2003
 *
 * Permission is hereby granted, free of charge, to any person or organization
 * obtaining a copy of the software and accompanying documentation covered by
 * this license (the "Software") to use, reproduce, display, distribute,
 * execute, and transmit the Software, and to prepare derivative works of the
 * Software, and to permit third-parties to whom the Software is furnished to
 * do so, all subject to the following:
 *
 * The copyright notices in the Software and this entire statement, including
 * the above license grant, this restriction and the following disclaimer,
 * must be included in all copies of the Software, in whole or in part, and
 * all derivative works of the Software, unless such copies or derivative
 * works are solely in the form of machine-executable object code generated by
 * a source language processor.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
 * SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
 * FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 ******************************************************************************/

#ifndef CLI_CLIFILESESSION_H
#define CLI_CLIFILESESSION_H

#include <string>
#include <iostream>
#include <stdexcept> // std::invalid_argument
#include "cli.h" // CliSession

namespace cli
{

class CliFileSession : public CliSession
{
public:
    /// @throw std::invalid_argument if @c _in or @c out are invalid streams
    explicit CliFileSession(Cli& _cli, std::istream& _in=std::cin, std::ostream& _out=std::cout) :
        CliSession(_cli, _out, 1),
        exit(false),
        in(_in)
    {
        if (!_in.good()) throw std::invalid_argument("istream invalid");
        if (!_out.good()) throw std::invalid_argument("ostream invalid");
        ExitAction(
            [this](std::ostream&)
            {
                exit = true;
            }
        );
    }
    void Start()
    {
        Enter();

        while(!exit)
        {
            Prompt();
            std::string line;
            if (!in.good())
                Exit();
            std::getline(in, line);
            if (in.eof())
                Exit();
            else
                Feed(line);
        }
    }

private:
    bool exit;
    std::istream& in;
};

} // namespace cli

#endif // CLI_CLIFILESESSION_H

