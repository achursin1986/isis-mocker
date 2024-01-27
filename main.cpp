#include <iostream>
#include <memory>
#include <unistd.h>
#include <malloc.h>
#include <algorithm>
#include <boost/program_options.hpp>

#include "parser.hpp"
#include "cli_commands.hpp"
#include "tinyfsm.hpp"
#include "fsm.hpp"
#include "mocker.hpp"
#include "tester.hpp"
#include "parser.hpp"
#include "flooder.hpp"
#include "get_version.h"

#include "cli/boostasioscheduler.h"
#include "cli/boostasioremotecli.h"
#include "cli/cli.h"
#include "cli/clilocalsession.h"
#include "cli/filehistorystorage.h"

namespace cli {
        using MainScheduler = BoostAsioScheduler;
        using CliTelnetServer = BoostAsioCliTelnetServer;
}

using namespace cli;

namespace bpo = boost::program_options;

bool DEBUG_PRINT = false;


int main(int argc, char* argv[]) {
    std::mutex db_mtx;
    std::unordered_map<std::string, std::string> LSDB, LSDB2, TESTDB;
    auxdb AUXDB;
    std::pair<std::string,std::string> mocked_lsp;
    std::unordered_set<std::string> used_ifnames;
    std::unordered_set<int> used_ids;
    std::vector<std::string> ifnames;
    std::string json_file,json_file_raw,json_file_hostname;

    try {
           bpo::options_description desc("options");

                desc.add_options()
                    ("help", "show help")
                    ("ifnames", bpo::value<std::vector<std::string>>(&ifnames)->multitoken()->required(), "interface names, required")
                    ("json-file", bpo::value<std::string>(&json_file)->required(), "json input file, required")
                    ("json-file-raw", bpo::value<std::string>(&json_file_raw)->required(), "json input file, required")
                    ("json-hostname", bpo::value<std::string>(&json_file_hostname)->required(), "json input file, required")
                ;


               bpo::variables_map vm;
               bpo::store(bpo::parse_command_line(argc, argv, desc), vm);

                if (vm.count("help")) {
                        std::cout << desc << std::endl;
                        return 1;
                }


                bpo::notify(vm);


        } catch (const std::exception& e) {
                std::cerr << "Exception: " <<  e.what() << std::endl;
                std::cerr << "Use --help to get options list" << std::endl;
                return 1;
        }

  std::cout << R"(
  ___ ____ ___ ____        __  __  ___   ____ _  _______ ____
 |_ _/ ___|_ _/ ___|      |  \/  |/ _ \ / ___| |/ / ____|  _ \
  | |\___ \| |\___ \ _____| |\/| | | | | |   | ' /|  _| | |_) |
  | | ___) | | ___) |_____| |  | | |_| | |___| . \| |___|  _ <
 |___|____/___|____/      |_|  |_|\___/ \____|_|\_\_____|_| \_\)"
                  << std::endl;


    try {

        parse(LSDB, AUXDB, json_file, json_file_raw, json_file_hostname);
        LSDB2 = LSDB;
        malloc_trim(0);

        /* bringing allocated interfaces up */ 
         for(const auto& k: ifnames) { 
               interface_up(k.c_str()); 
         }       


    } catch (const std::exception& e) {
          std::cerr << "Error while parsing file, exception: " <<  e.what() << std::endl;
          return 1;

    }


    /* init containers and start FSM park */

    std::vector<std::unique_ptr<Mocker>> Mockers;
    std::vector<std::unique_ptr<Flooder>> Flooders;
    std::vector<std::unique_ptr<Tester>> Testers;
    fsm_list::start();


    /* start CLI */
    try {
         
         auto rootMenu = std::make_unique<Menu>("isis-mocker");


         auto showMenu = std::make_unique<Menu>("show", "show commands");
         auto clearMenu = std::make_unique<Menu>("clear", "clear commands");
         auto runMenu = std::make_unique<Menu>("run", "run commands");
         auto loadMenu = std::make_unique<Menu>("load", "load commands");
         auto debugMenu = std::make_unique<Menu>("debug", "debug commands");

         auto showdatabaseMenu = std::make_unique<Menu>("database","show database commands");
         
         showMenu->Insert("interfaces", [&ifnames,&used_ifnames](std::ostream& out) {  show_interfaces(ifnames,used_ifnames, out); }, "show interfaces");
         showMenu->Insert("version", [](std::ostream& out) {  out << version() << std::endl;  }, "show version");
         showMenu->Insert("mockers", [&Mockers](std::ostream& out) {  show_mockers(Mockers,out);  }, "show mockers info");
         showdatabaseMenu->Insert("all",[&AUXDB](std::ostream& out){ show_database(AUXDB,out); }, "show sys-ids");
         showdatabaseMenu->Insert("sysid",{"xxxx.xxxx.xxxx"},[&AUXDB](std::ostream& out, const std::string& sysid){ show_sysid(AUXDB,sysid,out); }, "show sys-id details");
        

         runMenu->Insert("mock",{"xxxx.xxxx.xxxx"},[&LSDB,&db_mtx,&mocked_lsp](std::ostream& out, const std::string& sysid)
                                                                  { mock(LSDB,db_mtx,sysid,mocked_lsp, out);  }, "remove sys-id from lsdb");
         runMenu->Insert("mocker",{"x xxxx.xxxx.xxxx ethx xx.xx.xx.xx xx.xxxx"},[&Mockers,&ifnames,&used_ifnames,&used_ids,&mocked_lsp](std::ostream& out, int id, 
         const std::string& sysid, const std::string& ifname, const std::string& ip, const std::string& area)
                            { mocker_start(id,ifname, sysid,area,ip,Mockers,ifnames,used_ifnames,used_ids, mocked_lsp, out); },"start mocker instance");
          
          runMenu->Insert("flood",{"x"},[&LSDB,&Mockers,&Flooders](std::ostream& out, int id )
                                                                  { flood_start(id,LSDB,Flooders,Mockers,out);  }, "start flood");
          runMenu->Insert("test",{"x(id) x(msec 50 ... 5000)"},[&LSDB,&TESTDB,&Mockers,&Flooders,&Testers](std::ostream& out, int id, int test_interval )
                                                                  { test_start(id,LSDB,TESTDB,Flooders,Mockers,Testers,test_interval,out);  }, "start test");


          loadMenu->Insert("json2",{"filename"},[&TESTDB,&LSDB2,&json_file,&json_file_hostname](std::ostream& out, const std::string& json2) 
                                     { prepare_test(LSDB2,TESTDB, json_file, const_cast<std::string&>(json2),json_file_hostname, out); }, "load json2 raw file");


          debugMenu->Insert("on",[](std::ostream& out) { DEBUG_PRINT = true;  }, "debug on");
          debugMenu->Insert("off",[](std::ostream& out) { DEBUG_PRINT = false;  }, "debug off");
                   

         clearMenu->Insert("stats",[&Mockers](std::ostream& out){ clear_stats(Mockers); }, "clear stats");
         clearMenu->Insert("test",[&Testers](std::ostream& out){  test_clear(Testers); }, "clear test");
         clearMenu->Insert("all",[&Mockers,&Flooders, &Testers,&used_ifnames,&used_ids,&LSDB,&mocked_lsp](std::ostream& out)
                                 { reset_all(Mockers,Flooders,Testers, used_ifnames, used_ids, LSDB, mocked_lsp);  }, "clear all instances");  
         showMenu->Insert(std::move(showdatabaseMenu));
         rootMenu->Insert(std::move(runMenu));
         rootMenu->Insert(std::move(clearMenu));
         rootMenu->Insert(std::move(showMenu));
         rootMenu->Insert(std::move(loadMenu));
         rootMenu->Insert(std::move(debugMenu));

         Cli cli( std::move(rootMenu), std::make_unique<FileHistoryStorage>(".cli") );
         MainScheduler scheduler;
         CliLocalTerminalSession localSession(cli, scheduler, std::cout, 100);
         localSession.ExitAction([&scheduler](auto& out) { scheduler.Stop(); });

         CliTelnetServer server(cli, scheduler, 5000);
         server.ExitAction( [](auto& out) { } );


         scheduler.Run();



    } catch (const std::exception& e) {
          std::cerr << "Exception: " <<  e.what() << std::endl;
          return 1;                 

    }
    catch (...) {
         std::cerr << "Unknown exception" << std::endl;
         return 1;
    }

    return 0;
}
