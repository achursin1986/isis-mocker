#pragma once
#include "parser.hpp"
#include "mocker.hpp"
#include "flooder.hpp"
#include "fsm.hpp"
#include <algorithm>
#include <mutex>
#include <stdio.h>


void show_database (auxdb& db) {
           int paginator{}; std::string in= "";
           std::cout << "       sysid         hostname" << std::endl;
           for ( auto i=db.begin(); i != db.end(); i++ ) {
               if ( (*i).second.get()->NEIGHBORS_.size() ) { 
                   std::cout << "      " << (*i).first << " " << (*i).second.get()->HOSTNAME_ << std::endl;
                    ++paginator;
                   if ( paginator > 25 ) { 
                         paginator = 0;
                         std::cout << "<<press Enter for more>>" << std::endl;
                         fgetc(stdin);
                         std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); 
                   }
                }
            }
}


void show_sysid (auxdb& db, std::string sysid) {
           int paginator{}; std::string in= "";
           if (db.find(sysid) == db.end()) { 
                std::cout << "Incorrect id or not found" << std::endl;
                return;
           }

           if ( db[sysid].get()->NEIGHBORS_.size() ) {
           std::cout << db[sysid].get()->HOSTNAME_ << std::endl;
           std::cout << "area: " << std::endl;
           std::cout << db[sysid].get()->AREA_ << std::endl;
           if ( db[sysid].get()->NEIGHBORS_.size() ) std::cout << "neighbors: " << std::endl;
           for (auto k: db[sysid].get()->NEIGHBORS_ ) {
                 std::cout <<"      "<< k.second.first << " <--- " << k.second.second << " " << k.first << std::endl;
           }
           std::cout << "prefixes: " << std::endl;
           for (auto k: db[sysid].get()->SUBNETS_ ) {
                 std::cout << "      " <<  k << std::endl;
                 ++paginator;
                 if ( paginator > 25 ) {
                         paginator = 0;
                         std::cout << "<<press Enter for more>>" << std::endl;
                         fgetc(stdin);
                         std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                   }

           }
           
           std::cout << std::endl;
           }
}


void show_mockers(std::vector<std::unique_ptr<Mocker>>& mockers) {
          for ( auto i = mockers.begin(); i != mockers.end(); i++) (*i).get()->print_stats();
                    

}

void clear_stats(std::vector<std::unique_ptr<Mocker>>& mockers) {

          for ( auto i = mockers.begin(); i != mockers.end(); i++) (*i).get()->clear_stats();

}


void show_interfaces(std::vector<std::string>& ifnames,std::unordered_set<std::string>& ifnames_used) {
       std::cout << "Interfaces:" << std::endl;
       for ( auto k: ifnames ) {
          std::cout << "      " <<  k << std::endl;
       }
       std::cout << "Used:" << std::endl;
       for ( auto k: ifnames_used ) {
          std::cout << "      "<< k << std::endl;
       }
}


void mock(std::unordered_map<std::string, std::string>& lsdb, std::mutex& db_mtx, const std::string& sysid, std::pair<std::string,std::string>& mocked) {
       std::unique_lock<std::mutex> lock(db_mtx);
       std::string lspid = sysid + ".00-00";
       if (lsdb.find(lspid) == lsdb.end()) {
             std::cout << "Incorrect sysid or not found" << std::endl;
             return;
    
       }
       if ( mocked.first.length() || mocked.second.length() ) {
             std::cout << "Already present mocked instance" << std::endl;
             return;

       }
       mocked.first = lspid;
       mocked.second = lsdb[lspid];
       lsdb.erase(lspid);    
}

void mocker_start(int id, std::string ifname, std::string sysid, std::string area, std::string ip, std::vector<std::unique_ptr<Mocker>>& mockers, std::vector<std::string>& ifnames,  std::unordered_set<std::string>& used_ifnames,  std::unordered_set<int>& used_ids,  std::pair<std::string,std::string>& mocked_lsp)  {
              if ( id < 0 || id >= SM_PARK_SIZE ) {
                   std::cout << "Incorrect index, use indecies 0 to " << SM_PARK_SIZE << std::endl;
                   return;
              }
              if ( !ifname.size() || !sysid.size() || !area.size() || !ip.size() ) {
                   std::cout << "Empty params are not allowed, follow standard notations for parameters" << std::endl;
                   return;

              }
              bool found{false};
              for ( auto k: ifnames ) {
                   if ( k == ifname ) found = true;
              }                 

              if ( ! found ) { 
                    std::cout << "Provided ifname is not on the list" << std::endl;
                    return;

              }
    
              if ( used_ifnames.count(ifname) || used_ids.count(id) ) { 
                    std::cout << "id or ifname is/are used already" << std::endl;
                    return;

              }
              if ( !mocked_lsp.first.size() || !mocked_lsp.second.size() ) {
                    std::cout << "Need to mock first" << std::endl;
                    return;

              }
              
              std::unique_ptr<Mocker> temp(new Mocker(const_cast<char*>(ifname.c_str()), id, sysid, ip, area));
              mockers.push_back(std::move(temp));

              used_ifnames.insert(ifname);
              used_ids.insert(id);
}

void flood_start (int id, std::unordered_map<std::string, std::string>& lsdb, std::vector<std::unique_ptr<Flooder>>& flooders,  std::vector<std::unique_ptr<Mocker>>& mockers ) {
           if ( mockers.empty() ) {
                  std::cout << "Need to add mockers first" << std::endl;
                  return ;

           }
           bool found{false};
           for ( auto i = mockers.begin(); i != mockers.end(); i++) { 
                     if ( (*i).get()->get_id() == id ) {
                          bool update;              
                          if ( flooders.empty() ) update = true;
                          else update = false; 
                          
                          std::unique_ptr<Flooder> temp(new Flooder(id, lsdb, (*i).get()->get_io(), (*i).get()->get_state(), update)); 
                          flooders.push_back(std::move(temp));
                          (*i).get()->register_flooder(flooders.back().get());
                          found = true;
                     }
           }
           if ( ! found ) std::cout << "Mocker was not found" << std::endl;
}


void test_start (int id, std::unordered_map<std::string, std::string>& lsdb, std::unordered_map<std::string, std::string>& testdb, std::vector<std::unique_ptr<Flooder>>& flooders,  std::vector<std::unique_ptr<Mocker>>& mockers, std::vector<std::unique_ptr<Tester>>& testers, int test_interval) {
           if (testers.size() > 0) {
                 std::cout << "Tester is already running" << std::endl;
                 return ;

           } 
           if ( mockers.empty() ) {
                  std::cout << "Need to add mockers first" << std::endl;
                  return ;

           }
           if ( flooders.empty() ) {
                  std::cout << "Need to add flooders first" << std::endl;
                  return ;

           }
           if ( testdb.empty() ) { 
                  std::cout << "Diff is empty" << std::endl;
                  return ;

           }
           if ( test_interval <= 50 || test_interval > 5000 ) {
                  std::cout << "Out of range interval" << std::endl;
                  return ;


          } 
           
           bool found{false};
           for ( auto i = mockers.begin(); i != mockers.end(); i++) {
                     if ( (*i).get()->get_id() == id ) {
                          std::unique_ptr<Tester> temp(new Tester(id, lsdb, (*i).get()->get_io(), (*i).get()->get_state(), testdb, test_interval));
                          testers.push_back(std::move(temp));
                          (*i).get()->register_tester(testers.back().get());
                          found = true;
                     }
           }
           if ( ! found ) std::cout << "Mocker was not found" << std::endl;



}

void test_clear (std::vector<std::unique_ptr<Tester>>& testers) {
      testers.clear();
}


void reset_all(std::vector<std::unique_ptr<Mocker>>& mockers, std::vector<std::unique_ptr<Flooder>>&flooders, std::vector<std::unique_ptr<Tester>>& testers , std::unordered_set<std::string>& used_ifnames,  std::unordered_set<int>& used_ids, std::unordered_map<std::string, std::string>& lsdb, std::pair<std::string,std::string>& mocked) {
              std::cout << "Destroying... " << std::endl;
              /* put back mocked lsp */
              if ( mocked.first.length() && mocked.second.length() ) lsdb.insert(mocked);
              mocked.first = "";
              mocked.second = "";              
              /* clear floods and test*/
              testers.clear();
              flooders.clear(); 
              mockers.clear();

              used_ifnames.clear();
              used_ids.clear();
              std::cout << "done" << std::endl;

}


void prepare_test(std::unordered_map<std::string,std::string>& lsdb, std::unordered_map<std::string,std::string>& testdb, std::unordered_map<std::string,std::string>& lsdb_raw, std::string& json2, const std::string& json_file = std::string()) {
        testdb.clear(); 
        std::unordered_map<std::string, std::string> LSDB2,lsdb_raw2;  
        auxdb AUXDB2;

        try {
            /* if mocker was started with raw in mind turn processing to fill test db with RAW diff */ 
 
            if ( json_file.length() ) parse(LSDB2, AUXDB2, lsdb_raw2, const_cast<std::string&>(json_file), json2);
            else parse(LSDB2, AUXDB2, lsdb_raw2, json2);                                      
            std::cout << "Loaded json2" << std::endl;
            malloc_trim(0);

            if ( json_file.length() && json2.length() ) { 
             for (auto i = lsdb_raw.begin(); i != lsdb_raw.end(); i++ ) {

               auto size = std::min((*i).second.length(),lsdb_raw2[(*i).first].length());
               bool diff{false};
               for ( int j=42; j< int(size); j++ )  
                     if (((*i).second)[j] != (lsdb_raw2[(*i).first])[j]) { diff = true; break; }
               /* check if there is a diff */ 
               if ( lsdb_raw2.count((*i).first) && (*i).second.length() != lsdb_raw2[(*i).first].length() && diff ) { 
                    std::string tempkey = (*i).first;
                    std::string temp  = lsdb_raw2[tempkey];
                    testdb.insert(std::make_pair<std::string,std::string>(std::move(tempkey),std::move(temp)));
               }
            }

            } else {
            for (auto i = lsdb.begin(); i != lsdb.end(); i++ ) { 
               if ( LSDB2.count((*i).first) && (*i).second != LSDB2[(*i).first] ) {
                    std::string tempkey = (*i).first;
                    std::string temp  = LSDB2[tempkey];  
                    testdb.insert(std::make_pair<std::string,std::string>(std::move(tempkey),std::move(temp)));
               }
            }
            }
        
       if ( testdb.empty() ) std::cout << "No diff found" << std::endl; 
       else {
             std::cout << "Diff:" << std::endl;
             for (auto k: testdb ) std::cout << "       " << k.first << std::endl; 
             std::cout << "Ready to start test" << std::endl;
       }

        } catch (const std::exception& e) {
          std::cerr << "Error while parsing file, exception: " <<  e.what() << std::endl;

        } 

}










