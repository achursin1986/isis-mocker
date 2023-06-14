#pragma once
#include <iostream>
#include "utils.hpp"

struct TesterStats {
       long cycles{0};
};

void sendDB (std::unordered_map<std::string, std::string>& lsdb, IO& io) {
       for (auto const& [key, value] : lsdb) {
                 boost::asio::streambuf sbuf;
                 std::iostream os(&sbuf);
                 sbuf.prepare(value.size());
                 os << value;
                 io.do_send(&sbuf);
                 incrSequenceNum(lsdb,key,value);
       }
}

class Tester {

     public:
      Tester(Tester& other) = delete;
      Tester(Tester&& other) = delete;
      Tester& operator=(Tester&& other) = delete;

      Tester(int id, std::unordered_map<std::string, std::string>& lsdb, IO& io , std::atomic_bool& state, std::unordered_map<std::string, std::string>& testdb, int test_interval ): lsdb_(lsdb), testdb_(testdb), mocker_id_(id),io_(io), state_(state), test_interval_(test_interval){
                 tester_th_ = std::thread( [&](){    
                                                      /* sync seq numbers in testdb */
                                                      for ( auto i=testdb.begin(); i!= testdb.end(); i++ ) {
                                                                 std::string new_value = (*i).second;
                                                                 std::string seq_num_str = lsdb[(*i).first].substr(37, 4);
                                                                 unsigned int seq_num = static_cast<unsigned int>(static_cast<unsigned char>(seq_num_str[0])) << 24 |
                                                                 static_cast<unsigned int>(static_cast<unsigned char>(seq_num_str[1])) << 16 |
                                                                 static_cast<unsigned int>(static_cast<unsigned char>(seq_num_str[2])) << 8 |
                                                                 static_cast<unsigned int>(static_cast<unsigned char>(seq_num_str[3])); 
                                                                 seq_num++;
                                                                  new_value[40] = seq_num & 0x000000ff;
                                                                  new_value[39] = (seq_num & 0x0000ff00) >> 8;
                                                                  new_value[38] = (seq_num & 0x00ff0000) >> 16;
                                                                  new_value[37] = (seq_num & 0xff000000) >> 24;
                                                                  std::unique_ptr<unsigned char[]> checksum_temp_ptr(new unsigned char[new_value.size() - 17]{});
                                                                  unsigned char* checksum_temp = checksum_temp_ptr.get();
                                                                  new_value[41] = 0;
                                                                  new_value[42] = 0;
                                                                  std::memcpy(checksum_temp, new_value.c_str() + 17, new_value.size() - 17);

                                                                   unsigned short checksum = htons(fletcher_checksum(checksum_temp + 12, new_value.size() - 29, 12));
                                                                   new_value[41] = static_cast<unsigned char>(checksum >> 8);
                                                                   new_value[42] = static_cast<unsigned char>(checksum & 0xFF);       
                    
                                                      }
                                                       // need to send all fragments per diff 
                                                        while(! terminate ) {                                                       
                                                           if (  stats_.cycles % 2 ) {
                                                                  if ( state_ ) {
                                                                        sendDB(lsdb_, io_);                          
                                                                  }  

                                                           }  else {
                                                                 if ( state_ ) {
                                                                        sendDB(testdb_, io_);                                                               
                                                                 } 

                                                           }
                                                           stats_.cycles++;
                                                           std::this_thread::sleep_for(std::chrono::milliseconds(test_interval_));
                                                     }                      
                 } );

       }


     TesterStats& get_stats() {
              return stats_;
       }

       ~Tester() {
               terminate = true;
               test_interval_ = 1;
               tester_th_.join();
       }

      private:

        std::thread tester_th_;
        int mocker_id_, test_interval_;
        IO& io_;
        TesterStats stats_;
        std::unordered_map<std::string, std::string>& lsdb_, testdb_;
        std::atomic_bool terminate{false};
        // FSM state
        std::atomic_bool& state_;

};
